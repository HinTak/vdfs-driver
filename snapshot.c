/**
 * VDFS4 -- Vertically Deliberate improved performance File System
 *
 * Copyright 2012 by Samsung Electronics, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include <linux/fs.h>
#include <linux/rbtree.h>
#include <linux/vfs.h>
#include <linux/spinlock_types.h>
#include <linux/vmalloc.h>
#include <linux/buffer_head.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/pagemap.h>
#include <linux/crc32.h>
#include <linux/version.h>

#include "vdfs4.h"


struct vdfs4_base_table_record *vdfs4_get_table(struct vdfs4_sb_info *sbi,
		ino_t ino)
{
	struct vdfs4_base_table *b_table = sbi->snapshot_info->base_t;
	__u32 offset = le32_to_cpu(
		b_table->translation_table_offsets[VDFS4_SF_INDEX(ino)]);

	return (void *)((char *)b_table + offset);
}

static int expand_special_file(struct vdfs4_sb_info *sbi, ino_t ino_n,
		__u64 new_last_iblock, int force_insert);
static void insert_new_iblocks(struct vdfs4_sb_info *sbi, ino_t ino_n,
		sector_t new_last_iblock);

/**
 * @brief		Start transaction.
 * @param [in]	sbi	The eMMCFS super block info.
 * @return		Returns 0 on success, errno on failure.
 */
void vdfs4_start_transaction(struct vdfs4_sb_info *sbi)
{
	int *transaction_count = (int *)&current->journal_info;

	if (*transaction_count == 0) {
		if (!sbi->free_blocks_count &&
		    sbi->fsm_info && sbi->fsm_info->next_free_blocks)
			flush_delayed_work(&sbi->delayed_commit);
		VDFS4_DEBUG_MUTEX("transaction_lock down_read");
		down_read(&sbi->snapshot_info->transaction_lock);
		VDFS4_DEBUG_MUTEX("transaction_lock down_read success");
	}

	(*transaction_count)++;
}

/**
 * @brief		Stop transaction.
 * @param [in]	sbi	The eMMCFS super block info.
 * @return		Returns 0 on success, errno on failure.
 */
void vdfs4_stop_transaction(struct vdfs4_sb_info *sbi)
{
	int *transaction_count = (int *)&current->journal_info;

	VDFS4_BUG_ON(!*transaction_count);

	if (*transaction_count == 1) {
		VDFS4_DEBUG_MUTEX("transaction_lock up_read");
		up_read(&sbi->snapshot_info->transaction_lock);
		mod_delayed_work(system_wq, &sbi->delayed_commit, 60 * HZ);
	}
	(*transaction_count)--;
}

void vdfs4_start_writeback(struct vdfs4_sb_info *sbi)
{
	int *transaction_count = (int *)&current->journal_info;

	if (++*transaction_count == 1) {
		VDFS4_DEBUG_MUTEX("writeback_lock down_read");
		down_read(&sbi->snapshot_info->writeback_lock);
		VDFS4_DEBUG_MUTEX("writeback_lock down_read success");
	}
}

void vdfs4_stop_writeback(struct vdfs4_sb_info *sbi)
{
	int *transaction_count = (int *)&current->journal_info;

	if (--*transaction_count == 0) {
		VDFS4_DEBUG_MUTEX("writeback_lock up_read");
		up_read(&sbi->snapshot_info->writeback_lock);
	}
}

__u64 validate_base_table(struct vdfs4_base_table *table)
{
	__u32 checksum, on_disk_checksum;
	int is_not_base_table;
	__u32 *__on_disk_checksum;

	__on_disk_checksum = (void *)((char *)table +
			le32_to_cpu(table->descriptor.checksum_offset));
	on_disk_checksum = le32_to_cpu(*__on_disk_checksum);


	is_not_base_table = strncmp(table->descriptor.signature,
			VDFS4_SNAPSHOT_BASE_TABLE,
			sizeof(VDFS4_SNAPSHOT_BASE_TABLE) - 1);
	/* signature not match */
	if (is_not_base_table)
		return 0;
	checksum = crc32(0, table,
			le32_to_cpu(table->descriptor.checksum_offset));
	return (checksum != on_disk_checksum) ? 0 :
			VDFS4_SNAPSHOT_VERSION(table);

}

static __u64 parse_extended_table(struct vdfs4_sb_info *sbi,
		struct vdfs4_base_table *base_table,
		struct vdfs4_extended_table *extended_table)
{
	unsigned int count;
	__u32 rec_count = le32_to_cpu(extended_table->records_count);
	struct vdfs4_extended_record *record;
	struct vdfs4_base_table_record *table;
	__u64 last_table_index;

	record = (struct vdfs4_extended_record *)
		(void *)
		((char *) extended_table + sizeof(struct vdfs4_extended_table));

	for (count = 0; count < rec_count; count++) {
		__u64 table_idx = le64_to_cpu(record->table_index);
		__u64 obj_id = le64_to_cpu(record->object_id);

		table = vdfs4_get_table(sbi, (ino_t)obj_id);
		last_table_index = VDFS4_LAST_TABLE_INDEX(sbi, obj_id);

		BUG_ON(table_idx > last_table_index);

		table[table_idx].meta_iblock = record->meta_iblock;
		/* TODO - why two layout structures have different sizes ??? */
		table[table_idx].mount_count = (__le32)
				extended_table->descriptor.mount_count;
		table[table_idx].sync_count =
				extended_table->descriptor.sync_count;
		record++;
	}

	base_table->descriptor.mount_count =
			extended_table->descriptor.mount_count;
	base_table->descriptor.sync_count =
			extended_table->descriptor.sync_count;

	return le32_to_cpu(extended_table->descriptor.checksum_offset) +
			CRC32_SIZE;
}
static __u64 validate_extended_table(struct vdfs4_extended_table *table)
{
	__u32 checksum, on_disk_checksum;
	int is_not_ext_table;
	__u32 *__on_disk_checksum;

	is_not_ext_table = (strncmp(table->descriptor.signature,
			VDFS4_SNAPSHOT_EXTENDED_TABLE,
			sizeof(VDFS4_SNAPSHOT_EXTENDED_TABLE) - 1));
	/* signature not match */
	if (is_not_ext_table)
		return 0;

	__on_disk_checksum = (void *)((char *)table +
			le32_to_cpu(table->descriptor.checksum_offset));
	on_disk_checksum = le32_to_cpu(*__on_disk_checksum);

	checksum = crc32(0, table,
			le32_to_cpu(table->descriptor.checksum_offset));

	return (checksum != on_disk_checksum) ? 0 :
			VDFS4_SNAPSHOT_VERSION(table);
}

static void build_snapshot_bitmaps(struct vdfs4_sb_info *sbi)
{
	struct vdfs4_snapshot_info *snapshot = sbi->snapshot_info;
	/* current snapshot state */
	unsigned long *snapshot_bitmap = snapshot->snapshot_bitmap;
	/* next snapshot state */
	unsigned long *next_snapshot_bitmap = snapshot->next_snapshot_bitmap;
	unsigned long count, page_index;
	unsigned int table_offset;
	int pos, order;

	struct vdfs4_base_table_record *table;

	for (count = VDFS4_FSFILE; count <= VDFS4_LSFILE; count++) {
		table_offset = VDFS4_GET_TABLE_OFFSET(sbi, count);
		if (!table_offset)
			continue;

		table = vdfs4_get_table(sbi, count);
		order = is_tree(count) ? (int)sbi->log_blocks_in_leb :
				(int)sbi->log_blocks_in_page;
		for (page_index = 0; page_index <=
			VDFS4_LAST_TABLE_INDEX(sbi, count); page_index++) {
			pos = (int)le64_to_cpu(table->meta_iblock);

			bitmap_set(snapshot_bitmap, pos, (1 << order));
			table++;
		}
	}

	bitmap_copy(next_snapshot_bitmap, snapshot_bitmap,
				(int)snapshot->bitmap_size_in_bits);

}

/* return value -> phisical tables start sector */
static int restore_exsb(struct vdfs4_sb_info *sbi, __u64 version)
{
	struct vdfs4_layout_sb *vdfs4_sb = sbi->raw_superblock;
	struct vdfs4_layout_sb *vdfs4_sb_copy = sbi->raw_superblock_copy;
	struct vdfs4_extended_super_block *exsb, *exsb_copy;
	__u64 exsb_version, exsb_copy_version;
	int ret = 0;


	exsb = &vdfs4_sb->exsb;
	exsb_copy = &vdfs4_sb_copy->exsb;
	exsb_version = VDFS4_EXSB_VERSION(exsb);
	exsb_copy_version = VDFS4_EXSB_VERSION(exsb_copy);

	if (exsb_version == exsb_copy_version)
		return 0;

	if (version == exsb_version) {
		memcpy(exsb_copy, exsb,
			sizeof(struct vdfs4_extended_super_block));
		if (!(sbi->sb->s_flags & MS_RDONLY))
			ret = vdfs4_sync_second_super(sbi);
	} else {
		memcpy(exsb, exsb_copy,
			sizeof(struct vdfs4_extended_super_block));
		if (!(sbi->sb->s_flags & MS_RDONLY))
			ret = vdfs4_sync_first_super(sbi);
	}

	return ret;

}

static int get_table_version(struct vdfs4_sb_info *sbi,
		sector_t iblock, __u64 *version, __u64 *size) {

	struct page *page;
	struct vdfs4_base_table *table = NULL;
	int ret = 0;
	sector_t start_sector;

	ret = vdfs4_get_table_sector(sbi, iblock, &start_sector);
	if (ret)
		return ret;

	page = alloc_page(GFP_NOFS | __GFP_ZERO);
	if (!page)
		return -ENOMEM;

	ret = vdfs4_read_page(sbi->sb->s_bdev, page, start_sector, 8, 0);
	if (ret)
		goto exit;

	table = kmap_atomic(page);
	if (!table) {
		ret = -ENOMEM;
		goto exit;
	}
	if (!VDFS4_IS_COW_TABLE(table)) {
		*version = 0;
		goto exit_unmap;
	}

	*version = VDFS4_SNAPSHOT_VERSION(table);
	/* size of the base table is offset to CRC + CRC size */
	*size = le64_to_cpu(table->descriptor.checksum_offset) + CRC32_SIZE;

exit_unmap:
	kunmap_atomic(table);
exit:
	__free_page(page);
	return ret;

}

/* return value - first start sector of the extended tables */
static int load_base_table(struct vdfs4_sb_info *sbi,
		sector_t *ext_table_start, __u64 *table_version_out)
{
	struct vdfs4_layout_sb *vdfs4_sb = sbi->raw_superblock;
	struct vdfs4_extended_super_block *exsb = &vdfs4_sb->exsb;
	struct vdfs4_snapshot_info *snapshot = sbi->snapshot_info;
	sector_t table_start;
	__u64 table1_version, table2_version, table_version, checked;
	__u64 table_tbc;
	__u64 tables1_size_in_bytes, tables2_size_in_bytes,
		tables_size_in_bytes;
	int ret = 0;
	struct vdfs4_base_table *table;

	table_tbc = le64_to_cpu(exsb->tables.length);

	ret = get_table_version(sbi, 0, &table1_version,
			&tables1_size_in_bytes);
	if (ret)
		return ret;

	ret = get_table_version(sbi, (((sector_t)table_tbc) >> 1),
			 &table2_version, &tables2_size_in_bytes);
	if (ret)
		return ret;

	if (table1_version > table2_version) {
		table_version = table1_version;
		tables_size_in_bytes = tables1_size_in_bytes;
		table_start = 0;
	} else {
		table_version = table2_version;
		tables_size_in_bytes = tables2_size_in_bytes;
		table_start = (((sector_t)table_tbc) >> 1);
	}

	if ((table_version == 0) || (tables_size_in_bytes == 0))
		return -EINVAL;

	ret = restore_exsb(sbi, table_version);
	if (ret)
		return ret;

	table = vdfs4_vmalloc((long unsigned int)(DIV_ROUND_UP(tables_size_in_bytes,
			(__u64)PAGE_SIZE) << PAGE_SHIFT));
	if (!table)
		return -ENOMEM;

	ret = vdfs4_table_IO(sbi, table, tables_size_in_bytes, READ,
			&table_start);
	if (ret) {
		vfree(table);
		return ret;
	}

	checked = validate_base_table(table);
	if (!checked) {
		vfree(table);
		return -EIO;
	}

	snapshot->base_t = table;
	*ext_table_start = table_start;
	*table_version_out = table_version;

	return 0;
}

static int load_extended_table(struct vdfs4_sb_info *sbi, sector_t start)
{
	struct vdfs4_snapshot_info *snapshot = sbi->snapshot_info;

	if (!snapshot->extended_table) {
		snapshot->extended_table = vdfs4_vmalloc(PAGE_CACHE_SIZE);
		if (!snapshot->extended_table)
			return -ENOMEM;
	}

	return vdfs4_table_IO(sbi, snapshot->extended_table, PAGE_SIZE, READ,
			&start);
}

int vdfs4_build_snapshot_manager(struct vdfs4_sb_info *sbi)
{
	struct vdfs4_layout_sb *vdfs4_sb = sbi->raw_superblock;
	struct vdfs4_extended_super_block *exsb = &vdfs4_sb->exsb;
	struct vdfs4_snapshot_info *snapshot;
	int ret = 0;
	__u64 meta_tbc, base_table_version, ext_table_version;
	__u32 base_table_mount_count, base_table_sync_count;
	__u32 ext_table_mount_count, ext_table_sync_count;
	unsigned long bitmaps_length;
	sector_t iblock = 0;
	int count;

	snapshot = kzalloc(sizeof(*snapshot), GFP_NOFS);
	if (!snapshot)
		return -ENOMEM;
	sbi->snapshot_info = snapshot;
	ret = load_base_table(sbi, &iblock, &base_table_version);
	if (ret)
		goto error_exit_free_snapshot;

	meta_tbc = le64_to_cpu(exsb->meta_tbc);
	bitmaps_length = sizeof(unsigned long) *
		(unsigned long)BITS_TO_LONGS(meta_tbc);

	snapshot->snapshot_bitmap = kzalloc(bitmaps_length, GFP_NOFS);
	snapshot->moved_iblock = kzalloc(bitmaps_length, GFP_NOFS);
	snapshot->next_snapshot_bitmap = kzalloc(bitmaps_length, GFP_NOFS);
	snapshot->bitmap_size_in_bits = (long unsigned int)meta_tbc;

	if (!snapshot->snapshot_bitmap || !snapshot->moved_iblock ||
			!snapshot->next_snapshot_bitmap) {
		ret = -ENOMEM;
		goto error_exit;
	}

	for (count = 0; count < VDFS4_SNAPSHOT_EXT_TABLES; count++) {
		struct vdfs4_base_table *base_table = snapshot->base_t;
		ret = load_extended_table(sbi, iblock);
		if (ret)
			goto error_exit;
		ext_table_version =
			validate_extended_table(snapshot->extended_table);
		ext_table_mount_count = VDFS4_MOUNT_COUNT(ext_table_version);
		ext_table_sync_count = VDFS4_SYNC_COUNT(ext_table_version);
		base_table_mount_count = VDFS4_MOUNT_COUNT(base_table_version);
		base_table_sync_count = VDFS4_SYNC_COUNT(base_table_version);
		if ((ext_table_mount_count != base_table_mount_count) ||
				(ext_table_sync_count !=
						base_table_sync_count + 1))
			break;
		parse_extended_table(sbi, snapshot->base_t,
						snapshot->extended_table);
		base_table_version = VDFS4_SNAPSHOT_VERSION(base_table);
		iblock++;
		snapshot->exteneded_table_count++;
	}

	snapshot->iblock = iblock;
	build_snapshot_bitmaps(sbi);
	init_rwsem(&snapshot->tables_lock);
	init_rwsem(&snapshot->transaction_lock);
	init_rwsem(&snapshot->writeback_lock);

	memset(snapshot->extended_table, 0x0, PAGE_SIZE);
	return ret;

error_exit:
	kfree(snapshot->snapshot_bitmap);
	kfree(snapshot->moved_iblock);
	kfree(snapshot->next_snapshot_bitmap);
error_exit_free_snapshot:
	kfree(snapshot);
	sbi->snapshot_info = NULL;

	return ret;
}

/**
 * @brief		Destroys snapshot manager.
 * @param [in]	sbi	The eMMCFS super block info.
 * @return	void
 */
void vdfs4_destroy_snapshot_manager(struct vdfs4_sb_info *sbi)
{
	struct vdfs4_snapshot_info *snapshot = sbi->snapshot_info;
	sbi->snapshot_info = NULL;
	vfree(snapshot->base_t);
	vfree(snapshot->extended_table);
	kfree(snapshot->snapshot_bitmap);
	kfree(snapshot->moved_iblock);
	kfree(snapshot->next_snapshot_bitmap);
	kfree(snapshot);
}


static __u64 get_new_meta_iblock(struct vdfs4_sb_info *sbi, ino_t ino_n)
{
	unsigned long int hint, nr, align_mask, alignment;
	struct vdfs4_snapshot_info *snapshot = sbi->snapshot_info;
	unsigned long *snapshot_bitmap = snapshot->snapshot_bitmap;
	unsigned long *next_snapshot_bitmap = snapshot->next_snapshot_bitmap;
	unsigned long int size = snapshot->bitmap_size_in_bits;
	unsigned long position;


	if (is_tree(ino_n)) {
		nr = 1lu << sbi->log_blocks_in_leb;
		alignment = (unsigned long)sbi->log_blocks_in_leb;
		hint = sbi->snapshot_info->hint_btree;
	} else {
		nr = 1lu << sbi->log_blocks_in_page;
		alignment = (unsigned long)sbi->log_blocks_in_page;

		hint = sbi->snapshot_info->hint_bitmaps;
	}
	/*1 lookup for new iblock in snapshot_bitmap */
	align_mask = (1lu << alignment) - 1lu;
	position = bitmap_find_next_zero_area(snapshot_bitmap, size, hint, nr,
			align_mask);

	if (position > size) {
		position = bitmap_find_next_zero_area(snapshot_bitmap, size, 0,
				nr, align_mask);
		if (position > size)
			BUG();
	}

	/*2 set bits in snapshot_bitmap & next_snapshot_bitmaps */
	bitmap_set(snapshot_bitmap, (int)position, (1 << alignment));
	bitmap_set(next_snapshot_bitmap, (int)position, (1 << alignment));
	bitmap_set(snapshot->moved_iblock, (int)position, (1 << alignment));

	hint = position + nr;
	if (is_tree(ino_n))
		sbi->snapshot_info->hint_btree = hint;
	else
		sbi->snapshot_info->hint_bitmaps = hint;


	return (__u64)position;
}


static void move_iblock(struct vdfs4_sb_info *sbi, ino_t ino_n,
		sector_t current_iblock, pgoff_t page_index, sector_t *new_iblock)
{
	struct vdfs4_snapshot_info *snapshot = sbi->snapshot_info;
	unsigned long *next_snapshot_bitmap = snapshot->next_snapshot_bitmap;
	sector_t position;
	struct vdfs4_base_table_record *table = vdfs4_get_table(sbi, ino_n);
	__u64 last_table_index = VDFS4_LAST_TABLE_INDEX(sbi, ino_n);
	__u64 table_index;
	int nr;

	if (is_tree(ino_n))
		nr = 1 << sbi->log_blocks_in_leb;
	else
		nr = 1 << sbi->log_blocks_in_page;


	table_index = GET_TABLE_INDEX(sbi, ino_n, page_index);
	BUG_ON(table_index > last_table_index);
	position = get_new_meta_iblock(sbi, ino_n);
	bitmap_clear(next_snapshot_bitmap, (int)current_iblock, nr);

	table[table_index].meta_iblock = cpu_to_le64(position);

	*new_iblock = position;
}

static void update_extended_table(struct vdfs4_sb_info *sbi, ino_t ino_n,
		sector_t page_index, __u64 new_iblock)
{
	struct vdfs4_snapshot_info *snapshot = sbi->snapshot_info;
	struct vdfs4_extended_table *ext_table = snapshot->extended_table;
	__u32 rec_count = le32_to_cpu(ext_table->records_count);
	__u32 new_table_size;
	struct vdfs4_extended_record *record;
	__u64 table_index;

	table_index = GET_TABLE_INDEX(sbi, ino_n, page_index);

	if (snapshot->use_base_table)
		return;

	new_table_size = (rec_count + 1) * sizeof(struct vdfs4_extended_record) +
			sizeof(struct vdfs4_extended_table) + CRC32_SIZE;

	if (new_table_size > PAGE_CACHE_SIZE) {
		snapshot->use_base_table = 1;
		return;
	}

	record = (void *)((char *)snapshot->extended_table +
			sizeof(struct vdfs4_extended_table) +
			rec_count * sizeof(struct vdfs4_extended_record));
	record->meta_iblock = cpu_to_le64(new_iblock);
	record->object_id = cpu_to_le64(ino_n);
	record->table_index = cpu_to_le64(table_index);
	ext_table->records_count = cpu_to_le32(rec_count + 1);
}


void vdfs4_add_chunk_no_lock(struct vdfs4_sb_info *sbi, ino_t object_id,
		pgoff_t page_index)
{
	struct vdfs4_snapshot_info *snapshot = sbi->snapshot_info;
	unsigned long *moved_iblock = snapshot->moved_iblock;
	sector_t meta_iblock, new_iblock;
	int ret;

	BUG_ON((object_id < VDFS4_FSFILE) || (object_id > VDFS4_LSFILE));

	ret = vdfs4_get_meta_iblock(sbi, object_id, page_index,
			&meta_iblock);
	BUG_ON(ret);

	ret = test_bit((int)meta_iblock, moved_iblock);
	if (ret)
		return;

	move_iblock(sbi, object_id, meta_iblock, page_index, &new_iblock);

	if (is_tree(object_id))
		BUG_ON((new_iblock) &
				((1llu << sbi->log_blocks_in_leb) - 1llu));

	update_extended_table(sbi, object_id, page_index, new_iblock);

	snapshot->dirty_pages_count += (is_tree(object_id)) ?
			(1lu << sbi->log_blocks_in_leb) : 1;
}

static unsigned int get_bnode_size_in_pages(struct vdfs4_sb_info *sbi,
		ino_t i_ino)
{
	switch (i_ino) {
	case VDFS4_CAT_TREE_INO:
		return sbi->catalog_tree->pages_per_node;
	case VDFS4_EXTENTS_TREE_INO:
		return sbi->extents_tree->pages_per_node;
	case VDFS4_XATTR_TREE_INO:
		return sbi->xattr_tree->pages_per_node;
	default:
		break;
	}
	BUG();
	return 0;
}

#ifdef CONFIG_VDFS4_DEBUG

void vdfs4_check_moved_iblocks(struct vdfs4_sb_info *sbi, struct page **pages,
		unsigned int page_count)
{
	struct vdfs4_snapshot_info *snapshot = sbi->snapshot_info;
	long unsigned int *moved_iblock = snapshot->moved_iblock;
	ino_t i_ino = pages[0]->mapping->host->i_ino;
	sector_t meta_iblock;
	unsigned int count = 0, chunk_size, i;
	chunk_size = (is_tree(i_ino)) ? get_bnode_size_in_pages(sbi, i_ino) : 1;
	do {
		/* page->index must be exist in snapshot tables */
		BUG_ON(vdfs4_get_meta_iblock(sbi, i_ino, pages[count]->index,
				&meta_iblock));
		/* page must be moved */
		for (i = 0; i < chunk_size; i++) {
			BUG_ON(!test_and_clear_bit((int)meta_iblock,
						moved_iblock));
			meta_iblock++;
			count++;
		}
	} while (count < page_count);
}
#endif

void vdfs4_add_chunk_bitmap(struct vdfs4_sb_info *sbi, struct page *page,
			int fsm_flags)
{
	struct vdfs4_snapshot_info *snapshot = sbi->snapshot_info;
	ino_t i_ino = page->mapping->host->i_ino;

	vdfs4_assert_transaction(sbi);

	if (PageDirty(page))
		return;
	set_page_dirty(page);

	if (!(fsm_flags & VDFS4_FSM_ALLOC_METADATA))
		down_write(&snapshot->tables_lock);
	vdfs4_add_chunk_no_lock(sbi, i_ino, page->index);
	if (!(fsm_flags & VDFS4_FSM_ALLOC_METADATA))
		up_write(&snapshot->tables_lock);
}

void vdfs4_add_chunk_bnode(struct vdfs4_sb_info *sbi, struct page **pages)
{
	struct vdfs4_snapshot_info *snapshot = sbi->snapshot_info;
	ino_t i_ino = pages[0]->mapping->host->i_ino;
	int bnode_size_in_pages = (int)get_bnode_size_in_pages(sbi, i_ino);
	int count;

	vdfs4_assert_transaction(sbi);

	if (PageDirty(pages[0])) {
		for (count = 0; count < bnode_size_in_pages; count++)
			BUG_ON(!PageDirty(pages[count]));
		/* pages is diry - already moved to new place */
		return;
	}
	for (count = 0; count < bnode_size_in_pages; count++)
		set_page_dirty_lock(pages[count]);
	down_write(&snapshot->tables_lock);
	vdfs4_add_chunk_no_lock(sbi, i_ino, pages[0]->index);
	up_write(&snapshot->tables_lock);
}


/**
 * @brief		Check offset: space for page with page_index
 *			is allocated on volume or not; If not allocated
 *			then expand file;
 * @param [in]	sbi	VDFS4 run-time superblock
 * @return		none
 */
int vdfs4_check_page_offset(struct vdfs4_sb_info *sbi, struct inode *inode,
		pgoff_t page_index, char *is_new, int force_insert)
{
	ino_t object_id = inode->i_ino;
	sector_t last_table_index;
	sector_t table_index;
	int ret = 0;

	down_write(&sbi->snapshot_info->tables_lock);

	last_table_index = VDFS4_LAST_TABLE_INDEX(sbi, object_id);
	if (is_tree(object_id))
		table_index = page_index >> (sbi->log_blocks_in_leb +
				sbi->block_size_shift - PAGE_SHIFT);
	else
		table_index = page_index;

	if (table_index > last_table_index) {
		/* special file extention */
		ret = expand_special_file(sbi, object_id, table_index,
				force_insert);
		if (ret)
			goto exit;
		*is_new = 1;
		sbi->snapshot_info->use_base_table = 1;
		i_size_write(inode, vdfs4_special_file_size(sbi, inode->i_ino));
	} else
		*is_new = 0;
exit:
	up_write(&sbi->snapshot_info->tables_lock);

	return ret;
}

__le64 vdfs4_get_page_version(struct vdfs4_sb_info *sbi, struct inode *inode,
		pgoff_t page_index)
{
	sector_t table_index;
	__le64 version = 0;
	struct vdfs4_base_table_record *table;

	down_write(&sbi->snapshot_info->tables_lock);
	if (is_tree(inode->i_ino))
		table_index = page_index >> (sbi->log_blocks_in_leb +
				sbi->block_size_shift - PAGE_SHIFT);
	else
		table_index = page_index;
	table = vdfs4_get_table(sbi, inode->i_ino);
	version = cpu_to_le64((((__le64)(table[table_index].mount_count))
			<< 32) | table[table_index].sync_count);
	up_write(&sbi->snapshot_info->tables_lock);
	return version;
}
/**
 * @brief		Fill full table descriptor and calculate table CRC
 * @param [in]	sbi	VDFS4 run-time superblock
 * @param [in]	table	pointer to buffer
 * @param [in]	type	table type : base table or extended table
 * @return		none
 */
static void fill_descriptor_and_calculate_crc(struct vdfs4_sb_info *sbi,
		void *table, enum snapshot_table_type type)
{
	struct vdfs4_snapshot_info *snapshot = sbi->snapshot_info;
	struct vdfs4_snapshot_descriptor *descriptor = table;
	struct vdfs4_layout_sb *vdfs4_sb = sbi->raw_superblock;
	struct vdfs4_extended_super_block *exsb = &vdfs4_sb->exsb;

	int count;
	__u32 *checksum;

	if (type == SNAPSHOT_BASE_TABLE) {
		struct vdfs4_base_table *base_table = table;
		__u64 last_table_index;

		memcpy((void *)&descriptor->signature, VDFS4_SNAPSHOT_BASE_TABLE,
				sizeof(VDFS4_SNAPSHOT_BASE_TABLE) - 1);

		base_table->descriptor.checksum_offset = 0;
		for (count = VDFS4_FSFILE; count <= VDFS4_LSFILE; count++) {
			last_table_index = VDFS4_LAST_TABLE_INDEX(sbi, count);
			base_table->descriptor.checksum_offset +=
				sizeof(struct vdfs4_base_table_record) *
				(last_table_index + 1);
		}

		base_table->descriptor.checksum_offset += sizeof(*base_table);

		descriptor->checksum_offset =
				cpu_to_le32(descriptor->checksum_offset);
	} else if (type == SNAPSHOT_EXT_TABLE) {
		struct vdfs4_extended_table *ext_table = table;

		memcpy((void *)&descriptor->signature,
				VDFS4_SNAPSHOT_EXTENDED_TABLE,
				sizeof(VDFS4_SNAPSHOT_EXTENDED_TABLE) - 1);

		ext_table->descriptor.checksum_offset = sizeof(*ext_table) +
				sizeof(struct vdfs4_extended_record) *
				le32_to_cpu(ext_table->records_count);
	} else
		VDFS4_BUG();

	descriptor->mount_count = exsb->mount_counter;
	descriptor->sync_count = cpu_to_le32(snapshot->sync_count);

	checksum = (void *)((char *)table + descriptor->checksum_offset);
	/* sign snapshot : crc32 */
	*checksum = crc32(0, table, (size_t)descriptor->checksum_offset);

}

#define VDFS4_SNAPSHOT_TABLES_COUNT 8

/**
 * @brief		Finalizing metadata update by writing a translation
 *			tables on disk
 * @param [in]	sbi	VDFS4 run-time superblock
 * @param [in]	iblock	iblock - key for searching
 * @return		Returns 0 on success, errno on failure.
 */
int vdfs4_update_translation_tables(struct vdfs4_sb_info *sbi)
{
	struct vdfs4_snapshot_info *snapshot = sbi->snapshot_info;
	struct vdfs4_snapshot_descriptor *descriptor;
	void *table;
	__u64 table_size;
	sector_t iblock = snapshot->iblock, s_iblock = 0;
	int ret = 0;
#ifdef CONFIG_VDFS4_STATISTIC
	sector_t sectors_count;
#endif
	enum snapshot_table_type type;

	if (snapshot->exteneded_table_count >= VDFS4_SNAPSHOT_TABLES_COUNT ||
			snapshot->use_base_table) {
		struct vdfs4_layout_sb *vdfs4_sb = sbi->raw_superblock;
		__u64 table_ttb = le64_to_cpu(vdfs4_sb->exsb.tables.length);

		type = SNAPSHOT_BASE_TABLE;
		table = snapshot->base_t;
		snapshot->use_base_table = 0;
		snapshot->exteneded_table_count = 0;

		iblock = (iblock >= (table_ttb >> 1)) ? 0 : table_ttb >> 1;
	} else {
		type = SNAPSHOT_EXT_TABLE;
		snapshot->exteneded_table_count++;
		table = snapshot->extended_table;
	}

	fill_descriptor_and_calculate_crc(sbi, table, type);
	descriptor = (struct vdfs4_snapshot_descriptor *)table;
	table_size = le64_to_cpu(descriptor->checksum_offset) + CRC32_SIZE;
#ifdef CONFIG_VDFS4_STATISTIC
	sectors_count = (DIV_ROUND_UP(table_size, SECTOR_SIZE));
#endif
	BUG_ON((table_size > PAGE_SIZE) && (type != SNAPSHOT_BASE_TABLE));

	if (table_size > PAGE_SIZE && type == SNAPSHOT_BASE_TABLE) {
		s_iblock = iblock + 1;
		ret = vdfs4_table_IO(sbi, (char *)table + PAGE_SIZE,
			table_size - PAGE_SIZE, WRITE_FLUSH_FUA, &s_iblock);
		if (ret)
			return ret;
	}
	ret = vdfs4_table_IO(sbi, table, PAGE_SIZE, WRITE_FLUSH_FUA,
			&iblock);
	if (ret)
		return ret;

	snapshot->iblock = s_iblock ? s_iblock : iblock;
	snapshot->sync_count++;
	snapshot->dirty_pages_count = 0;
	memset(snapshot->extended_table, 0x0, PAGE_SIZE);
#ifdef CONFIG_VDFS4_STATISTIC
	sbi->umount_written_bytes += ((DIV_ROUND_UP(table_size, SECTOR_SIZE))
			<< SECTOR_SIZE_SHIFT);
#endif
	return ret;
}


void vdfs4_update_bitmaps(struct vdfs4_sb_info *sbi)
{
	struct vdfs4_snapshot_info *snapshot = sbi->snapshot_info;
	unsigned long *moved_iblock = snapshot->moved_iblock;
	unsigned long *snapshot_bitmap = snapshot->snapshot_bitmap;
	unsigned long *next_snapshot_bitmap = snapshot->next_snapshot_bitmap;
	int nbits = (int)snapshot->bitmap_size_in_bits;

#ifdef CONFIG_VDFS4_DEBUG
	/* moved iblock bitmap must be empty after metadata updating */
	BUG_ON(!bitmap_empty(moved_iblock, nbits));
#endif
	bitmap_zero(moved_iblock, nbits);
	bitmap_copy(snapshot_bitmap, next_snapshot_bitmap, nbits);
}

/**
 * @brief		Calculation metadata area expand step size
 * @param [in]	sbi	VDFS4 run-time superblock
 * @return		Returns expand step size in blocks.
 */
static __u32 calculate_expand_step(struct vdfs4_sb_info *sbi)
{
	/* minimal snapshot area size =
	 * 4 btree 2 *(catalog, extents, hlins and xattr) * bnode_size +
	 * 3 bimaps (free space, inode id and small files) * block_size)
	 */
	loff_t volume_size = sbi->sb->s_bdev->bd_inode->i_size;
	__u32 minimal_expand_step = 2 * (4 * (1lu <<
		sbi->log_super_page_size) + 3 * sbi->block_size);
	__u32 expand_step;
	char is_volume_small;
	__u32 blocks_per_superpage = 1lu << (sbi->log_super_page_size -
					sbi->log_block_size);
	volume_size >>= 5;
	is_volume_small = (minimal_expand_step > volume_size) ?
			1 : 0;
	minimal_expand_step >>= sbi->log_block_size;

	/* allign to superpage size */
	minimal_expand_step += blocks_per_superpage -
			(minimal_expand_step & (blocks_per_superpage - 1));

	expand_step = (is_volume_small) ? minimal_expand_step :
		(1lu << (sbi->log_erase_block_size - sbi->log_block_size));
	expand_step = expand_step << 1;

	return expand_step;
}

/**
 * @brief		Expand area on disk (metadata area or tables area) by
 *			expand_block_count
 * @param [in]	sbi	VDFS4 run-time superblock
 * @param [in]	extents			VDFS4 extents massive
 * @param [in]	extents_count		How many extents in massive
 * @param [in]	expand_block_count	Expand step size in blocks
 * @param [out] tbc			Total blocks count
 * @return		Returns 0 on success, errno on failure.
 */
static int expand_area(struct vdfs4_sb_info *sbi, struct vdfs4_extent *extents,
		unsigned int extents_count, unsigned int expand_block_count,
		__le32 *tbc)
{
	unsigned int count;
	__u64 start_offset;

	/* lookup for last used extent */
	for (count = 0; count < extents_count; count++) {
		if (extents->begin == 0)
			break;
		extents++;
	}
	if (count >= extents_count)
		return -EINVAL;

	extents--;
	start_offset = le64_to_cpu(extents->begin) +
			le32_to_cpu(extents->length);

	start_offset = vdfs4_fsm_get_free_block(sbi, start_offset,
			&expand_block_count,
			VDFS4_FSM_ALLOC_ALIGNED | VDFS4_FSM_ALLOC_METADATA);

	if (!start_offset)
		return -ENOSPC;

	if (le64_to_cpu(extents->begin) + le32_to_cpu(extents->length) ==
			start_offset) {
		extents->length = cpu_to_le32(le32_to_cpu(extents->length) +
				expand_block_count);
	} else {
		extents++;
		extents->begin = cpu_to_le64(start_offset);
		extents->length = cpu_to_le32(expand_block_count);
	}
	*tbc = cpu_to_le32(le32_to_cpu(*tbc) + expand_block_count);

	return 0;

}

static void insert_new_iblocks(struct vdfs4_sb_info *sbi, ino_t ino_n,
		sector_t new_last_table_index)
{
	void *dest, *src;
	unsigned long size;
	struct vdfs4_snapshot_info *snapshot = sbi->snapshot_info;
	struct vdfs4_base_table *base_table = snapshot->base_t;
	struct vdfs4_base_table_record *table = vdfs4_get_table(sbi, ino_n);
	__u64 last_table_index = VDFS4_LAST_TABLE_INDEX(sbi, ino_n), offset;
	__u64 count, add_size;
	struct vdfs4_layout_sb *vdfs4_sb = sbi->raw_superblock;

	BUG_ON(last_table_index > new_last_table_index);

	add_size =  sizeof(struct vdfs4_base_table_record) *
		(new_last_table_index - last_table_index);

	src = (char *)table + sizeof(struct vdfs4_base_table_record) *
			(last_table_index + 1);
	dest = (char *)src + add_size;
	size = (unsigned long)le32_to_cpu(base_table->
		descriptor.checksum_offset) + (unsigned long)base_table -
		(unsigned long)src;

	memmove(dest, src, size);

	for (count = VDFS4_FSFILE; count <= VDFS4_LSFILE; count++) {
		if (base_table->translation_table_offsets[VDFS4_SF_INDEX(ino_n)]
		>= base_table->translation_table_offsets[VDFS4_SF_INDEX(count)])
			continue;
		offset = le64_to_cpu(base_table->
			translation_table_offsets[VDFS4_SF_INDEX(count)]);
		offset += add_size;
		base_table->translation_table_offsets[VDFS4_SF_INDEX(count)] =
			cpu_to_le64(offset);
	}

	offset = le32_to_cpu(base_table->descriptor.checksum_offset);
	offset += add_size;
	base_table->descriptor.checksum_offset = cpu_to_le32(offset);

	for (count = last_table_index + 1; count <= new_last_table_index;
			count++) {
		table[count].meta_iblock =
				cpu_to_le64(get_new_meta_iblock(sbi, ino_n));
		table[count].mount_count = vdfs4_sb->exsb.mount_counter;
		table[count].sync_count = snapshot->sync_count;
	}
	base_table->last_page_index[VDFS4_SF_INDEX(ino_n)] =
			cpu_to_le32(new_last_table_index);

	if (is_tree(ino_n))
		snapshot->dirty_pages_count +=
			(unsigned)(1 << sbi->log_blocks_in_leb) *
		(unsigned)(new_last_table_index - last_table_index);
	else
		snapshot->dirty_pages_count += (unsigned)(new_last_table_index -
				last_table_index);

}

static int expand_translation_tables(struct vdfs4_sb_info *sbi, ino_t ino_n,
		__u64 new_table_index)
{
	struct vdfs4_snapshot_info *snapshot = sbi->snapshot_info;
	struct vdfs4_layout_sb *vdfs4_sb = sbi->raw_superblock;
	__u32 meta_tbc = le32_to_cpu(vdfs4_sb->exsb.meta_tbc);
	unsigned int bitmaps_length, old_bitmap_length;
	unsigned long *snapshot_bitmap = NULL, *moved_iblock = NULL,
		*next_snapshot_bitmap = NULL;
	unsigned long tables_in_pages;


	__u64 tables_size = le64_to_cpu(snapshot->base_t->
			descriptor.checksum_offset) + CRC32_SIZE;

	if (tables_size + sizeof(struct vdfs4_base_table_record) >
			le64_to_cpu(vdfs4_sb->exsb.tables.length) / 2 -
			VDFS4_SNAPSHOT_EXT_TABLES * VDFS4_SNAPSHOT_EXT_SIZE)
		return -ENOSPC;

	tables_in_pages = (unsigned long)DIV_ROUND_UP(tables_size +
			(__u64)sizeof(struct vdfs4_base_table_record),
			(__u64)PAGE_SIZE);

	if (((tables_size & (PAGE_SIZE - 1)) +
			sizeof(struct vdfs4_base_table_record)) > PAGE_SIZE) {
		void *new_table = vdfs4_vmalloc(tables_in_pages << PAGE_SHIFT);

		if (!new_table)
			return -ENOMEM;

		memcpy(new_table, snapshot->base_t, (size_t)tables_size -
				CRC32_SIZE);
		vfree(snapshot->base_t);
		snapshot->base_t = new_table;
	}


	if (meta_tbc > snapshot->bitmap_size_in_bits) {
		old_bitmap_length = sizeof(unsigned long) *
			BITS_TO_LONGS(snapshot->bitmap_size_in_bits);
		bitmaps_length = sizeof(unsigned long) *
				BITS_TO_LONGS(meta_tbc);
		snapshot_bitmap = kzalloc(bitmaps_length, GFP_NOFS);
		moved_iblock = kzalloc(bitmaps_length, GFP_NOFS);
		next_snapshot_bitmap = kzalloc(bitmaps_length, GFP_NOFS);

		if (!snapshot_bitmap || !moved_iblock ||
				!next_snapshot_bitmap) {
			kfree(snapshot_bitmap);
			kfree(moved_iblock);
			kfree(next_snapshot_bitmap);
			return -ENOMEM;
		}

		memcpy(snapshot_bitmap, snapshot->snapshot_bitmap,
				old_bitmap_length);
		memcpy(moved_iblock, snapshot->moved_iblock, old_bitmap_length);
		memcpy(next_snapshot_bitmap, snapshot->next_snapshot_bitmap,
				old_bitmap_length);

		kfree(snapshot->snapshot_bitmap);
		snapshot->snapshot_bitmap = snapshot_bitmap;
		kfree(snapshot->moved_iblock);
		snapshot->moved_iblock = moved_iblock;
		kfree(snapshot->next_snapshot_bitmap);
		snapshot->next_snapshot_bitmap = next_snapshot_bitmap;
		snapshot->bitmap_size_in_bits = meta_tbc;
	}

	insert_new_iblocks(sbi, ino_n, new_table_index);

	return 0;
}

static int expand_special_file(struct vdfs4_sb_info *sbi, ino_t ino_n,
		__u64 new_table_index, int force_insert)
{
	struct vdfs4_layout_sb *vdfs4_sb = sbi->raw_superblock;
	__u32 meta_tbc = le32_to_cpu(vdfs4_sb->exsb.meta_tbc);
	__u32 new_blocks_count;
	__u64 last_table_index = VDFS4_LAST_TABLE_INDEX(sbi, ino_n);
	long free_blocks;
	int ret = 0, count;

	if (new_table_index <= last_table_index)
		return -EINVAL;

	free_blocks = (long)meta_tbc;
	new_blocks_count = (__u32)(new_table_index - last_table_index);

	if (is_tree(ino_n))
		new_blocks_count *= (__u32)(1 << (sbi->log_blocks_in_page +
			sbi->log_blocks_in_leb));
	else
		new_blocks_count *= (__u32)(1 << sbi->log_blocks_in_page);

	for (count = VDFS4_FSFILE; count <= VDFS4_LSFILE; count++) {
		last_table_index = (__u64)VDFS4_LAST_TABLE_INDEX(sbi, count);
		free_blocks -= (long)(1 << (sbi->log_blocks_in_page +
				sbi->log_blocks_in_leb)) *
				(long)(last_table_index + 1);
	}

	if ((free_blocks - (long)new_blocks_count) < ((long)meta_tbc >> 1)) {
		ret = expand_area(sbi, &vdfs4_sb->exsb.meta[0],
				VDFS4_META_BTREE_EXTENTS,
				calculate_expand_step(sbi),
				&vdfs4_sb->exsb.meta_tbc);
		if (ret) {
			if (!force_insert)
				return ret;
			else
				ret = 0;
		} else
			set_sbi_flag(sbi, EXSB_DIRTY);
	}

	ret = expand_translation_tables(sbi, ino_n, new_table_index);
	return ret;
}

static unsigned long free_blocks_in_bitmap(unsigned long *bitmap,
		unsigned long size)
{
	unsigned long position, next_position;
	unsigned long free_blocks = 0;

	position = find_first_zero_bit(bitmap, size);

	while (position < size) {
		next_position = find_next_bit(bitmap, size, position);
		if (next_position > size) {
			free_blocks += next_position - 1 - position;
			break;
		}
		free_blocks += (next_position - position);
		position = find_next_zero_bit(bitmap, size, next_position);
	}

	return free_blocks;
}

static long meta_area_free_blocks(struct vdfs4_sb_info *sbi)
{
	struct vdfs4_layout_sb *vdfs_sb = sbi->raw_superblock;
	long free_blocks = le32_to_cpu(vdfs_sb->exsb.meta_tbc);
	int count;
	__u64 last_table_index;

	for (count = VDFS4_FSFILE; count <= VDFS4_LSFILE; count++) {
		last_table_index = (__u64)VDFS4_LAST_TABLE_INDEX(sbi, count);
		free_blocks -= (long)(1 << (sbi->log_blocks_in_page +
				sbi->log_blocks_in_leb)) *
				(long)(last_table_index + 1);
	}

	return free_blocks;
}

int vdfs4_is_enospc(struct vdfs4_sb_info *sbi, int threshold)
{
	struct vdfs4_layout_sb *vdfs_sb = sbi->raw_superblock;
	long free_blocks, ttb;
	int threshold_in_blocks;
	unsigned long *snapshot_bitmap = sbi->snapshot_info->snapshot_bitmap;
	struct vdfs4_snapshot_info *snapshot = sbi->snapshot_info;
	unsigned long free_to_use;

	if (threshold < 0 || threshold > 100)
		return 1;

	down_read(&snapshot->tables_lock);
	ttb = le32_to_cpu(vdfs_sb->exsb.meta_tbc);

	free_blocks = meta_area_free_blocks(sbi);
	if (free_blocks > (ttb >> 1)) {
		up_read(&snapshot->tables_lock);
		return 0;
	}
	free_to_use = free_blocks_in_bitmap(snapshot_bitmap,
			sbi->snapshot_info->bitmap_size_in_bits);

	threshold_in_blocks = ttb /100;
	threshold_in_blocks *= threshold;

	up_read(&snapshot->tables_lock);
	return (threshold_in_blocks > free_to_use) ? 1 : 0;
}

int vdfs4_check_meta_space(struct vdfs4_sb_info *sbi)
{
	long free_blocks, ttb;
	struct vdfs4_layout_sb *vdfs_sb = sbi->raw_superblock;
	struct vdfs4_snapshot_info *snapshot = sbi->snapshot_info;
	int ret;

	down_read(&snapshot->tables_lock);
	ttb = le32_to_cpu(vdfs_sb->exsb.meta_tbc);
	free_blocks = meta_area_free_blocks(sbi);
	up_read(&snapshot->tables_lock);

	if (free_blocks > (ttb >> 1))
		return 0;

	down_write(&snapshot->tables_lock);
	ret = expand_area(sbi, &vdfs_sb->exsb.meta[0],
				VDFS4_META_BTREE_EXTENTS,
				calculate_expand_step(sbi),
				&vdfs_sb->exsb.meta_tbc);
	if (!ret)
		set_sbi_flag(sbi, EXSB_DIRTY);

	up_write(&snapshot->tables_lock);
	return ret;
}

int vdfs4_get_meta_iblock(struct vdfs4_sb_info *sbi, ino_t ino_n,
		pgoff_t page_index, sector_t *meta_iblock)
{
	struct vdfs4_base_table_record *table;
	pgoff_t last_page_index = (pgoff_t)VDFS4_LAST_TABLE_INDEX(sbi, ino_n);
	pgoff_t table_page_index = GET_TABLE_INDEX(sbi, ino_n, page_index);

	if (table_page_index > last_page_index)
		return -EINVAL;

	table = vdfs4_get_table(sbi, ino_n);
	*meta_iblock = le64_to_cpu(table[table_page_index].meta_iblock);
	return 0;
}

loff_t vdfs4_special_file_size(struct vdfs4_sb_info *sbi, ino_t ino_n)
{
	loff_t last_page_index = (loff_t)VDFS4_LAST_TABLE_INDEX(sbi, ino_n);
	loff_t size;

	if (is_tree(ino_n))
		size = (loff_t)(1llu << sbi->log_super_page_size) *
			(last_page_index + (loff_t)1);
	else
		size = PAGE_CACHE_SIZE * (last_page_index + 1);


	return size;
}


