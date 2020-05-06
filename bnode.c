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

#include <linux/slab.h>
#include <linux/buffer_head.h>
#include <linux/vmalloc.h>
#include <linux/swap.h>
#include "vdfs4.h"
#include <linux/mmzone.h>
#include "btree.h"

#ifdef CONFIG_VDFS4_META_SANITY_CHECK
static inline __le32 __get_checksum_offset_from_btree(struct vdfs4_btree *btree)
{
	return btree->node_size_bytes -	VDFS4_BNODE_FIRST_OFFSET;
}

static __le32 *__get_checksum_addr_for_bnode(void *bnode_data,
		struct vdfs4_btree *btree)
{
	void *check_offset = (char *)bnode_data +
		__get_checksum_offset_from_btree(btree);
	__le32 *offset = check_offset;

	return offset;
}

static inline __le32 __calc_crc_for_bnode(void *bnode_data,
		struct vdfs4_btree *btree)
{
	return crc32(0, bnode_data, __get_checksum_offset_from_btree(btree));
}

inline void vdfs4_calc_crc_for_bnode(void *bnode_data,
		struct vdfs4_btree *btree)
{
	*__get_checksum_addr_for_bnode(bnode_data, btree) =
		__calc_crc_for_bnode(bnode_data, btree);
}

static int  __get_checksum_for_bnode(void *bnode_data,
	struct vdfs4_btree *btree, struct vdfs4_bnode *bnode, __le32 *checksum)
{
	struct vdfs4_sb_info *sbi = btree->sbi;
	__le32 crc_on_bnode = *__get_checksum_addr_for_bnode(bnode_data, btree);
	unsigned int *crc_on_hashtable;
	ino_t ino;
	__le64 index;

	*checksum = crc_on_bnode;

	/* crc in bnode is used for No auth case (R/W partition) */
	if (is_sbi_flag_set(sbi, DO_NOT_CHECK_SIGN))
		return 1;

#if defined(CONFIG_VDFS4_DEBUG_AUTHENTICAION)
	if (!sbi->raw_meta_hashtable) {
		/* suppress warning log */
		/* VDFS4_WARNING("No meta hashtable - skip to get checksum for bnode\n"); */
		return 1;
	}
#endif
	index = bnode->pages[0]->index >>
			(sbi->log_super_page_size - PAGE_SHIFT);

	switch (btree->btree_type) {
	case VDFS4_BTREE_CATALOG:
		ino = VDFS4_CAT_TREE_INO;
		break;
	case VDFS4_BTREE_EXTENTS:
		ino = VDFS4_EXTENTS_TREE_INO;
		break;
	case VDFS4_BTREE_XATTRS:
		ino = VDFS4_XATTR_TREE_INO;
		break;
	default:
		VDFS4_ERR("Invalid btree_type : %d\n", btree->btree_type);
		VDFS4_BUG(sbi);
	}

	/* crc in bnode & meta hash table is used for auth case (R/O partition) */
	crc_on_hashtable = vdfs4_get_meta_hashtable(sbi, ino);

	if (crc_on_bnode != crc_on_hashtable[index]) {
#if defined(CONFIG_VDFS4_DEBUG_AUTHENTICAION)
		/* suppress warning log */
		/* VDFS4_WARNING("wrong bnode hash bnode:%x hashtable:%x\n",
		      crc_on_bnode, crc_on_hashtable[index]); */
#else
		return 0;
#endif
	}
	return 1;
}
#endif

static struct vdfs4_bnode *alloc_bnode(struct vdfs4_btree *btree,
		__u32 node_id, enum vdfs4_get_bnode_mode mode);

static void free_bnode(struct vdfs4_bnode *bnode);
/**
 * @brief		Error handling. The function is used in case critial
 *			errors in btree.c and bnode.c files
 * @param [in]	bnode	Broken bnode. The bnode will be printed at debug console
 *			and dumped to disk (if it is possible)
 * @param [in]	fmt	Error message string
 * @return		void
 */
void vdfs4_dump_panic_remount(struct vdfs4_bnode *bnode, uint32_t err_type,
		const char *fmt, ...)
{
	struct vdfs4_sb_info *sbi = bnode->host->sbi;
	const char *device = sbi->sb->s_id;
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;

	VDFS4_NOTICE("VDFS4(%s): error in %pf, %pV\n", device,
			__builtin_return_address(0), &vaf);
	va_end(args);

	vdfs4_dump_bnode(bnode, bnode->data);

	if (err_type)
		vdfs4_record_err_dump_disk(sbi, err_type, bnode->node_id, 0, fmt,
			(void *)bnode->data, bnode->host->node_size_bytes);

#ifdef CONFIG_VDFS4_PANIC_ON_ERROR
	panic("VDFS4(%s): forced kernel panic after fatal error\n", device);
#else
	if (!(sbi->sb->s_flags & MS_RDONLY)) {
		VDFS4_WARNING("VDFS4(%s): remount to read-only mode\n", device);
		sbi->sb->s_flags |= MS_RDONLY;
	}
#endif
}

/**
 * @brief		Extract bnode into memory.
 * @param [in]	bnode	bnode to read
 * @param [in]	create	Flag if to create (1) or get existing (0) bnode
 * @return		Returns zero in case of success, error code otherwise
 */
static int read_or_create_bnode_data(struct vdfs4_bnode *bnode, int create,
		int force_insert)
{
	struct vdfs4_btree *btree = bnode->host;
	pgoff_t page_idx;
	pgprot_t prot;
	void *data;
	int ret;
	int count;
	int type = VDFS4_META_READ;
	int reread_count = VDFS4_META_REREAD_BNODE;

	page_idx = (unsigned long)bnode->node_id *
				(unsigned long)btree->pages_per_node;
	if ((btree->btree_type == VDFS4_BTREE_INST_CATALOG) ||
			(btree->btree_type == VDFS4_BTREE_INST_XATTR) ||
			(btree->btree_type == VDFS4_BTREE_INST_EXT)) {
		page_idx += (pgoff_t)btree->tree_metadata_offset;
		type = VDFS4_PACKTREE_READ;
	}

do_reread:
	ret = vdfs4_read_or_create_pages(btree->inode, page_idx,
			btree->pages_per_node, bnode->pages,
			type, 0, force_insert);
	if (ret)
		goto err_read;

	prot = PAGE_KERNEL;
	/* Unfortunately ARM don't have PAGE_KERNEL_RO */
#if defined(CONFIG_VDFS4_DEBUG) && defined(PAGE_KERNEL_RO)
	if (bnode->mode == VDFS4_BNODE_MODE_RO)
		prot = PAGE_KERNEL_RO;
#endif
	data = vdfs4_vm_map_ram(bnode->pages, btree->pages_per_node, -1, prot);
	if (!data) {
		VDFS4_ERR("unable to vmap %d pages", btree->pages_per_node);
		ret = -ENOMEM;
		release_pages(bnode->pages, (int)btree->pages_per_node, 0);
		dump_stack();
		vdfs4_fatal_error(bnode->host->sbi, "vm_map_ram fails");
		goto err_read;
	}

#ifdef CONFIG_VDFS4_DEBUG
	if (create) {
		__u16 poison_val;
		__u16 max_poison_val = (__u16)(btree->pages_per_node <<
			(PAGE_CACHE_SHIFT - 1));
		__u16 *curr_pointer = data;

		for (poison_val = 0; poison_val < max_poison_val;
				poison_val++, curr_pointer++)
			*curr_pointer = poison_val;
	}
#endif

	if (!create && bnode->node_id != 0 &&
			*(u16 *)data != VDFS4_NODE_DESCR_MAGIC) {
		VDFS4_ERR("Wrong bnode magic(%s,type:%u,mode:%u):"
				"magic:%#x,addr:0x%p,inode=%lu,bnode=%d",
				btree->sbi->sb->s_id, btree->btree_type,
				bnode->mode, *(u16 *)data, data,
				btree->inode->i_ino, bnode->node_id);
		goto err_exit_vunmap;
	}
	if (!create && !PageDirty(bnode->pages[0]) &&
			(btree->btree_type < VDFS4_BTREE_INST_CATALOG)) {
		u16 magic_len = 4;
		void *__version = (char *)data + magic_len;

		__le64 real_version, version = vdfs4_get_page_version(
				bnode->host->sbi, btree->inode, page_idx);

		real_version = *((__le64 *)(__version));
		if (real_version != version) {
			VDFS4_ERR("METADATA PAGE VERSION MISMATCH"
					"(%s, type:%u,mode:%u):"
					"inode_num-%lu,bnode_num-%u,addr:0x%p,"
					" must be - %u.%u,"
					" real - %u.%u",
					btree->sbi->sb->s_id, btree->btree_type,
					bnode->mode, btree->inode->i_ino, bnode->node_id,
					data, VDFS4_MOUNT_COUNT(version),
					VDFS4_SYNC_COUNT(version),
					VDFS4_MOUNT_COUNT(real_version),
					VDFS4_SYNC_COUNT(real_version));
			goto err_exit_vunmap;
		}
	}
#ifdef CONFIG_VDFS4_META_SANITY_CHECK
	if (create)
		vdfs4_calc_crc_for_bnode(data, btree);
	if ((!create) && (!PageChecked(bnode->pages[0]) &&
			(btree->btree_type != VDFS4_BTREE_INST_CATALOG))) {
		int verify_hash;
		__le32 calculated = __calc_crc_for_bnode(data, btree);
		__le32 from_disk = 0;

		verify_hash = __get_checksum_for_bnode(data, btree, bnode, &from_disk);

		if (!verify_hash || from_disk != calculated) {
			VDFS4_ERR("CRC mismatch(%s,type:%u,mode:%u,verify_hash:%d):"
					"(Btree Inode id:%lu,Bnode id:%u,addr:0x%p)(calc:%#x,read:%#x)",
					btree->sbi->sb->s_id, btree->btree_type,
					bnode->mode, verify_hash,
					btree->inode->i_ino, bnode->node_id, data,
					calculated, from_disk);
			destroy_layout(bnode->host->sbi);
			goto err_exit_vunmap;
		}
	}
#endif
	for (count = 0; count < (int)btree->pages_per_node; count++)
		SetPageChecked(bnode->pages[count]);

	/* publish bnode data */
	bnode->data = data;

#ifdef CONFIG_VDFS4_META_SANITY_CHECK
	if (!create)
		vdfs4_bnode_sanity_check(bnode);
#endif

	/* temporary code: first time we read incorrectly, next time
	it was ok. Need to know if such situation can really happen */
	if (reread_count != VDFS4_META_REREAD_BNODE)
		vdfs4_fatal_error(bnode->host->sbi,
		"wrong data read from mmc, need to investigate (try %d/%d)",
		VDFS4_META_REREAD_BNODE - (reread_count + 1),
		VDFS4_META_REREAD_BNODE);

	return 0;

err_exit_vunmap:
	for (count = 0; count < (int)btree->pages_per_node; count++)
		ClearPageUptodate(bnode->pages[count]);

	vdfs4_dump_bnode(bnode, data);
	vdfs4_dump_basetable(VDFS4_SB(btree->inode->i_sb), NULL, 0);

	vdfs4_record_err_dump_disk(btree->sbi, VDFS4_DEBUG_ERR_BNODE_READ,
		 btree->btree_type, page_idx, "bnode read err",
		 (void *)data, bnode->host->node_size_bytes);

	vm_unmap_ram(data, btree->pages_per_node);
	release_pages(bnode->pages, (int)btree->pages_per_node, 0);
	memset(bnode->pages, 0, sizeof(struct page *) * btree->pages_per_node);

	if (--reread_count >= 0) {
		VDFS4_ERR("do bnode re-read %d",
			VDFS4_META_REREAD - reread_count);
		goto do_reread;
	}

	ret = -EINVAL;
	if (is_sbi_flag_set(btree->sbi, IS_MOUNT_FINISHED))
		vdfs4_fatal_error(bnode->host->sbi, "file: bnode validate");

err_read:
	/* publish error code */
	bnode->data = ERR_PTR(ret);
	memset(bnode->pages, 0, sizeof(struct page *) * btree->pages_per_node);
	return ret;
}

static int bnode_hash_fn(__u32 bnode_id)
{
	/*bnode_id = (bnode_id >> 16) + bnode_id;
	bnode_id = (bnode_id >> 8) + bnode_id;*/
	return bnode_id & VDFS4_BNODE_HASH_MASK;
}

static void hash_bnode(struct vdfs4_bnode *bnode)
{
	struct vdfs4_btree *btree = bnode->host;
	int hash = bnode_hash_fn(bnode->node_id);

	hlist_add_head(&bnode->hash_node, &btree->hash_table[hash]);
}

static void unhash_bnode(struct vdfs4_bnode *bnode)
{
	hlist_del(&bnode->hash_node);
}

static struct vdfs4_bnode *get_bnode_from_hash(struct vdfs4_btree *btree,
		__u32 bnode_id, enum vdfs4_get_bnode_mode mode)
{
	int hash = bnode_hash_fn(bnode_id);
	struct hlist_node *iterator;

	hlist_for_each(iterator, &btree->hash_table[hash]) {
		struct vdfs4_bnode *node = hlist_entry(iterator,
				struct vdfs4_bnode, hash_node);
		if (node->node_id == bnode_id) {
			if (mode < node->mode)
				node->mode = mode;
			return node;
		}
	}
	return NULL;
}

static DECLARE_WAIT_QUEUE_HEAD(bnode_wq);

/**
 * @brief		Interface for extracting bnode into memory.
 * @param [in]	btree	B-tree from which bnode is to be extracted
 * @param [in]	node_id	Id of extracted bnode
 * @param [in]	mode	Mode in which the extacted bnode will be used
 * @return		Returns pointer to bnode in case of success,
 *			error code otherwise
 */
struct vdfs4_bnode *vdfs4_get_bnode(struct vdfs4_btree *btree,
		__u32 node_id, enum vdfs4_get_bnode_mode mode, int wait)
{
	struct vdfs4_bnode *bnode;

	if (node_id) {
		if (node_id >= btree->bitmap->bits_num)
			return ERR_PTR(-ENOENT);

		if (!test_bit((int)node_id, btree->bitmap->data))
			return ERR_PTR(-ENOENT);
	}

	mutex_lock(&btree->hash_lock);
	bnode = get_bnode_from_hash(btree, node_id, mode);
	if (!bnode) {
		bnode = alloc_bnode(btree, node_id, mode);
		if (IS_ERR(bnode)) {
			mutex_unlock(&btree->hash_lock);
			return bnode;
		}
		hash_bnode(bnode);
		mutex_unlock(&btree->hash_lock);
		read_or_create_bnode_data(bnode, 0, 0);
		wake_up_all(&bnode_wq);
	} else {
		bnode->ref_count++;

		/*
		 * Algorithms expects that nobody will take any bnode
		 * recursevely, so, its wrong behaviour if ref_count > 2
		 */
		if (mode == VDFS4_BNODE_MODE_RW && bnode->ref_count > 2) {
			VDFS4_ERR("bnode %d ref_count %d",
					bnode->node_id, bnode->ref_count);
		}
		mutex_unlock(&btree->hash_lock);
		wait_event(bnode_wq, bnode->data != NULL);
	}

	if (IS_ERR(bnode->data)) {
		void *ret = bnode->data;

		vdfs4_put_bnode(bnode);
		return ret;
	}

	if (mode == VDFS4_BNODE_MODE_RW) {
		vdfs4_assert_transaction(btree->sbi);
		vdfs4_assert_btree_write(btree);
	} else {
		vdfs4_assert_btree_lock(btree);
	}

	return bnode;
}

/**
 * @brief		Create, reserve and prepare new bnode.
 * @param [in]	btree	The B-tree from which bnode is to be prepared
 * @return		Returns pointer to bnode in case of success,
 *			error code otherwise
 */
struct vdfs4_bnode *vdfs4_alloc_new_bnode(struct vdfs4_btree *btree)
{
	struct vdfs4_bnode_bitmap *bitmap = btree->bitmap;
	struct vdfs4_bnode *bnode;
	void *ret;

	vdfs4_assert_btree_write(btree);

	if (bitmap->free_num == 0)
		return ERR_PTR(-ENOSPC);

	if (__test_and_set_bit((int)bitmap->first_free_id, bitmap->data)) {
		vdfs4_dump_panic_remount(
			btree->head_bnode, VDFS4_DEBUG_ERR_BNODE_ALLOC,
			"cannot allocate bnode id");
		return ERR_PTR(-EFAULT);
	}

	bnode = alloc_bnode(btree, bitmap->first_free_id, VDFS4_BNODE_MODE_RW);
	ret = bnode;
	if (IS_ERR(bnode))
		goto out_err;

	if (read_or_create_bnode_data(bnode, 1, 0))
		goto out_err_create;

	/* Updata bitmap information */
	bitmap->first_free_id = (__u32)find_next_zero_bit(bitmap->data,
			(unsigned long)bitmap->bits_num,
			(unsigned long)bitmap->first_free_id);
	bitmap->free_num--;
	vdfs4_mark_bnode_dirty(btree->head_bnode);
	mutex_lock(&btree->hash_lock);
	hash_bnode(bnode);
	mutex_unlock(&btree->hash_lock);

	return bnode;

out_err_create:
	ret = bnode->data;
	free_bnode(bnode);
out_err:
	__clear_bit((int)bitmap->first_free_id, bitmap->data);
	return ret;
}

static void mark_bnode_accessed(struct vdfs4_bnode *bnode)
{
	unsigned int i;

	if (!bnode->pages[0] || PageActive(bnode->pages[0]))
		return;

	for (i = 0; i < bnode->host->pages_per_node; i++) {
		/* force page activation */
		SetPageReferenced(bnode->pages[i]);
		mark_page_accessed(bnode->pages[i]);
	}
}

static struct vdfs4_bnode *alloc_bnode(struct vdfs4_btree *btree,
		__u32 node_id, enum vdfs4_get_bnode_mode mode)
{
	struct vdfs4_bnode *bnode;

	bnode = kzalloc(sizeof(struct vdfs4_bnode) +
			sizeof(struct page *) * btree->pages_per_node,
			GFP_NOFS);
	if (!bnode)
		return ERR_PTR(-ENOMEM);

	bnode->host = btree;
	bnode->node_id = node_id;
	bnode->mode = mode;
	bnode->ref_count = 1;

	return bnode;
}

static void free_bnode(struct vdfs4_bnode *bnode)
{
	unsigned int i;

	if (!IS_ERR_OR_NULL(bnode->data))
		vm_unmap_ram(bnode->data, bnode->host->pages_per_node);
	bnode->data = NULL;

	for (i = 0; i < bnode->host->pages_per_node; i++) {
		if (!IS_ERR_OR_NULL(bnode->pages[i]))
			page_cache_release(bnode->pages[i]);
		bnode->pages[i] = NULL;
	}

	kfree(bnode);
}

/**
 * @brief		Interface for freeing bnode structure.
 * @param [in]	bnode	Node to be freed
 * @return	void
 */
void vdfs4_put_bnode(struct vdfs4_bnode *bnode)
{
	struct vdfs4_btree *btree = bnode->host;

	mutex_lock(&btree->hash_lock);
	if (bnode->ref_count <= 0) {
		vdfs4_dump_panic_remount(
			btree->head_bnode, VDFS4_DEBUG_ERR_BNODE_PUT,
			"ref count less 0");
	}
	if (--bnode->ref_count == 0)
		unhash_bnode(bnode);
	else
		bnode = NULL;
	mutex_unlock(&btree->hash_lock);

	if (bnode) {
		mark_bnode_accessed(bnode);
		free_bnode(bnode);
	}
}

/**
 * @brief			preallocate a reseve for splitting btree
 * @param btee			which btree needs bnodes reserve
 * @param alloc_to_bnode_id	at least this bnode will be available after
 *				expanding
 * @return			0 on success or err code
 * */
static int vdfs4_prealloc_one_bnode_reserve(struct vdfs4_btree *btree,
		__u32 reserving_bnode_id, int force_insert)
{
	struct vdfs4_bnode *bnode;
	int ret;

	bnode = alloc_bnode(btree, reserving_bnode_id, VDFS4_BNODE_MODE_RW);
	if (IS_ERR(bnode))
		return PTR_ERR(bnode);

	ret = read_or_create_bnode_data(bnode, 1, force_insert);
	if (ret)
		goto out;
	vdfs4_init_new_node_descr(bnode, 0);
	vdfs4_mark_bnode_dirty(bnode);
out:
	free_bnode(bnode);

	return ret;
}

/**
 * @brief		checks if btree has anough bnodes for safe splitting,
 *			and tries to allocate resever if it has not.
 * @param [in] btree	which btree to check
 * @return		0 if success or error code
 * */
int vdfs4_check_bnode_reserve(struct vdfs4_btree *btree, int force_insert)
{
	pgoff_t available_bnodes, free_bnodes, used_bnodes, i, bnodes_deficit;
	pgoff_t new_bnodes_num, reserve;
	int ret = 0;

	reserve = (pgoff_t)(vdfs4_btree_get_height(btree) * 4);

	down_read(&btree->sbi->snapshot_info->tables_lock);
	available_bnodes = (pgoff_t)VDFS4_LAST_TABLE_INDEX(btree->sbi,
			btree->inode->i_ino) + 1lu;
	up_read(&btree->sbi->snapshot_info->tables_lock);

	used_bnodes = btree->bitmap->bits_num - btree->bitmap->free_num;

	free_bnodes = available_bnodes - used_bnodes;

	bnodes_deficit = reserve - free_bnodes;

	if (bnodes_deficit <= 0)
		goto exit;

	new_bnodes_num = available_bnodes + bnodes_deficit;
	for (i = available_bnodes; i < new_bnodes_num; i++) {
		ret = vdfs4_prealloc_one_bnode_reserve(btree, (__u32)i,
				force_insert);
		if (ret)
			break;
	}

exit:
	return ret;
}


/**
 * @brief		Mark bnode as free.
 * @param [in]	bnode	Node to be freed
 * @return	0 on success and error code on failure
 */
int vdfs4_destroy_bnode(struct vdfs4_bnode *bnode)
{
	__u32 bnode_id = bnode->node_id;
	struct vdfs4_btree *btree = bnode->host;
	struct vdfs4_bnode_bitmap *bitmap = btree->bitmap;
	int err = 0;


	if (bnode_id == VDFS4_INVALID_NODE_ID) {
		vdfs4_dump_panic_remount(
			bnode, VDFS4_DEBUG_ERR_BNODE_DESTROY,
			"invalid bnode id %u", bnode_id);
		return -EINVAL;
	}

	mutex_lock(&btree->hash_lock);
	if (--bnode->ref_count != 0) {
		vdfs4_dump_panic_remount(
			bnode, VDFS4_DEBUG_ERR_BNODE_DESTROY,
			"invalid ref count %d", bnode->ref_count);
		mutex_unlock(&btree->hash_lock);
		return -EFAULT;
	}

	unhash_bnode(bnode);
	mutex_unlock(&btree->hash_lock);

	free_bnode(bnode);

	if (!vdfs4_test_and_clear_bit((int)bnode_id, bitmap->data)) {
		vdfs4_dump_panic_remount(
			btree->head_bnode, VDFS4_DEBUG_ERR_BNODE_DESTROY,
			"already clear bit %u", bnode_id);
		return -EFAULT;
	}

	/* TODO - the comment same as at vdfs4_alloc_new_bnode */
	vdfs4_mark_bnode_dirty(btree->head_bnode);
	if (bitmap->first_free_id > bnode_id)
		bitmap->first_free_id = bnode_id;
	bitmap->free_num++;

	return err;
}

/**
 * @brief			Build free bnode bitmap runtime structure.
 * @param [in]	data		Pointer to reserved memory area satisfying
 *				to keep bitmap
 * @param [in]	start_bnode_id	Starting bnode id to fix into bitmap
 * @param [in]	size_in_bytes	Size of reserved memory area in bytes
 * @param [in]	host_bnode	Pointer to bnode containing essential info
 * @return			Returns pointer to bitmap on success,
 *				error code on failure
 */
struct vdfs4_bnode_bitmap *vdfs4_build_free_bnode_bitmap(void *data,
		__u32 start_bnode_id, __u64 size_in_bytes,
		struct vdfs4_bnode *host_bnode)
{
	struct vdfs4_bnode_bitmap *bitmap;

	if (!host_bnode)
		return ERR_PTR(-EINVAL);

	bitmap = kzalloc(sizeof(*bitmap), GFP_NOFS);
	if (!bitmap)
		return ERR_PTR(-ENOMEM);

	bitmap->data = data;
	bitmap->size = size_in_bytes;
	bitmap->bits_num = (__u32)(bitmap->size * 8);

	bitmap->start_id = start_bnode_id;
	bitmap->end_id = start_bnode_id + bitmap->bits_num;

	bitmap->free_num = (__u32)bitmap->bits_num -
		(__u32)__bitmap_weight(bitmap->data, (int)bitmap->bits_num);
	bitmap->first_free_id = (__u32)find_first_zero_bit(bitmap->data,
			bitmap->bits_num) + start_bnode_id;

	bitmap->host = host_bnode;

	return bitmap;
}

/**
 * @brief		Clear memory allocated for bnode bitmap.
 * @param [in]	bitmap	Bitmap to be cleared
 * @return	void
 */
void vdfs4_destroy_free_bnode_bitmap(struct vdfs4_bnode_bitmap *bitmap)
{
	kfree(bitmap);
}

/**
 * @brief		Mark bnode as dirty (data on disk and in memory
 *			differ).
 * @param [in]	bnode	Node to be marked as dirty
 * @return	void
 */
void vdfs4_mark_bnode_dirty(struct vdfs4_bnode *node)
{
	VDFS4_BUG_ON(!node, NULL);
	if (node->mode != VDFS4_BNODE_MODE_RW) {
		vdfs4_dump_panic_remount(
			node, VDFS4_DEBUG_ERR_BNODE_DIRTY,
			"invalid bnode mode %u", node->mode);
	}
	vdfs4_assert_btree_write(node->host);
	vdfs4_add_chunk_bnode(node->host->sbi, node->pages);
}

int vdfs4_check_and_sign_dirty_bnodes(struct page **page,
		struct vdfs4_btree *btree, __u64 version)
{
	void *bnode_data;

	bnode_data = vdfs4_vm_map_ram(page, btree->pages_per_node,
				-1, PAGE_KERNEL);
	if (!bnode_data) {
		VDFS4_ERR("can not allocate virtual memory");
		return -ENOMEM;
	}
#ifdef CONFIG_VDFS4_META_SANITY_CHECK
	vdfs4_meta_sanity_check_bnode(bnode_data, btree, page[0]->index);
#endif
	memcpy((char *)bnode_data + 4, &version, VERSION_SIZE);
#ifdef CONFIG_VDFS4_META_SANITY_CHECK
	vdfs4_calc_crc_for_bnode(bnode_data, btree);
#endif
	vm_unmap_ram(bnode_data, btree->pages_per_node);
	return 0;
}
