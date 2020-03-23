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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/buffer_head.h>
#include <linux/crc32.h>
#include <linux/version.h>
#include <linux/genhd.h>
#include <linux/exportfs.h>
#include <linux/vmalloc.h>
#include <linux/writeback.h>
#include <linux/bootmem.h>
#include <linux/mutex.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/freezer.h>
#include <linux/blkdev.h>
#include <linux/crypto.h>
#include <linux/random.h>

#include "vdfs4_layout.h"
#include "vdfs4.h"
#include "btree.h"
#include "debug.h"

#include "cattree.h"
#include "exttree.h"
#include "xattrtree.h"
#ifdef CONFIG_VDFS4_DATA_AUTHENTICATION
#include "public_key.h"
#endif

static inline void vdfs4_check_layout(void)
{
	BUILD_BUG_ON(sizeof(struct vdfs4_timespec) != 12);
	BUILD_BUG_ON(sizeof(struct vdfs4_extent) != 16);
	BUILD_BUG_ON(sizeof(struct vdfs4_iextent) != 24);

	BUILD_BUG_ON(sizeof(struct vdfs4_catalog_folder_record) != 10 * 8);
	BUILD_BUG_ON(sizeof(struct vdfs4_fork) != 29 * 8);
	BUILD_BUG_ON(sizeof(struct vdfs4_catalog_file_record) != 39 * 8);

	BUILD_BUG_ON(sizeof(struct vdfs4_translation_record) != 16);
	BUILD_BUG_ON(sizeof(struct vdfs4_snapshot_descriptor) != 24);
	BUILD_BUG_ON(sizeof(struct vdfs4_base_table) != 24 + VDFS4_SF_NR * 16);
	BUILD_BUG_ON(sizeof(struct vdfs4_extended_table) != 24 + 8);
	BUILD_BUG_ON(sizeof(struct vdfs4_debug_record) != 64);
	BUILD_BUG_ON(sizeof(struct vdfs4_debug_descriptor) != 12);

	BUILD_BUG_ON(sizeof(struct vdfs4_super_block) != 512);
	BUILD_BUG_ON(sizeof(struct vdfs4_volume_begins) != 512);
	BUILD_BUG_ON(sizeof(struct vdfs4_extended_super_block) != 512 * 5);

	BUILD_BUG_ON(sizeof(struct vdfs4_gen_node_descr) != 8 * 4);
	BUILD_BUG_ON(sizeof(struct generic_index_value) != 4);

	BUILD_BUG_ON(sizeof(struct vdfs4_catalog_hlink_record) != 1 * 8);
	BUILD_BUG_ON(sizeof(struct vdfs4_comp_extent) != 2 * 8);
	BUILD_BUG_ON(sizeof(struct vdfs4_comp_file_descr) != 4 * 8);
}

static struct lock_class_key catalog_tree_lock_key;
static struct lock_class_key extents_tree_lock_key;
static struct lock_class_key xattr_tree_lock_key;

static struct kset *vdfs4_kset;

#define VDFS4_MOUNT_INFO(fmt, ...)\
do {\
	printk(KERN_INFO "[VDFS4] " fmt, ##__VA_ARGS__);\
} while (0)

/**
 * @brief			B-tree destructor.
 * @param [in,out]	btree	Pointer to btree that will be destroyed
 * @return		void
 */
void vdfs4_put_btree(struct vdfs4_btree *btree, int iput_inode)
{
	int i;

	vdfs4_put_bnode(btree->head_bnode);

	for (i = 0; i < VDFS4_BNODE_HASH_SIZE; i++)
		VDFS4_BUG_ON(!hlist_empty(btree->hash_table + i));

	vdfs4_destroy_free_bnode_bitmap(btree->bitmap);
	VDFS4_BUG_ON(!btree->head_bnode);
	if (iput_inode)
		iput(btree->inode);
	kfree(btree->split_buff);
	kfree(btree);
}

/**
 * @brief			Inode bitmap destructor.
 * @param [in,out]	sbi	Pointer to sb info which free_inode_bitmap
 *				will be destroyed
 * @return		void
 */
static void destroy_free_inode_bitmap(struct vdfs4_sb_info *sbi)
{
	iput(sbi->free_inode_bitmap.inode);
	sbi->free_inode_bitmap.inode = NULL;
}

/** Debug mask is a module parameter. This parameter enables particular debug
 *  type printing (see VDFS4_DBG_* in fs/vdfs4/debug.h).  */
unsigned int vdfs4_debug_mask = 0
		/*+ VDFS4_DBG_INO*/
		/*+ VDFS4_DBG_FSM*/
		/*+ VDFS4_DBG_SNAPSHOT*/
		/*+ VDFS4_DBG_TRANSACTION*/
		+ VDFS4_DBG_TMP
		;

/** The eMMCFS inode cache
 */
static struct kmem_cache *vdfs4_inode_cachep;


void vdfs4_init_inode(struct vdfs4_inode_info *inode)
{
	inode->name = NULL;
	inode->fork.total_block_count = 0;
	inode->record_type = 0;

	inode->fork.prealloc_block_count = 0;
	inode->fork.prealloc_start_block = 0;

	inode->flags = 0;
	inode->fbc = NULL;

	INIT_LIST_HEAD(&inode->orphan_list);
	inode->next_orphan_id = (u64)(-1);
}
/**
 * @brief			Method to allocate inode.
 * @param [in,out]	sb	Pointer to eMMCFS superblock
 * @return			Returns pointer to inode, NULL on failure
 */
static struct inode *vdfs4_alloc_inode(struct super_block *sb)
{
	struct vdfs4_inode_info *inode;

	inode = kmem_cache_alloc(vdfs4_inode_cachep, GFP_NOFS);
	if (!inode)
		return NULL;

	vdfs4_init_inode(inode);

	return &inode->vfs_inode;
}


static void vdfs4_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct vdfs4_inode_info *inode_info = VDFS4_I(inode);

	kmem_cache_free(vdfs4_inode_cachep, inode_info);
}
/**
 * @brief			Method to destroy inode.
 * @param [in,out]	inode	Pointer to inode for destroy
 * @return		void
 */
static void vdfs4_destroy_inode(struct inode *inode)
{
	struct vdfs4_inode_info *inode_info = VDFS4_I(inode);

	kfree(inode_info->name);

	call_rcu(&inode->i_rcu, vdfs4_i_callback);
}

/**
 * @brief		Sync starting superblock.
 * @param [in]	sb	Superblock information
 * @return		Returns error code
 */
int vdfs4_sync_first_super(struct vdfs4_sb_info *sbi)
{
	struct vdfs4_layout_sb *l_sb = sbi->raw_superblock;
	struct vdfs4_extended_super_block *exsb = &l_sb->exsb;
	__u32 checksum;
	int ret = 0;

	lock_page(sbi->superblocks);

	exsb->files_count = cpu_to_le64(sbi->files_count);
	exsb->folders_count = cpu_to_le64(sbi->folders_count);
	checksum = crc32(0, exsb, sizeof(*exsb) - sizeof(exsb->checksum));
	exsb->checksum = cpu_to_le32(checksum);
	set_page_writeback(sbi->superblocks);
	ret = vdfs4_write_page(sbi, sbi->superblocks, VDFS4_EXSB_OFFSET,
		VDFS4_EXSB_SIZE_SECTORS, 3 * SB_SIZE_IN_SECTOR * SECTOR_SIZE, 1);
#ifdef CONFIG_VDFS4_STATISTIC
	sbi->umount_written_bytes += (VDFS4_EXSB_SIZE_SECTORS
			<< SECTOR_SIZE_SHIFT);
#endif
	unlock_page(sbi->superblocks);

	return ret;
}

/**
 * @brief		Sync finalizing superblock.
 * @param [in]	sb	Superblock information
 * @return		Returns error code
 */
int vdfs4_sync_second_super(struct vdfs4_sb_info *sbi)
{
	int ret = 0;
	__u32 checksum;
	struct vdfs4_layout_sb *l_sb = sbi->raw_superblock;
	struct vdfs4_extended_super_block *exsb = &l_sb->exsb;

	lock_page(sbi->superblocks);
	set_page_writeback(sbi->superblocks);
		/* Update cheksum */
	exsb->files_count = cpu_to_le64(sbi->files_count);
	exsb->folders_count = cpu_to_le64(sbi->folders_count);
	checksum = crc32(0, exsb, sizeof(*exsb) - sizeof(exsb->checksum));
	exsb->checksum = cpu_to_le32(checksum);
	ret = vdfs4_write_page(sbi, sbi->superblocks, VDFS4_EXSB_COPY_OFFSET,
		VDFS4_EXSB_SIZE_SECTORS, 3 * SB_SIZE_IN_SECTOR * SECTOR_SIZE, 1);
#ifdef CONFIG_VDFS4_STATISTIC
	sbi->umount_written_bytes += (VDFS4_EXSB_SIZE_SECTORS
			<< SECTOR_SIZE_SHIFT);
#endif
	unlock_page(sbi->superblocks);

	return ret;
}

/**
 * @brief		Method to write out all dirty data associated
 *				with the superblock.
 * @param [in,out]	sb	Pointer to the eMMCFS superblock
 * @param [in,out]	wait	Block on write completion
 * @return		Returns 0 on success, errno on failure
 */
int vdfs4_sync_fs(struct super_block *sb, int wait)
{
	struct vdfs4_sb_info *sbi = sb->s_fs_info;
	struct vdfs4_snapshot_info *si = sbi->snapshot_info;
	int ret = 0;

	if (wait) {
		int *transaction_count = (int *)&current->journal_info;
		struct list_head *iter;

		down_write(&si->transaction_lock);
		(*transaction_count)++;
		sync_inodes_sb(sb);

		down_write(&si->writeback_lock);

		list_for_each(iter, &sbi->orphan_inodes) {
			struct vdfs4_inode_info *inode_i = list_entry(iter,
					struct vdfs4_inode_info, orphan_list);
			struct inode *inode = &inode_i->vfs_inode;
			struct address_space *mapping = inode->i_mapping;

			if ((inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW)) ||
					(mapping->nrpages == 0))
				if ((S_ISREG(inode->i_mode) ||
					S_ISLNK(inode->i_mode)) &&
					(inode_i->vfs_inode.i_ino != 1)) {
					mutex_w_lock(sbi->catalog_tree->
							rw_tree_lock);
			/* an error is handled in __vdfs4_write_inode */
					__vdfs4_write_inode(sbi, inode);
					mutex_w_unlock(sbi->catalog_tree->
							rw_tree_lock);
				}
		}

		ret = vdfs4_sync_metadata(sbi);
		if (ret)
			vdfs4_fatal_error(sbi, "metadata commit failed:%d", ret);
		up_write(&si->writeback_lock);
		(*transaction_count)--;
		up_write(&si->transaction_lock);
	}

	return ret;
}

static void vdfs4_delayed_commit(struct work_struct *work)
{
	struct vdfs4_sb_info *sbi = container_of(to_delayed_work(work),
					struct vdfs4_sb_info, delayed_commit);
	struct super_block *sb = sbi->sb;

	if (down_read_trylock(&sb->s_umount)) {
		sync_filesystem(sb);
		up_read(&sb->s_umount);
	} else if (sb->s_flags & MS_ACTIVE) {
		/* Try again later */
		mod_delayed_work(system_wq, &sbi->delayed_commit, HZ);
	}
}

#ifdef CONFIG_VDFS4_DEBUG
static void vdfs4_save_debug_area(struct vdfs4_sb_info *sbi)
{
	struct page **debug_pages;
	int count;
	struct vdfs4_layout_sb *l_sb = sbi->raw_superblock;
	unsigned int debug_area_start =
			(unsigned int)l_sb->exsb.debug_area.begin;
	unsigned int debug_page_count =
			(unsigned int)l_sb->exsb.debug_area.length;

	void *debug_area = NULL;
	int is_not_debug_area;
	int ret;

	debug_pages = kzalloc(sizeof(struct page *) * debug_page_count,
			GFP_NOFS);

	if (!debug_pages)
		return;

	for (count = 0; count < (int)debug_page_count; count++) {
		debug_pages[count] = alloc_page(GFP_NOFS | __GFP_ZERO);
		if (!debug_pages[count]) {
			count--;
			for (; count >= 0; count--) {
				unlock_page(debug_pages[count]);
				__free_page(debug_pages[count]);
			}
			kfree(debug_pages);
			return;
		}
		lock_page(debug_pages[count]);
	}

	ret = vdfs4_read_pages(sbi->sb->s_bdev, debug_pages,
			debug_area_start << (PAGE_CACHE_SHIFT -
				SECTOR_SIZE_SHIFT), debug_page_count);

	for (count = 0; count < (int)debug_page_count; count++) {
		unlock_page(debug_pages[count]);
		if (!PageUptodate(debug_pages[count]))
			ret = -EIO;
	}
	if (ret)
		goto exit_free_page;

	debug_area = vdfs4_vmap(debug_pages, debug_page_count, VM_MAP, PAGE_KERNEL);
	if (!debug_area)
		goto exit_free_page;

	is_not_debug_area = (strncmp(debug_area, VDFS4_OOPS_MAGIC,
			sizeof(VDFS4_OOPS_MAGIC) - 1));

	if (*(int *)debug_area && is_not_debug_area) {
		const char name[] = "dump_debug_area.dump";
		/* we have something in the debug area */
		vdfs4_dump_chunk_to_disk(debug_area,
			debug_page_count << PAGE_SHIFT, name, strlen(name));
		memset(debug_area, 0x0, debug_page_count << PAGE_SHIFT);

		for (count = 0; count < (int)debug_page_count; count++) {
			sector_t sector_to_write;
			sector_to_write = (sector_t)(debug_area_start <<
					(PAGE_CACHE_SHIFT - SECTOR_SIZE_SHIFT));
			sector_to_write += (sector_t)(count
						<< (PAGE_CACHE_SHIFT
							- SECTOR_SIZE_SHIFT));

			lock_page(debug_pages[count]);
			set_page_writeback(debug_pages[count]);
			ret = vdfs4_write_page(sbi, debug_pages[count],
				sector_to_write, 8, 0, 1);
			unlock_page(debug_pages[count]);
			if (ret)
				goto exit_unmap_page;
		}
	}

exit_unmap_page:
	vunmap(debug_area);

exit_free_page:
	for (count = 0; count < (int)debug_page_count; count++)
		__free_page(debug_pages[count]);

	kfree(debug_pages);
}
#endif

#ifdef CONFIG_VDFS4_DEBUG
static void vdfs4_delayed_save_debug_area(struct work_struct *work)
{
	struct vdfs4_sb_info *sbi = container_of(to_delayed_work(work),
					struct vdfs4_sb_info,
					delayed_check_debug_area);
	struct super_block *sb = sbi->sb;
	if (down_read_trylock(&sb->s_umount)) {
		vdfs4_save_debug_area(sbi);
		up_read(&sb->s_umount);
	} else if (sb->s_flags & MS_ACTIVE) {
		/* Try again later */
		mod_delayed_work(system_wq, &sbi->delayed_check_debug_area, HZ);
	}
}
#endif


/**
 * @brief			Method to free superblock (unmount).
 * @param [in,out]	sbi	Pointer to the eMMCFS superblock
 * @return		void
 */
static void destroy_super(struct vdfs4_sb_info *sbi)
{
	sbi->raw_superblock_copy = NULL;
	sbi->raw_superblock = NULL;

	if (sbi->superblocks) {
		kunmap(sbi->superblocks);
		__free_pages(sbi->superblocks, 0);
	}

	if (sbi->superblocks_copy) {
		kunmap(sbi->superblocks_copy);
		__free_pages(sbi->superblocks_copy, 0);
	}
}

/**
 * @brief			Method to free sbi info.
 * @param [in,out]	sb	Pointer to a superblock
 * @return		void
 */
static void vdfs4_put_super(struct super_block *sb)
{
	struct vdfs4_sb_info *sbi = sb->s_fs_info;

#ifdef CONFIG_VDFS4_DEBUG
	cancel_delayed_work_sync(&sbi->delayed_check_debug_area);
#endif

	cancel_delayed_work_sync(&sbi->delayed_commit);
	sbi->umount_time = 1;
	vdfs4_put_btree(sbi->catalog_tree, 1);
	sbi->catalog_tree = NULL;
	vdfs4_put_btree(sbi->extents_tree, 1);
	sbi->extents_tree = NULL;
	vdfs4_put_btree(sbi->xattr_tree, 1);
	sbi->xattr_tree = NULL;

	if (sbi->free_inode_bitmap.inode)
		destroy_free_inode_bitmap(sbi);

	if (sbi->fsm_info)
		vdfs4_fsm_destroy_management(sb);
#ifdef CONFIG_VDFS4_DATA_AUTHENTICATION
	if (sbi->rsa_key)
		vdfs4_destroy_rsa_key(sbi->rsa_key);
#endif
/*	if (VDFS4_DEBUG_PAGES(sbi))
		vdfs4_free_debug_area(sb);*/

	vdfs4_destroy_high_priority(&sbi->high_priority);
	if (sbi->snapshot_info)
		vdfs4_destroy_snapshot_manager(sbi);

	kobject_del(&sbi->s_kobj);
	kobject_put(&sbi->s_kobj);
	wait_for_completion(&sbi->s_kobj_unregister);

	destroy_super(sbi);

#ifdef CONFIG_VDFS4_STATISTIC
	printk(KERN_INFO "Bytes written during umount : %lld\n",
			sbi->umount_written_bytes);
#endif

	kfree(sbi);
	VDFS4_DEBUG_SB("finished");
}

/**
 * @brief			This function handle umount start.
 * @param [in,out]	sb	Pointer to a superblock
 * @return		void
 */
static void vdfs4_umount_begin(struct super_block *sb)
{
#ifdef CONFIG_VDFS4_STATISTIC
	struct vdfs4_sb_info *sbi = sb->s_fs_info;
	/* reset the page counter */
	sbi->umount_written_bytes = 0;
#endif
}
/**
 * @brief			Force FS into a consistency state and
 *				lock it (for LVM).
 * @param [in,out]	sb	Pointer to the eMMCFS superblock
 * @remark			TODO: detailed description
 * @return			Returns 0 on success, errno on failure
 */
static int vdfs4_freeze(struct super_block *sb)
{
	/* d.voytik-TODO-29-12-2011-17-24-00: [vdfs4_freeze]
	 * implement vdfs4_freeze() */
	int ret = 0;
	VDFS4_DEBUG_SB("finished (ret = %d)", ret);
	return ret;
}

/**
 * @brief			Calculates metadata size, using extended
 *				superblock's forks
 * @param [in,out]	sbi	Pointer to the eMMCFS superblock
 * @return		metadata size in 4K-blocks
 */
static u64 calc_special_files_size(struct vdfs4_sb_info *sbi)
{
	u64 res = 0;
	struct vdfs4_layout_sb *l_sb = sbi->raw_superblock;
	struct vdfs4_extended_super_block *exsb = &l_sb->exsb;

	res += le64_to_cpu(exsb->meta_tbc);
	res += le64_to_cpu(exsb->tables.length);

	return res;
}

/**
 * @brief			Get FS statistics.
 * @param [in,out]	dentry	Pointer to directory entry
 * @param [in,out]	buf	Point to kstatfs buffer where information
 *				will be placed
 * @return			Returns 0 on success, errno on failure
 */

static int vdfs4_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block	*sb = dentry->d_sb;
	struct vdfs4_sb_info	*sbi = sb->s_fs_info;
	struct vdfs4_layout_sb *l_sb = sbi->raw_superblock;
#ifdef CONFIG_VDFS4_CHECK_FRAGMENTATION
	int count;
#endif

	buf->f_type = (long) VDFS4_SB_SIGNATURE;
	buf->f_bsize = (long int)sbi->block_size;
	buf->f_blocks = sbi->volume_blocks_count;
	buf->f_bavail = buf->f_bfree = sbi->free_blocks_count;
	buf->f_files = sbi->files_count + sbi->folders_count + 0xfefefe;
	memcpy((void *)&buf->f_fsid.val[0], l_sb->exsb.volume_uuid,
			sizeof(int));
	memcpy((void *)&buf->f_fsid.val[1], l_sb->exsb.volume_uuid +
			sizeof(int), sizeof(int));
	buf->f_namelen = VDFS4_FILE_NAME_LEN;
	/* the vdfs4 has no limitation
	 * but in case if end of space  it could be wrong*/
	buf->f_ffree = 0xfefefe;

	return 0;
}

/**
 * @brief			Evict inode.
 * @param [in,out]	inode	Pointer to inode that will be evicted
 * @return		void
 */
static void vdfs4_evict_inode(struct inode *inode)
{
	struct vdfs4_sb_info *sbi = VDFS4_SB(inode->i_sb);
	int error = 0;
	sector_t freed_runtime_iblocks;

	VDFS4_DEBUG_INO("evict inode %lu nlink\t%u",
			inode->i_ino, inode->i_nlink);

	truncate_inode_pages(&inode->i_data, 0);
	invalidate_inode_buffers(inode);

	/* Inode isn't present in catalog tree */
	if (!inode->i_ino)
		goto no_delete;

	if (VDFS4_I(inode)->record_type == VDFS4_CATALOG_UNPACK_INODE) {
		inode->i_state = I_FREEING | I_CLEAR;
		return;
	}

	if (is_dlink(inode)) {
		iput(VDFS4_I(inode)->data_link.inode);
		VDFS4_I(inode)->data_link.inode = NULL;
	}

	if ((S_ISREG(inode->i_mode) || S_ISLNK(inode->i_mode))) {
		freed_runtime_iblocks = vdfs4_truncate_runtime_blocks(0,
			&VDFS4_I(inode)->runtime_extents);
		vdfs4_free_reserved_space(inode, freed_runtime_iblocks);
	}

	if (inode->i_nlink)
		goto no_delete;

	vdfs4_start_transaction(sbi);

	error = vdfs4_xattrtree_remove_all(sbi->xattr_tree, inode->i_ino);
	if (error) {
		vdfs4_fatal_error(sbi,
			"cannot clear xattrs for ino#%lu: %d",
			inode->i_ino, error);
		goto out_trans;
	}

	if (S_ISREG(inode->i_mode) || S_ISLNK(inode->i_mode)) {
		error = vdfs4_truncate_blocks(inode, 0);
		if (error) {
			vdfs4_fatal_error(sbi,
					"cannot truncate ino#%lu blocks: %d",
					inode->i_ino, error);
			goto out_trans;
		}
		inode->i_size = 0;
	}

	mutex_w_lock(sbi->catalog_tree->rw_tree_lock);

	if (is_vdfs4_inode_flag_set(inode, HARD_LINK))
		error = vdfs4_cattree_remove(sbi->catalog_tree, inode->i_ino,
				inode->i_ino, NULL, 0,
				VDFS4_I(inode)->record_type);
	else
		error = vdfs4_cattree_remove(sbi->catalog_tree, inode->i_ino,
				VDFS4_I(inode)->parent_id,
				VDFS4_I(inode)->name,
				strlen(VDFS4_I(inode)->name),
				VDFS4_I(inode)->record_type);
	if (error) {
		vdfs4_fatal_error(sbi, "cannot remove inode ino#%lu: %d",
				inode->i_ino, error);
		goto out_unlock;
	}

	vdfs4_del_from_orphan(sbi, inode);
	error = 0;

out_unlock:
	mutex_w_unlock(sbi->catalog_tree->rw_tree_lock);

	if (!error) {
		vdfs4_free_inode_n(sbi, inode->i_ino, 1);

		if (S_ISDIR(inode->i_mode))
			sbi->folders_count--;
		else
			sbi->files_count--;
	}

out_trans:
	vdfs4_stop_transaction(sbi);

no_delete:
	clear_inode(inode);
}

int vdfs4_remount_fs(struct super_block *sb, int *flags, char *data);

/*
 * Structure of the eMMCFS super block operations
 */
static struct super_operations vdfs4_sops = {
	.alloc_inode	= vdfs4_alloc_inode,
	.destroy_inode	= vdfs4_destroy_inode,
	.write_inode	= vdfs4_write_inode,
	.put_super	= vdfs4_put_super,
	.sync_fs	= vdfs4_sync_fs,
	.freeze_fs	= vdfs4_freeze,
	.statfs		= vdfs4_statfs,
	.umount_begin	= vdfs4_umount_begin,
	.remount_fs	= vdfs4_remount_fs,
	.show_options	= vdfs4_show_options,
	.evict_inode	= vdfs4_evict_inode,
};
/**
 * @brief			Sanity check of eMMCFS super block.
 * @param [in]	esb		The eMMCFS super block
 * @param [in]	str_sb_type	Determines which SB is verified on error
 *				printing
 * @param [in]	silent		Doesn't print errors if silent is true
 * @return			Returns 0 on success, errno on failure
 */
static int vdfs4_verify_sb(struct vdfs4_super_block *esb, char *str_sb_type,
				int silent, int check_signature,
				struct vdfs4_sb_info *sbi)
{
	__le32 checksum;
	/* check magic number */
	if (memcmp(esb->signature, VDFS4_SB_SIGNATURE,
				strlen(VDFS4_SB_SIGNATURE))) {
		if (!silent || vdfs4_debug_mask & VDFS4_DBG_SB)
			pr_err("%s: bad signature - %.8s, expected - %.8s\n",
				str_sb_type, esb->signature, VDFS4_SB_SIGNATURE);
		return -EINVAL;
	}

	if (memcmp(esb->layout_version, VDFS4_LAYOUT_VERSION,
		strlen(VDFS4_LAYOUT_VERSION))) {
		VDFS4_ERR("Invalid mkfs layout version: %.4s,\n"
			"driver uses %.4s version\n", esb->layout_version,
			VDFS4_LAYOUT_VERSION);
		return -EINVAL;
	}

	/* check crc32 */
	checksum = crc32(0, esb, sizeof(*esb) - sizeof(esb->checksum));
	if (esb->checksum != checksum) {
		VDFS4_ERR("%s: bad checksum - 0x%x, must be 0x%x\n",
				str_sb_type, esb->checksum, checksum);
		return -EINVAL;
	}

#ifdef CONFIG_VDFS4_DATA_AUTHENTICATION
	/* check the superblock rsa signature */
	if (check_signature && vdfs4_verify_superblock_rsa_signature(esb->hash_type,
		(unsigned char *)esb, sizeof(*esb) - sizeof(esb->checksum)
			- sizeof(esb->sb_hash), esb->sb_hash, sbi->rsa_key)) {
		pr_err("bad superblock hash!!!");
#ifndef	CONFIG_VDFS4_DEBUG_AUTHENTICAION
		return -EINVAL;
#endif
	}
#endif
	return 0;
}
/**
 * @brief		Fill run-time superblock from on-disk superblock.
 * @param [in]	esb	The eMMCFS super block
 * @param [in]	sb	VFS superblock
 * @return		Returns 0 on success, errno on failure
 */
static int fill_runtime_superblock(struct vdfs4_super_block *esb,
		struct super_block *sb)
{
	int ret = 0;
	unsigned long blck_size;
	struct vdfs4_sb_info *sbi = sb->s_fs_info;

	/* check total block count in SB */
	if ((esb->mkfs_git_branch[0] || esb->mkfs_git_branch[1] ||
		esb->mkfs_git_branch[2]  || esb->mkfs_git_branch[3]) &&
		(esb->mkfs_git_hash[0] || esb->mkfs_git_hash[1] ||
		esb->mkfs_git_hash[2] || esb->mkfs_git_hash[3])) {
		VDFS4_MOUNT_INFO("mkfs git branch is \"%s\"\n",
				esb->mkfs_git_branch);
		VDFS4_MOUNT_INFO("mkfs git revhash \"%.40s\"\n",
				esb->mkfs_git_hash);
	}

	/* check if block size is supported and set it */
	blck_size = (unsigned long)(1 << esb->log_block_size);
	if (blck_size & (unsigned long)(~(512 | 1024 | 2048 | 4096))) {
		VDFS4_ERR("unsupported block size (%lu)\n", blck_size);
		ret = -EINVAL;
		goto err_exit;
	}

	if (blck_size == 512) {
		sbi->log_blocks_in_page = 3;
		sbi->log_block_size = 9;
	} else if (blck_size == 1024) {
		sbi->log_blocks_in_page = 2;
		sbi->log_block_size = 10;
	} else if (blck_size == 2048) {
		sbi->log_blocks_in_page = 1;
		sbi->log_block_size = 11;
	} else {
		sbi->log_blocks_in_page = 0;
		sbi->log_block_size = 12;
	}

	sbi->block_size = blck_size;
	if (!sb_set_blocksize(sb, (int)sbi->block_size))
		VDFS4_ERR("can't set block size\n");
	sbi->block_size_shift = esb->log_block_size;
	sbi->log_sectors_per_block = sbi->block_size_shift - SECTOR_SIZE_SHIFT;

	sbi->offset_msk_inblock = 0xFFFFFFFF >> (32 - sbi->block_size_shift);

	/* Check if superpage oredr is supported and set it */
	if (esb->log_super_page_size < sbi->log_block_size) {
		VDFS4_ERR("unsupported superpage order (%u)\n",
				sbi->log_super_page_size);
		ret = -EINVAL;
		goto err_exit;
	}

	sbi->log_super_page_size = esb->log_super_page_size;
	sbi->log_blocks_in_leb = (unsigned int)(
			esb->log_super_page_size - esb->log_block_size);
	sbi->btree_node_size_blks =
		(unsigned long)(1 << sbi->log_blocks_in_leb);

	if (esb->case_insensitive)
		set_option(sbi, CASE_INSENSITIVE);

err_exit:
	return ret;
}

void destroy_layout(struct vdfs4_sb_info *sbi)
{
	if (test_option(sbi, DESTROY_LAYOUT)) {
		struct page *page;
		char message[] = "THE MAGIC WAS ERASED BY VDFS4_FATAL_ERROR";
		void *buffer;

		page = alloc_page(GFP_NOFS | __GFP_ZERO);
		lock_page(page);
		buffer = kmap(page);
		memcpy(buffer, message, sizeof(message));
		kunmap(page);
		set_page_writeback(page);
		vdfs4_write_page(sbi, page, 0, 1, 0, 1);
		unlock_page(page);
	}
}

void vdfs4_fatal_error(struct vdfs4_sb_info *sbi, const char *fmt, ...)
{
	const char *device = sbi->sb->s_id;
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	pr_emerg("VDFS4(%s): error in %pf, %pV\n", device,
			__builtin_return_address(0), &vaf);
	va_end(args);


#ifdef CONFIG_VDFS4_PANIC_ON_ERROR
	panic("VDFS4(%s): forced kernel panic after fatal error\n", device);
#else
	if (!(sbi->sb->s_flags & MS_RDONLY)) {
		pr_emerg("VDFS4(%s): remount to read-only mode\n", device);
		sbi->sb->s_flags |= MS_RDONLY;
	}
#endif
}

/**
 * @brief			VDFS4 volume sainty check : it is vdfs4 or not
 * @param [in]		sb	VFS superblock info stucture
 * @return			Returns 0 on success, errno on failure
 *
 */
static int vdfs4_volume_check(struct super_block *sb)
{
	int ret = 0;
	struct page *superblocks;
	void *raw_superblocks;
	struct vdfs4_super_block *esb;
	struct vdfs4_sb_info *sbi = sb->s_fs_info;

	superblocks = alloc_page(GFP_NOFS | __GFP_ZERO);
	if (!superblocks)
		return -ENOMEM;

	lock_page(superblocks);
	/* size of the VDFS4 superblock is fixed = 4K or 8 sectors */
	ret = vdfs4_read_page(sb->s_bdev, superblocks, VDFS4_SB_ADDR,
		PAGE_TO_SECTORS(1), 0);
	unlock_page(superblocks);

	if (ret)
		goto error_exit;

	raw_superblocks = kmap(superblocks);
	sbi->raw_superblock = raw_superblocks;

	/* check superblocks */
	esb = (struct vdfs4_super_block *)raw_superblocks;
	ret = vdfs4_verify_sb(esb, "SB", 0, 0, sbi);
	if (ret)
		goto error_exit;

	esb++;
	ret = vdfs4_verify_sb(esb, "SB", 0, 0, sbi);
	if (ret)
		goto error_exit;
	sbi->superblocks = superblocks;
	return 0;
error_exit:
	sbi->superblocks = NULL;
	sbi->raw_superblock = NULL;
	kunmap(superblocks);
	__free_page(superblocks);
	return ret;
}


/**
 * @brief		Reads and checks and recovers eMMCFS super blocks.
 * @param [in]	sb	The VFS super block
 * @param [in]	silent	Do not print errors if silent is true
 * @return		Returns 0 on success, errno on failure
 */
static int vdfs4_sb_read(struct super_block *sb, int silent)
{
	void *raw_superblocks;
	void *raw_superblocks_copy;
	struct vdfs4_super_block *esb;
	struct vdfs4_super_block *esb_copy;
	int ret = 0;
	int check_sb;
	int check_sb_copy;
	int check_signature = 1;
	struct vdfs4_sb_info *sbi = sb->s_fs_info;
	struct page *superblocks, *superblocks_copy;

	superblocks = sbi->superblocks;
	raw_superblocks = sbi->raw_superblock;
	if (!raw_superblocks) {
		ret = -EINVAL;
		goto error_exit;
	}

	/* alloc page for superblock copy*/
	superblocks_copy = alloc_page(GFP_NOFS | __GFP_ZERO);
	if (IS_ERR(superblocks_copy)) {
		VDFS4_ERR("Fail to alloc page for reading superblocks copy");
		ret = -ENOMEM;
		goto error_exit;
	}
	/* read super block and extended super block from volume */
	/*  0    1    2    3      8    9   10   11     15   */
	/*  | SB | SB | SB |ESB   | SB | SB | SB |ESB   |   */
	/*  |    superblocks      |   superblocks_copy  |   */

	lock_page(superblocks_copy);
	ret = vdfs4_read_page(sb->s_bdev, superblocks_copy, VDFS4_SB_COPY_ADDR,
			PAGE_TO_SECTORS(1), 0);
	unlock_page(superblocks_copy);

	if (ret)
		goto err_superblock_copy;

	raw_superblocks_copy = kmap(superblocks_copy);
	if (!raw_superblocks_copy) {
		ret = -ENOMEM;
		goto err_superblock_copy;
	}
#ifdef CONFIG_VDFS4_DATA_AUTHENTICATION
	if (is_sbi_flag_set(sbi, DO_NOT_CHECK_SIGN))
		check_signature = 0;
	else {
		sbi->rsa_key = vdfs4_create_rsa_key(pubkey_n, pubkey_e);
		if (!sbi->rsa_key) {
			VDFS4_ERR("can't create rsa key");
			ret = -EINVAL;
			goto err_superblock_copy_unmap;
		}

	}
#endif
	/* check superblocks */
	esb = (struct vdfs4_super_block *)raw_superblocks + 2;
	esb_copy =  (struct vdfs4_super_block *)raw_superblocks_copy + 2;

	check_sb = vdfs4_verify_sb(esb, "SB", silent, check_signature, sbi);
	check_sb_copy = vdfs4_verify_sb(esb_copy, "SB_COPY", silent,
			check_signature, sbi);

	if (check_sb && check_sb_copy) {
		/*both superblocks are corrupted*/
		ret = check_sb;
		if (!silent || vdfs4_debug_mask & VDFS4_DBG_SB)
			VDFS4_ERR("can't find an VDFS4 filesystem on dev %s",
					sb->s_id);
	} else if ((!check_sb) && check_sb_copy) {
		/*first superblock is ok, copy is corrupted, recovery*/
		memcpy(esb_copy, esb, sizeof(*esb_copy));
		/* write superblock COPY to disk */
		lock_page(superblocks_copy);
		set_page_writeback(superblocks_copy);
		ret = vdfs4_write_page(sbi, superblocks_copy,
				VDFS4_SB_COPY_OFFSET, 2, SB_SIZE * 2, 1);
		unlock_page(superblocks_copy);
	} else if (check_sb && (!check_sb_copy)) {
		/*first superblock is corrupted, recovery*/
		memcpy(esb, esb_copy, sizeof(*esb));
		/* write superblock to disk */
		lock_page(superblocks);
		set_page_writeback(superblocks);
		ret = vdfs4_write_page(sbi, superblocks,
				VDFS4_SB_OFFSET, 2, SB_SIZE * 2, 1);
		unlock_page(superblocks);
	}

	if (ret)
		goto err_superblock_copy_unmap;
	ret = fill_runtime_superblock(esb, sb);

	if (ret)
		goto err_superblock_copy_unmap;

	sbi->raw_superblock_copy = raw_superblocks_copy;
	sbi->superblocks_copy = superblocks_copy;

	sbi->log_erase_block_size = esb->log_erase_block_size;
	sbi->erase_block_size = 1lu << sbi->log_erase_block_size;
	sbi->erase_block_size_in_blocks = sbi->erase_block_size >>
			sbi->block_size_shift;
	sbi->log_erase_block_size_in_blocks = (u8)(sbi->log_erase_block_size -
			sbi->block_size_shift);
	sbi->orig_ro = esb->read_only;
#ifdef CONFIG_VDFS4_DATA_AUTHENTICATION
	if (check_signature)
		set_sbi_flag(sbi, VOLUME_AUTH);
#endif
	if (esb->read_only)
		sb->s_flags |= MS_RDONLY;

	return 0;
err_superblock_copy_unmap:
	kunmap(superblocks_copy);
err_superblock_copy:
	__free_page(superblocks_copy);
error_exit:
	sbi->raw_superblock = NULL;
	kunmap(sbi->superblocks);
	__free_page(sbi->superblocks);
	sbi->superblocks = NULL;
	return ret;
}

/**
 * @brief		Verifies eMMCFS extended super block checksum.
 * @param [in]	exsb	The eMMCFS super block
 * @return		Returns 0 on success, errno on failure
 */
static int vdfs4_verify_exsb(struct vdfs4_extended_super_block *exsb)
{
	__le32 checksum;

	if (!VDFS4_EXSB_VERSION(exsb)) {
		VDFS4_ERR("Bad version of extended super block");
		return -EINVAL;
	}

	/* check crc32 */
	checksum = crc32(0, exsb, sizeof(*exsb) - sizeof(exsb->checksum));

	if (exsb->checksum != checksum) {
		VDFS4_ERR("bad checksum of extended super block - 0x%x, "\
				"must be 0x%x\n", exsb->checksum, checksum);
		return -EINVAL;
	} else
		return 0;
}

/**
 * @brief		Reads and checks eMMCFS extended super block.
 * @param [in]	sb	The VFS super block
 * @return		Returns 0 on success, errno on failure
 */
static int vdfs4_extended_sb_read(struct super_block *sb)
{
	struct vdfs4_sb_info *sbi = sb->s_fs_info;
	struct vdfs4_layout_sb *l_sb = sbi->raw_superblock;
	struct vdfs4_layout_sb *l_sb_copy = sbi->raw_superblock_copy;
	struct vdfs4_extended_super_block *exsb = &l_sb->exsb;
	struct vdfs4_extended_super_block *exsb_copy = &l_sb_copy->exsb;
	int ret = 0;
	int check_exsb;
	int check_exsb_copy;

	check_exsb = vdfs4_verify_exsb(exsb);
	check_exsb_copy = vdfs4_verify_exsb(exsb_copy);

	if (check_exsb && check_exsb_copy) {
		VDFS4_ERR("Extended superblocks are corrupted");
		ret = check_exsb;
		return ret;
	} else if ((!check_exsb) && check_exsb_copy) {
		/* extended superblock copy are corrupted, recovery */
		lock_page(sbi->superblocks);
		memcpy(exsb_copy, exsb, sizeof(*exsb_copy));
		set_page_writeback(sbi->superblocks);
		ret = vdfs4_write_page(sbi, sbi->superblocks,
			VDFS4_EXSB_COPY_OFFSET, VDFS4_EXSB_SIZE_SECTORS,
			(SB_SIZE_IN_SECTOR * 3) * SECTOR_SIZE, 1);
		unlock_page(sbi->superblocks);
	} else if (check_exsb && (!check_exsb_copy)) {
		/* main extended superblock are corrupted, recovery */
		lock_page(sbi->superblocks_copy);
		memcpy(exsb, exsb_copy, sizeof(*exsb));
		set_page_writeback(sbi->superblocks_copy);
		ret = vdfs4_write_page(sbi, sbi->superblocks_copy,
				VDFS4_EXSB_OFFSET, VDFS4_EXSB_SIZE_SECTORS,
				(SB_SIZE_IN_SECTOR * 3) * SECTOR_SIZE, 1);
		unlock_page(sbi->superblocks_copy);
	}

	if (!ret) {
		sbi->files_count = le64_to_cpu(exsb->files_count);
		sbi->folders_count = le64_to_cpu(exsb->folders_count);
	}


	return ret;
}

static int vdfs4_check_resize_volume(struct super_block *sb)
{
	struct vdfs4_sb_info *sbi = sb->s_fs_info;
	struct vdfs4_layout_sb *l_sb = sbi->raw_superblock;
	struct vdfs4_super_block *esb = &l_sb->sb;
	struct vdfs4_extended_super_block *exsb = &l_sb->exsb;

	unsigned long long disk_blocks;

	sbi->volume_blocks_count = le64_to_cpu(exsb->volume_blocks_count);

	disk_blocks = (unsigned long long)
			(sb->s_bdev->bd_inode->i_size >> sb->s_blocksize_bits);

	if (sbi->volume_blocks_count > disk_blocks) {
		pr_err("VDFS4(%s): filesystem bigger than disk:"
				"%llu > %llu blocks\n", sb->s_id,
				sbi->volume_blocks_count,
				disk_blocks);
		return -EFBIG;
	}

	/* Resize filesystem only on first writable mount */
	if (VDFS4_IS_READONLY(sb) || le32_to_cpu(exsb->mount_counter) != 0)
		return 0;

	if (disk_blocks > le64_to_cpu(esb->maximum_blocks_count)) {
		pr_notice("VDFS4(%s): disk bigger than filesystem maximum size:"
				" %lld > %lld blocks, cannot use the rest\n",
				sb->s_id, disk_blocks,
				le64_to_cpu(esb->maximum_blocks_count));
		disk_blocks = le64_to_cpu(esb->maximum_blocks_count);
	}

	if (sbi->volume_blocks_count < disk_blocks) {
		pr_notice("VDFS4(%s): resize volume from %lld to %lld blocks\n",
				sb->s_id, sbi->volume_blocks_count,
				disk_blocks);
		sbi->volume_blocks_count = disk_blocks;
		exsb->volume_blocks_count = cpu_to_le64(disk_blocks);
	}

	return 0;
}

/**
 * @brief		The eMMCFS B-tree common constructor.
 * @param [in]	sbi	The eMMCFS superblock info
 * @param [in]	btree	The eMMCFS B-tree
 * @param [in]	inode	The inode
 * @return		Returns 0 on success, errno on failure
 */
int vdfs4_fill_btree(struct vdfs4_sb_info *sbi,
		struct vdfs4_btree *btree, struct inode *inode)
{
	struct vdfs4_bnode *head_bnode, *bnode;
	struct vdfs4_raw_btree_head *raw_btree_head;
	__u64 bitmap_size;
	int err = 0;
	enum vdfs4_get_bnode_mode mode;
	int loop;

	btree->sbi = sbi;
	btree->inode = inode;
	btree->pages_per_node = 1lu << (sbi->log_blocks_in_leb +
			sbi->block_size_shift - PAGE_SHIFT);
	btree->log_pages_per_node = sbi->log_blocks_in_leb +
			sbi->block_size_shift - PAGE_SHIFT;
	btree->node_size_bytes = btree->pages_per_node << PAGE_SHIFT;

	init_mutex(btree->rw_tree_lock);
	if (VDFS4_IS_READONLY(sbi->sb) ||
		(btree->btree_type >= VDFS4_BTREE_INST_CATALOG))
		mode = VDFS4_BNODE_MODE_RO;
	else
		mode = VDFS4_BNODE_MODE_RW;

	mutex_init(&btree->hash_lock);

	for (loop = 0; loop < VDFS4_BNODE_HASH_SIZE; loop++)
		INIT_HLIST_HEAD(&btree->hash_table[loop]);

	head_bnode =  __vdfs4_get_bnode(btree, 0, mode);
	if (IS_ERR(head_bnode)) {
		err = PTR_ERR(head_bnode);
		goto free_mem;
	}

	raw_btree_head = head_bnode->data;

	/* Check the magic */
	if (memcmp(raw_btree_head->magic, VDFS4_BTREE_HEAD_NODE_MAGIC,
				sizeof(VDFS4_BTREE_HEAD_NODE_MAGIC) - 1)) {
		err = -EINVAL;
		goto err_put_bnode;
	}

	btree->head_bnode = head_bnode;

	/* Fill free bnode bitmpap */
	bitmap_size = btree->node_size_bytes -
		sizeof(struct vdfs4_raw_btree_head) -
		VDFS4_BNODE_FIRST_OFFSET;
	btree->bitmap = vdfs4_build_free_bnode_bitmap(raw_btree_head->bitmap, 0,
			bitmap_size, head_bnode);
	if (IS_ERR(btree->bitmap)) {
		err = PTR_ERR(btree->bitmap);
		btree->bitmap = NULL;
		goto err_put_bnode;
	}

	/* Check if root bnode non-empty */
	bnode = __vdfs4_get_bnode(btree, vdfs4_btree_get_root_id(btree),
			VDFS4_BNODE_MODE_RO);

	if (IS_ERR(bnode)) {
		err = PTR_ERR(bnode);
		goto err_put_bnode;
	}

	if (VDFS4_BNODE_DSCR(bnode)->recs_count == 0) {
		vdfs4_put_bnode(bnode);
		err = -EINVAL;
		goto err_put_bnode;
	}
	vdfs4_put_bnode(bnode);

	mutex_init(&btree->split_buff_lock);
	btree->split_buff = kzalloc(btree->node_size_bytes, GFP_NOFS);
	if (!btree->split_buff)
		goto err_put_bnode;

	return 0;

err_put_bnode:
	vdfs4_put_bnode(head_bnode);
	kfree(btree->bitmap);
free_mem:
	return err;
}

static void tree_remount(struct vdfs4_btree *btree, int flags)
{
	if ((flags & MS_RDONLY) || btree->btree_type >= VDFS4_BTREE_INST_CATALOG)
		btree->head_bnode->mode = VDFS4_BNODE_MODE_RO;
	else
		btree->head_bnode->mode = VDFS4_BNODE_MODE_RW;
}

/**
 * @brief			Catalog tree constructor.
 * @param [in,out]	sbi	The eMMCFS super block info
 * @return			Returns 0 on success, errno on failure
 */
static int vdfs4_fill_cat_tree(struct vdfs4_sb_info *sbi)
{
	struct inode *inode = NULL;
	struct vdfs4_btree *cat_tree;

	int err = 0;

	BUILD_BUG_ON(sizeof(struct vdfs4_btree_gen_record) !=
			sizeof(struct vdfs4_cattree_record));

	cat_tree = kzalloc(sizeof(*cat_tree), GFP_NOFS);
	if (!cat_tree)
		return -ENOMEM;

	cat_tree->btree_type = VDFS4_BTREE_CATALOG;
	cat_tree->max_record_len = ALIGN(sizeof(struct vdfs4_cattree_key), 8) +
			sizeof(struct vdfs4_catalog_file_record);
	inode = vdfs4_special_iget(sbi->sb, VDFS4_CAT_TREE_INO);
	if (IS_ERR(inode)) {
		int ret = PTR_ERR(inode);
		kfree(cat_tree);
		return ret;
	}

	err = vdfs4_fill_btree(sbi, cat_tree, inode);
	if (err)
		goto err_put_inode;

	cat_tree->comp_fn = test_option(sbi, CASE_INSENSITIVE) ?
			vdfs4_cattree_cmpfn_ci : vdfs4_cattree_cmpfn;
	sbi->catalog_tree = cat_tree;

	lockdep_set_class(&sbi->catalog_tree->rw_tree_lock,
			&catalog_tree_lock_key);

	/*sbi->max_cattree_height = count_max_cattree_height(sbi);*/
	return 0;

err_put_inode:
	iput(inode);
	VDFS4_ERR("can not read catalog tree");
	kfree(cat_tree);
	return err;
}

/**
 * @brief			Extents tree constructor.
 * @param [in,out]	sbi	The eMMCFS super block info
 * @return			Returns 0 on success, errno on failure
 */
static int vdfs4_fill_ext_tree(struct vdfs4_sb_info *sbi)
{
	struct inode *inode = NULL;
	struct vdfs4_btree *ext_tree;
	int err = 0;

	BUILD_BUG_ON(sizeof(struct vdfs4_btree_gen_record) !=
			sizeof(struct vdfs4_exttree_record));

	ext_tree = kzalloc(sizeof(*ext_tree), GFP_NOFS);
	if (!ext_tree)
		return -ENOMEM;

	ext_tree->btree_type = VDFS4_BTREE_EXTENTS;
	ext_tree->max_record_len = sizeof(struct vdfs4_exttree_key) +
			sizeof(struct vdfs4_exttree_lrecord);
	inode = vdfs4_special_iget(sbi->sb, VDFS4_EXTENTS_TREE_INO);
	if (IS_ERR(inode)) {
		int ret;
		kfree(ext_tree);
		ret = PTR_ERR(inode);
		return ret;
	}

	err = vdfs4_fill_btree(sbi, ext_tree, inode);
	if (err)
		goto err_put_inode;

	ext_tree->comp_fn = vdfs4_exttree_cmpfn;
	sbi->extents_tree = ext_tree;
	lockdep_set_class(&sbi->extents_tree->rw_tree_lock,
			&extents_tree_lock_key);
	return 0;

err_put_inode:
	iput(inode);
	VDFS4_ERR("can not read extents overflow tree");
	kfree(ext_tree);
	return err;
}


/**
 * @brief			xattr tree constructor.
 * @param [in,out]	sbi	The eMMCFS super block info
 * @return			Returns 0 on success, errno on failure
 */
static int vdsf_fill_xattr_tree(struct vdfs4_sb_info *sbi)

{
	struct inode *inode = NULL;
	struct vdfs4_btree *xattr_tree;
	int err = 0;

	BUILD_BUG_ON(sizeof(struct vdfs4_btree_gen_record) !=
			sizeof(struct vdfs4_xattrtree_record));

	xattr_tree = kzalloc(sizeof(*xattr_tree), GFP_NOFS);
	if (!xattr_tree)
		return -ENOMEM;

	xattr_tree->btree_type = VDFS4_BTREE_XATTRS;
	xattr_tree->max_record_len = VDFS4_XATTR_KEY_MAX_LEN +
				     VDFS4_XATTR_VAL_MAX_LEN;
	inode = vdfs4_special_iget(sbi->sb, VDFS4_XATTR_TREE_INO);
	if (IS_ERR(inode)) {
		int ret;
		kfree(xattr_tree);
		ret = PTR_ERR(inode);
		return ret;
	}

	err = vdfs4_fill_btree(sbi, xattr_tree, inode);
	if (err)
		goto err_put_inode;

	xattr_tree->comp_fn = vdfs4_xattrtree_cmpfn;
	sbi->xattr_tree = xattr_tree;
	lockdep_set_class(&sbi->xattr_tree->rw_tree_lock, &xattr_tree_lock_key);
	return 0;

err_put_inode:
	iput(inode);
	VDFS4_ERR("can not read extents overflow tree");
	kfree(xattr_tree);
	return err;
}

/**
 * @brief			Free inode bitmap constructor.
 * @param [in,out]	sbi	The eMMCFS super block info
 * @return			Returns 0 on success, errno on failure
 */
static int build_free_inode_bitmap(struct vdfs4_sb_info *sbi)
{
	int ret = 0;
	struct inode *inode;

	inode = vdfs4_special_iget(sbi->sb, VDFS4_FREE_INODE_BITMAP_INO);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		return ret;
	}

	atomic64_set(&sbi->free_inode_bitmap.last_used, VDFS4_1ST_FILE_INO);
	sbi->free_inode_bitmap.inode = inode;
	return ret;
}

int vdfs4_remount_fs(struct super_block *sb, int *flags, char *data)
{
	int ret = 0;
	struct vdfs4_sb_info *sbi = VDFS4_SB(sb);
	struct vdfs4_layout_sb *l_sb = sbi->raw_superblock;
	struct vdfs4_extended_super_block *exsb = &l_sb->exsb;

	if ((sb->s_flags & MS_RDONLY) == (*flags & MS_RDONLY))
		return 0;

	if (!(*flags & MS_RDONLY)) {
		if ((sb->s_flags & MS_RDONLY) && sbi->orig_ro) {
			return -EROFS;
		} else {

			/*ret = vdfs4_load_debug_area(sb);
			if (ret)
				return ret;*/

			ret = vdfs4_fsm_build_management(sb);
			if (ret)
				goto vdfs4_fsm_create_error;

			ret = build_free_inode_bitmap(sbi);
			if (ret)
				goto build_free_inode_bitmap_error;

			tree_remount(sbi->catalog_tree, 0);
			tree_remount(sbi->extents_tree, 0);
			tree_remount(sbi->xattr_tree, 0);

			ret = vdfs4_process_orphan_inodes(sbi);
			if (ret)
				goto process_orphan_inodes_error;

			le32_add_cpu(&(exsb->mount_counter), 1);
			le32_add_cpu(&(exsb->generation), 1);
			set_sbi_flag(sbi, EXSB_DIRTY);
		}
	} else {
process_orphan_inodes_error:
		tree_remount(sbi->catalog_tree, MS_RDONLY);
		tree_remount(sbi->extents_tree, MS_RDONLY);
		tree_remount(sbi->xattr_tree, MS_RDONLY);

		destroy_free_inode_bitmap(sbi);
build_free_inode_bitmap_error:
		vdfs4_fsm_destroy_management(sb);
	}
vdfs4_fsm_create_error:

	return ret;
}
static struct inode *vdfs4_nfs_get_inode(struct super_block *sb,
					u64 ino, u32 generation)
{
	struct inode *inode;

	if (ino <  VDFS4_1ST_FILE_INO && ino != VDFS4_ROOT_INO)
		return ERR_PTR(-ESTALE);

	inode = vdfs4_iget(VDFS4_SB(sb), (ino_t)ino);
	if (IS_ERR(inode))
		return ERR_CAST(inode);
	if (generation && inode->i_generation != generation) {
		iput(inode);
		return ERR_PTR(-ESTALE);
	}

	return inode;
}

static struct dentry *vdfs4_get_parent(struct dentry *child)
{
	u64 ino = VDFS4_I(child->d_inode)->parent_id;
	struct vdfs4_sb_info *sbi = VDFS4_SB(child->d_inode->i_sb);

	return d_obtain_alias(vdfs4_iget(sbi, (ino_t)ino));
}

static struct dentry *vdfs4_fh_to_dentry(struct super_block *sb, struct fid *fid,
					int fh_len, int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				vdfs4_nfs_get_inode);
}

static struct dentry *vdfs4_fh_to_parent(struct super_block *sb, struct fid *fid,
					int fh_len, int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				vdfs4_nfs_get_inode);
}

static const struct export_operations vdfs4_export_ops = {
	.fh_to_dentry = vdfs4_fh_to_dentry,
	.fh_to_parent = vdfs4_fh_to_parent,
	.get_parent = vdfs4_get_parent,
};
/**
 * @brief			Dirty extended super page.
 * @param [in,out]	sb	The VFS superblock
 */
void vdfs4_dirty_super(struct vdfs4_sb_info *sbi)
{
	if (!(VDFS4_IS_READONLY(sbi->sb)))
		set_sbi_flag(sbi, EXSB_DIRTY);

}


/*Sys*/

static ssize_t vdfs4_info(struct vdfs4_sb_info *sbi, char *buf)
{
	ssize_t ret = 0;
	u64 meta_size = calc_special_files_size(sbi) <<
			(sbi->block_size_shift - 10);
	u64 data_size = (sbi->volume_blocks_count - sbi->free_blocks_count -
			calc_special_files_size(sbi))
			<< (sbi->block_size_shift - 10);

	ret = snprintf(buf, PAGE_SIZE, "Meta: %lluKB\tData: %lluKB\n",
			meta_size, data_size);

	return ret;
}


static ssize_t vdfs4_attr_show(struct kobject *kobj,
			      struct attribute *attr, char *buf)
{
	struct vdfs4_sb_info *sbi = container_of(kobj, struct vdfs4_sb_info,
			s_kobj);
	struct vdfs4_attr *a = container_of(attr, struct vdfs4_attr, attr);
	return a->show ? a->show(sbi, buf) : 0;
}

static ssize_t vdfs4_attr_store(struct kobject *kobj,
			       struct attribute *attr,
			       const char *buf, size_t len)
{
	struct vdfs4_sb_info *sbi = container_of(kobj, struct vdfs4_sb_info,
						s_kobj);
	struct vdfs4_attr *a = container_of(attr, struct vdfs4_attr, attr);
	return a->store ? a->store(sbi, buf, len) : 0;
}

static const struct sysfs_ops vdfs4_attr_ops = {
	.show  = vdfs4_attr_show,
	.store = vdfs4_attr_store,
};
#define VDFS4_ATTR(name, mode, show, store) \
static struct vdfs4_attr vdfs4_attr_##name = __ATTR(name, mode, show, store)

VDFS4_ATTR(info, 0444, vdfs4_info, NULL);

static struct attribute *vdfs4_attrs[] = {
	&vdfs4_attr_info.attr,
	NULL,
};
static void vdfs4_sb_release(struct kobject *kobj)
{
	struct vdfs4_sb_info *sbi = container_of(kobj, struct vdfs4_sb_info,
						s_kobj);
	complete(&sbi->s_kobj_unregister);
}
static struct kobj_type vdfs4_ktype = {
	.release = vdfs4_sb_release,
	.default_attrs = vdfs4_attrs,
	.sysfs_ops     = &vdfs4_attr_ops,
};

/*End Sys*/

/**
 * @brief			Initialize the eMMCFS filesystem.
 * @param [in,out]	sb	The VFS superblock
 * @param [in,out]	data	FS private information
 * @param [in]		silent	Flag whether to print error message
 * @remark			Reads super block and FS internal data
 *				structures for futher use.
 * @return			Return 0 on success, errno on failure
 */
static int vdfs4_fill_super(struct super_block *sb, void *data, int silent)
{
	int ret	= 0;
	struct vdfs4_sb_info *sbi;
	struct inode *root_inode;
	char bdev_name[BDEVNAME_SIZE];
	struct vdfs4_layout_sb *l_sb = NULL;
	struct vdfs4_extended_super_block *exsb = NULL;
#ifdef CONFIG_VDFS4_PRINT_MOUNT_TIME
	unsigned long mount_start = jiffies;
#endif

#if defined(VDFS4_GIT_BRANCH) && defined(VDFS4_GIT_REV_HASH) && \
		defined(VDFS4_VERSION)
	pr_err("%.5s\n", VDFS4_VERSION);
	VDFS4_MOUNT_INFO("version is \"%s\"\n", VDFS4_VERSION);
	VDFS4_MOUNT_INFO("git branch is \"%s\"\n", VDFS4_GIT_BRANCH);
	VDFS4_MOUNT_INFO("git revhash \"%.40s\"\n", VDFS4_GIT_REV_HASH);
#endif
#ifdef CONFIG_VDFS4_NOOPTIMIZE
	pr_warn("[VDFS4] Build optimization is switched off\n");
#endif

	if (!sb)
		return -ENXIO;
	if (!sb->s_bdev)
		return -ENXIO;
	if (!sb->s_bdev->bd_part)
		return -ENXIO;

	VDFS4_MOUNT_INFO("mounting %s\n", bdevname(sb->s_bdev, bdev_name));
	sbi = kzalloc(sizeof(*sbi), GFP_NOFS);
	if (!sbi)
		return -ENOMEM;

	sb->s_fs_info = sbi;
	sbi->sb = sb;
#ifdef CONFIG_VDFS4_USE_HW2_DECOMPRESS
	/* Check support of hw decompression by block device */
	if (sb->s_bdev->bd_disk) {
		const struct block_device_operations *ops;
		ops = sb->s_bdev->bd_disk->fops;
		if (ops->hw_decompress_vec) {
			sbi->use_hw_decompressor = 1;
			VDFS4_MOUNT_INFO("hw decompression enabled\n");
		}
	}
#endif
	INIT_LIST_HEAD(&sbi->packtree_images.list);
	mutex_init(&sbi->packtree_images.lock_pactree_list);
#ifdef CONFIG_VDFS4_DEBUG
	mutex_init(&sbi->dump_meta);
#endif
	sb->s_maxbytes = VDFS4_MAX_FILE_SIZE_IN_BYTES;
	INIT_DELAYED_WORK(&sbi->delayed_commit, vdfs4_delayed_commit);
	atomic_set(&sbi->meta_bio_count, 0);
	init_waitqueue_head(&sbi->meta_bio_wait);

	ret = vdfs4_parse_options(sb, data);
	if (ret) {
		VDFS4_ERR("unable to parse mount options\n");
		ret = -EINVAL;
		goto vdfs4_parse_options_error;
	}

	ret = vdfs4_volume_check(sb);
	if (ret)
		goto not_vdfs4_volume;

	ret = vdfs4_sb_read(sb, silent);
	if (ret)
		goto vdfs4_sb_read_error;

	ret = vdfs4_extended_sb_read(sb);
	if (ret)
		goto vdfs4_extended_sb_read_error;

	ret = vdfs4_check_resize_volume(sb);
	if (ret)
		goto vdfs4_extended_sb_read_error;

/*	if (!(VDFS4_IS_READONLY(sb))) {
		ret = vdfs4_load_debug_area(sb);
		if (ret)
			goto vdfs4_extended_sb_read_error;
	}*/
	l_sb = sbi->raw_superblock;
	exsb = &l_sb->exsb;

#ifdef CONFIG_VDFS4_CRC_CHECK
	if (exsb->crc == CRC_ENABLED)
		set_sbi_flag(sbi, VDFS4_META_CRC);
	else {
		VDFS4_MOUNT_INFO("Driver supports only signed volumes\n");
		ret  = -1;
		goto vdfs4_extended_sb_read_error;
	}
#else
	/* if the image is signed reset the signed flag */
	if (exsb->crc == CRC_ENABLED)
		exsb->crc = CRC_DISABLED;
#endif
	VDFS4_MOUNT_INFO("mounted %d times\n", exsb->mount_counter);

	/*vdfs4_debug_print_sb(sbi)*/;

	sb->s_op = &vdfs4_sops;
	sb->s_export_op = &vdfs4_export_ops;

	#ifdef CONFIG_VDFS4_POSIX_ACL
	sb->s_flags |= MS_POSIXACL;
#endif
	/* s_magic is 4 bytes on 32-bit; system */
	memcpy(&sb->s_magic, VDFS4_SB_SIGNATURE, sizeof(VDFS4_SB_SIGNATURE) - 1);

	sbi->max_cattree_height = 5;
	ret = vdfs4_build_snapshot_manager(sbi);
	if (ret)
		goto vdfs4_build_snapshot_manager_error;

	if (!(VDFS4_IS_READONLY(sb))) {
		ret = vdfs4_fsm_build_management(sb);
		if (ret)
			goto vdfs4_fsm_create_error;
	}

	ret = vdfs4_fill_ext_tree(sbi);
	if (ret)
		goto vdfs4_fill_ext_tree_error;

	ret = vdfs4_fill_cat_tree(sbi);
	if (ret)
		goto vdfs4_fill_cat_tree_error;

	ret = vdsf_fill_xattr_tree(sbi);
	if (ret)
		goto vdfs4_fill_xattr_tree_error;

	if (!(VDFS4_IS_READONLY(sb))) {
		ret = build_free_inode_bitmap(sbi);
		if (ret)
			goto build_free_inode_bitmap_error;
	}

	/* allocate root directory */
	root_inode = vdfs4_get_root_inode(sbi->catalog_tree);
	if (IS_ERR(root_inode)) {
		VDFS4_ERR("failed to load root directory\n");
		ret = PTR_ERR(root_inode);
		goto vdfs4_iget_err;
	}

	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root) {
		VDFS4_ERR("unable to get root inode\n");
		ret = -EINVAL;
		goto d_alloc_root_err;
	}

	/*
	 * Root inode always in orphan_list. It stores entry point.
	 */
	list_add(&sbi->orphan_inodes, &VDFS4_I(root_inode)->orphan_list);

	if (DATE_RESOLUTION_IN_NANOSECONDS_ENABLED)
		sb->s_time_gran = 1;
	else
		printk(KERN_WARNING
			"Date resolution in nanoseconds is disabled\n");

#ifdef CONFIG_VDFS4_CHECK_FRAGMENTATION
	for (count = 0; count < VDFS4_EXTENTS_COUNT_IN_FORK; count++)
		sbi->in_fork[count] = 0;
	sbi->in_extents_overflow = 0;
#endif

	if (!(VDFS4_IS_READONLY(sb))) {
		if (!(exsb->mount_counter))
			generate_random_uuid(exsb->volume_uuid);
		/* If somebody will switch power off right after mounting,
		 * mount count will not inclreased
		 * But this operation takes a lot of time, and dramatically
		 * increase mount time */
		le32_add_cpu(&exsb->mount_counter, 1);
		le32_add_cpu(&exsb->generation, 1);
		vdfs4_dirty_super(sbi);

		ret = vdfs4_process_orphan_inodes(sbi);
		if (ret) {
			destroy_layout(sbi);
			goto process_orphan_inodes_error;
		}
	}

	/* print uuid if the volue already has it */
	if (le32_to_cpu(exsb->mount_counter) != 1)
		VDFS4_MOUNT_INFO("volume uuid: %pU\n",
				exsb->volume_uuid);


#ifdef CONFIG_VDFS4_PRINT_MOUNT_TIME
	{
		unsigned long result = jiffies - mount_start;
		printk(KERN_ERR "Mount time %lu ms\n", result * 1000 / HZ);
	}
#endif

	vdfs4_init_high_priority(&sbi->high_priority);

	sbi->s_kobj.kset = vdfs4_kset;
	init_completion(&sbi->s_kobj_unregister);
	ret = kobject_init_and_add(&sbi->s_kobj, &vdfs4_ktype, NULL,
				   "%s", sb->s_id);
	if (ret)
		goto process_orphan_inodes_error;


#ifdef CONFIG_VDFS4_DEBUG
	INIT_DELAYED_WORK(&sbi->delayed_check_debug_area,
			  vdfs4_delayed_save_debug_area);
	if (!(VDFS4_IS_READONLY(sb)))
		mod_delayed_work(system_wq, &sbi->delayed_check_debug_area, HZ);
#endif
	set_sbi_flag(sbi, IS_MOUNT_FINISHED);
	VDFS4_DEBUG_SB("finished ok");
	return 0;

	kobject_del(&sbi->s_kobj);
process_orphan_inodes_error:
	dput(sb->s_root);
	sb->s_root = NULL;
	root_inode = NULL;
d_alloc_root_err:
	iput(root_inode);

vdfs4_iget_err:
	destroy_free_inode_bitmap(sbi);

build_free_inode_bitmap_error:
	vdfs4_put_btree(sbi->xattr_tree, 1);
	sbi->xattr_tree = NULL;

vdfs4_fill_xattr_tree_error:
	vdfs4_put_btree(sbi->catalog_tree, 1);
	sbi->catalog_tree = NULL;

vdfs4_fill_cat_tree_error:
	vdfs4_put_btree(sbi->extents_tree, 1);
	sbi->extents_tree = NULL;

vdfs4_fill_ext_tree_error:
	if (!(VDFS4_IS_READONLY(sb)))
		vdfs4_fsm_destroy_management(sb);

vdfs4_fsm_create_error:
	vdfs4_destroy_snapshot_manager(sbi);

vdfs4_build_snapshot_manager_error:
/*	if (!(VDFS4_IS_READONLY(sb)))
		vdfs4_free_debug_area(sb);*/

vdfs4_extended_sb_read_error:
vdfs4_sb_read_error:
vdfs4_parse_options_error:
not_vdfs4_volume:
#ifdef CONFIG_VDFS4_DATA_AUTHENTICATION
	if (sbi->rsa_key)
		vdfs4_destroy_rsa_key(sbi->rsa_key);
#endif
	destroy_super(sbi);

	sb->s_fs_info = NULL;
	kfree(sbi);
	VDFS4_DEBUG_SB("finished with error = %d", ret);

	return ret;
}


/**
 * @brief				Method to get the eMMCFS super block.
 * @param [in,out]	fs_type		Describes the eMMCFS file system
 * @param [in]		flags		Input flags
 * @param [in]		dev_name	Block device name
 * @param [in,out]	data		Private information
 * @param [in,out]	mnt		Mounted eMMCFS filesystem information
 * @return				Returns 0 on success, errno on failure
 */
static struct dentry *vdfs4_mount(struct file_system_type *fs_type, int flags,
				const char *device_name, void *data)
{
	return mount_bdev(fs_type, flags, device_name, data, vdfs4_fill_super);
}

static void vdfs4_kill_block_super(struct super_block *sb)
{
	kill_block_super(sb);
}

/*
 * Structure of the eMMCFS filesystem type
 */
static struct file_system_type vdfs4_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "vdfs4",
	.mount		= vdfs4_mount,
	.kill_sb	= vdfs4_kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};

/**
 * @brief				Inode storage initializer.
 * @param [in,out]	generic_inode	Inode for init
 * @return		void
 */
static void vdfs4_init_inode_once(void *generic_inode)
{
	struct vdfs4_inode_info *inode = generic_inode;

	mutex_init(&inode->truncate_mutex);
	inode_init_once(&inode->vfs_inode);
	INIT_LIST_HEAD(&inode->runtime_extents);
}

#ifdef CONFIG_VDFS4_USE_HW1_DECOMPRESS
#define HW_BUF_COUNT 2
#define HW_PAGES_SHIFT  5
#define HW_PAGES_PER_CHUNK (1 << HW_PAGES_SHIFT)

static struct page *hw_buf_pages1[HW_PAGES_PER_CHUNK];
static struct page *hw_buf_pages2[HW_PAGES_PER_CHUNK];
static unsigned long hw_buf_addr1;
static unsigned long hw_buf_addr2;

static spinlock_t hw_buffers_lock;

static void init_hw_buffer(struct page **pages, struct inode *inode,
		pgoff_t start_index, int pages_count)
{
	int count;
	sector_t page_idx;
	for (count = 0; count < pages_count; count++) {
		lock_page(pages[count]);
		ClearPageUptodate(pages[count]);

		vdfs4_get_block_file_based(inode, start_index + (pgoff_t)count,
						&page_idx);
		pages[count]->index = (pgoff_t)page_idx;
		pages[count]->mapping =
			inode->i_sb->s_bdev->bd_inode->i_mapping;
	}
}

struct page **vdfs4_get_hw_buffer(struct inode *inode, pgoff_t start_index,
		void **buffer, int pages_count)
{
	struct page **pages = NULL;

	spin_lock(&hw_buffers_lock);
	if (hw_buf_pages1[0] != NULL && hw_buf_pages1[0]->mapping == 0) {
		pages = hw_buf_pages1;
		*buffer = (void *)hw_buf_addr1;
		hw_buf_pages1[0]->mapping = (void *)1;
		goto exit;
	}

	if (hw_buf_pages2[0] != NULL && hw_buf_pages2[0]->mapping == 0) {
		pages = hw_buf_pages2;
		*buffer = (void *)hw_buf_addr2;
		hw_buf_pages2[0]->mapping = (void *)1;
	}
exit:

	spin_unlock(&hw_buffers_lock);
	if (pages)
		init_hw_buffer(pages, inode, start_index, pages_count);
	return pages;
}

void vdfs4_put_hw_buffer(struct page **pages)
{
	spin_lock(&hw_buffers_lock);
	pages[0]->mapping = NULL;
	spin_unlock(&hw_buffers_lock);
}


static int allocate_hw_input_buffers(void)
{
	unsigned long count;
	spin_lock_init(&hw_buffers_lock);

	hw_buf_addr1 = __get_free_pages(GFP_NOFS, HW_PAGES_SHIFT);
	if (!hw_buf_addr1) {
		VDFS4_ERR("Cannot allocate first input buffer for HW1");
		hw_buf_pages1[0] = NULL;
		hw_buf_pages2[0] = NULL;
		return 0;
	}

	for (count = 0; count < HW_PAGES_PER_CHUNK; count++) {
		hw_buf_pages1[count] = virt_to_page(hw_buf_addr1 +
				PAGE_SIZE * count);
		hw_buf_pages1[count]->mapping = NULL;
	}

	hw_buf_addr2 = __get_free_pages(GFP_NOFS, HW_PAGES_SHIFT);
	if (!hw_buf_addr2) {
		VDFS4_ERR("Cannot allocate second input buffer for HW1");
		hw_buf_pages2[0] = NULL;
		return 0;
	}

	for (count = 0; count < HW_PAGES_PER_CHUNK; count++) {
		hw_buf_pages2[count] = virt_to_page(hw_buf_addr2 +
				PAGE_SIZE * count);
		hw_buf_pages2[count]->mapping = NULL;
	}

	return 0;
}

static void destroy_hw_input_buffers(void)
{
	free_pages((long unsigned)hw_buf_addr1, HW_PAGES_SHIFT);
	free_pages((long unsigned)hw_buf_addr2, HW_PAGES_SHIFT);
}
#endif

#ifdef CONFIG_VDFS4_PRINT_DIRTY_FILES
#include <linux/syscore_ops.h>
struct syscore_ops vdfs4_sys_ops = {
	.shutdown = print_dirty_file,
};
#endif
/**
 * @brief	Initialization of the eMMCFS module.
 * @return	Returns 0 on success, errno on failure
 */
static int __init init_vdfs4_fs(void)
{
	int ret;

	vdfs4_check_layout();

#ifdef CONFIG_VDFS4_PRINT_DIRTY_FILES
	register_syscore_ops(&vdfs4_sys_ops);
#endif

	vdfs4_inode_cachep = kmem_cache_create("vdfs4_icache",
				sizeof(struct vdfs4_inode_info), 0,
				SLAB_HWCACHE_ALIGN, vdfs4_init_inode_once);
	if (!vdfs4_inode_cachep) {
		VDFS4_ERR("failed to initialise inode cache\n");
		return -ENOMEM;
	}

	ret = vdfs4_init_btree_caches();
	if (ret)
		goto fail_create_btree_cache;

	ret = vdfs4_exttree_cache_init();
	if (ret)
		goto fail_create_exttree_cache;

	ret = vdfs4_fsm_cache_init();

	if (ret)
		goto fail_create_fsm_cache;

	vdfs4_kset = kset_create_and_add("vdfs4", NULL, fs_kobj);
	if (!vdfs4_kset) {
		ret = -ENOMEM;
		goto fail_create_kset;
	}

	ret = register_filesystem(&vdfs4_fs_type);
	if (ret)
		goto failed_register_fs;


#ifdef CONFIG_VDFS4_USE_HW1_DECOMPRESS
	ret = allocate_hw_input_buffers();
	if (ret)
		goto failed_register_fs;
#endif
	return 0;

failed_register_fs:
	kset_unregister(vdfs4_kset);
fail_create_kset:
	vdfs4_fsm_cache_destroy();
fail_create_fsm_cache:
	vdfs4_exttree_cache_destroy();
fail_create_exttree_cache:
	vdfs4_destroy_btree_caches();
fail_create_btree_cache:

	return ret;
}

/**
 * @brief		Module unload callback.
 * @return	void
 */
static void __exit exit_vdfs4_fs(void)
{
	vdfs4_fsm_cache_destroy();
	unregister_filesystem(&vdfs4_fs_type);
	kmem_cache_destroy(vdfs4_inode_cachep);
	vdfs4_exttree_cache_destroy();
	vdfs4_destroy_btree_caches();
	kset_unregister(vdfs4_kset);
#ifdef CONFIG_VDFS4_USE_HW1_DECOMPRESS
	destroy_hw_input_buffers();
#endif
}

module_init(init_vdfs4_fs)
module_exit(exit_vdfs4_fs)

module_param(vdfs4_debug_mask, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(vdfs4_debug_mask, "Debug mask (1 - print debug for superblock ops,"\
				" 2 - print debug for inode ops)");
MODULE_AUTHOR("Samsung R&D Russia - System Software Lab - VD Software Group");
MODULE_VERSION(__stringify(VDFS4_VERSION));
MODULE_DESCRIPTION("Vertically Deliberate improved performance File System");
MODULE_LICENSE("GPL");
