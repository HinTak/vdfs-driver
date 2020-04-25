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
#include <linux/writeback.h>
#include <linux/nls.h>
#include <linux/mpage.h>
#include <linux/version.h>
#include <linux/migrate.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/bio.h>
#include <linux/uaccess.h>
#include <linux/blkdev.h>
#include <linux/swap.h>
#include <linux/vmalloc.h>
#include <linux/security.h>
#include <linux/file.h>
#include <linux/crypto.h>
#include <linux/uio.h>
#include <linux/falloc.h>
#include <linux/posix_acl_xattr.h>

#ifdef CONFIG_VDFS4_HW_DECOMPRESS_SUPPORT
#include <crypto/crypto_wrapper.h>
#include <mach/hw_decompress.h>
#endif

#include "vdfs4.h"
#include "cattree.h"
#include "debug.h"
#include <trace/events/vdfs4.h>
#include <linux/vdfs_trace.h>	/* FlashFS : vdfs-trace */
#include "lock_trace.h"

static const uint16_t supported_compressed_layouts[] = {
	/* current layout */
	VDFS4_COMPR_LAYOUT_VER_06,
	/* with RSA1024 hardcoded */
	VDFS4_COMPR_LAYOUT_VER_05,
};

#define VDFS4_NUM_OF_SUPPORTED_COMPR_LAYOUTS \
	ARRAY_SIZE(supported_compressed_layouts)

/**
 * @brief		Create inode.
 * @param [out]	dir		The inode to be created
 * @param [in]	dentry	Struct dentry with information
 * @param [in]	mode	Mode of creation
 * @param [in]	nd		Struct with name data
 * @return		Returns 0 on success, errno on failure
 */
static int vdfs4_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool excl);

static int vdfs4_get_block_prep_da(struct inode *inode, sector_t iblock,
		struct buffer_head *bh_result, int create);


/**
 * @brief		Allocate new inode.
 * @param [in]	dir		Parent directory
 * @param [in]	mode	Mode of operation
 * @return		Returns pointer to newly created inode on success,
 *			errno on failure
 */
static struct inode *vdfs4_new_inode(struct inode *dir, umode_t mode);

/**
 * @brief		Get root folder.
 * @param [in]	tree	Pointer to btree information
 * @param [out] fd	Buffer for finded data
 * @return		Returns 0 on success, errno on failure
 */
struct inode *vdfs4_get_root_inode(struct vdfs4_btree *tree)
{
	struct inode *root_inode = NULL;
	struct vdfs4_cattree_record *record = NULL;

	record = vdfs4_cattree_find_inode(tree,
			VDFS4_ROOT_INO, VDFS4_ROOTDIR_OBJ_ID,
			VDFS4_ROOTDIR_NAME, strlen(VDFS4_ROOTDIR_NAME),
			VDFS4_BNODE_MODE_RO);

	if (IS_ERR(record)) {
		/* Pass error code to return value */
		root_inode = (void *)record;
		goto exit;
	}

	root_inode = vdfs4_get_inode_from_record(record, NULL);
	vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
exit:
	return root_inode;
}


static void vdfs4_fill_cattree_record(struct inode *inode,
		struct vdfs4_cattree_record *record)
{
	void *pvalue = record->val;

	VDFS4_BUG_ON(!pvalue || IS_ERR(pvalue), VDFS4_SB(inode->i_sb));

	VDFS4_I(inode)->record_type = record->key->record_type;

	if (VDFS4_GET_CATTREE_RECORD_TYPE(record) == VDFS4_CATALOG_HLINK_RECORD)
		vdfs4_fill_hlink_value(inode, pvalue);
	else
		vdfs4_fill_cattree_value(inode, pvalue);
}

/**
 * @brief		Method to iterate directory.
 * @param [in]	filp	File pointer
 * @param [in]	ctx		Dir context
 */
static int vdfs4_iterate(struct file *filp, struct dir_context *ctx)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct vdfs4_sb_info *sbi = inode->i_sb->s_fs_info;
	__u64 catalog_id = inode->i_ino;
	int ret = 0;
	struct vdfs4_cattree_record *record;
	struct vdfs4_btree *btree = NULL;
	loff_t pos = 2;

	VT_PREPARE_PARAM(vt_data);

	if (!dir_emit_dots(filp, ctx))
		return 0;

	vdfs4_cattree_r_lock(sbi);
	btree = sbi->catalog_tree;

	if (IS_ERR(btree)) {
		vdfs4_cattree_r_unlock(sbi);
		return PTR_ERR(btree);
	}

	VT_FOPS_START(vt_data, vdfs_trace_fops_dir_iterate,
		      inode->i_sb->s_bdev->bd_part, inode, filp);
	if (!filp->private_data) {
		record = vdfs4_cattree_get_first_child(btree, catalog_id);
	} else {
		char *name = filp->private_data;

		record = vdfs4_cattree_find(btree, catalog_id,
				name, strlen(name), VDFS4_BNODE_MODE_RO);
	}

	if (IS_ERR(record)) {
		ret = (PTR_ERR(record) == -EISDIR) ? 0 : PTR_ERR(record);
		goto exit;
	}

	while (1) {
		struct vdfs4_catalog_folder_record *cattree_val;
		umode_t object_mode;
		u8 record_type;
		__u64 obj_id;

		if (record->key->parent_id != cpu_to_le64(catalog_id))
			goto exit;

		if ((record->key->record_type == VDFS4_CATALOG_ILINK_RECORD) ||
				vdfs4_cattree_is_orphan(record))
			goto get_next_record;

		if (!filp->private_data && pos < ctx->pos)
			goto next;

		cattree_val = record->val;
		record_type = record->key->record_type;
		obj_id = le64_to_cpu(record->key->object_id);
		if (record_type == VDFS4_CATALOG_HLINK_RECORD) {
			object_mode = le16_to_cpu((
					(struct vdfs4_catalog_hlink_record *)
					cattree_val)->file_mode);
		} else {
			object_mode = le16_to_cpu(cattree_val->file_mode);
		}

		if (btree->btree_type == VDFS4_BTREE_INST_CATALOG)
			obj_id += btree->start_ino;

		if (!dir_emit(ctx, record->key->name, record->key->name_len,
				obj_id, IFTODT(object_mode))) {
			char *private_data;

			if (!filp->private_data) {
				private_data = kmalloc(VDFS4_FILE_NAME_LEN + 1,
						GFP_NOFS);
				filp->private_data = private_data;
				if (!private_data) {
					ret = -ENOMEM;
					goto exit;
				}
			} else {
				private_data = filp->private_data;
			}

			memcpy(private_data, record->key->name,
					record->key->name_len);
			private_data[record->key->name_len] = 0;

			ret = 0;
			goto exit;
		}

		++ctx->pos;
next:
		++pos;
get_next_record:
		ret = vdfs4_cattree_get_next_record(record);
		if ((ret == -ENOENT) ||
			record->key->parent_id != cpu_to_le64(catalog_id)) {
			/* No more entries */
			kfree(filp->private_data);
			filp->private_data = NULL;
			ret = 0;
			goto exit;
		} else if (ret) {
			goto exit;
		}
	}

exit:
	if (!IS_ERR_OR_NULL(record))
		vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
	vdfs4_cattree_r_unlock(sbi);
	VT_FINISH(vt_data);
	return ret;
}

static int vdfs4_release_dir(struct inode *inode, struct file *filp)
{
	kfree(filp->private_data);
	filp->private_data = NULL;
	return 0;
}

static loff_t vdfs4_llseek_dir(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;

	mutex_lock(&inode->i_mutex);
	vdfs4_release_dir(inode, file);
	mutex_unlock(&inode->i_mutex);

	return generic_file_llseek(file, offset, whence);
}

static int vdfs4_dir_fsync(struct file *file, loff_t start,
						loff_t end, int datasync)
{
	struct super_block *sb = file->f_path.dentry->d_sb;
	int ret = 0;

	VT_PREPARE_PARAM(vt_data);

	if (!datasync) {
		VT_FOPS_START(vt_data, vdfs_trace_fops_dir_fsync,
			      sb->s_bdev->bd_part,file->f_path.dentry->d_inode,
			      file);
		down_read(&sb->s_umount);
		ret = sync_filesystem(sb);
		up_read(&sb->s_umount);
		VT_FINISH(vt_data);
	}

	return ret;
}

/**
 * @brief		Method to look up an entry in a directory.
 * @param [in]	dir		Parent directory
 * @param [in]	dentry	Searching entry
 * @param [in]	nd		Associated nameidata
 * @return		Returns pointer to found dentry, NULL if it is
 *			not found, ERR_PTR(errno) on failure
 */
struct dentry *vdfs4_lookup(struct inode *dir, struct dentry *dentry,
						unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct vdfs4_sb_info *sbi = sb->s_fs_info;
	struct vdfs4_cattree_record *record;
	struct inode *inode;
	struct vdfs4_btree *tree = sbi->catalog_tree;
	struct dentry *ret = NULL;
	__u64 catalog_id = dir->i_ino;

	VT_PREPARE_PARAM(vt_data);

	if (dentry->d_name.len > VDFS4_FILE_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

again:
	vdfs4_cattree_r_lock(sbi);
	tree = sbi->catalog_tree;

	if (IS_ERR(tree)) {
		vdfs4_cattree_r_unlock(sbi);
		return (struct dentry *)tree;
	}

	VT_IOPS_START(vt_data, vdfs_trace_iops_lookup, dentry);
	record = vdfs4_cattree_find(tree, catalog_id,
			dentry->d_name.name, dentry->d_name.len,
			VDFS4_BNODE_MODE_RO);

	if (!IS_ERR(record) && ((record->key->record_type ==
			VDFS4_CATALOG_ILINK_RECORD))) {
		struct vdfs4_cattree_key *key;

		key = kzalloc(sizeof(*key), GFP_KERNEL);
		if (!key) {
			vdfs4_release_record((struct vdfs4_btree_gen_record *)
					record);

			inode = ERR_PTR(-ENOMEM);
			goto exit;
		}
		key->parent_id = cpu_to_le64(catalog_id);
		key->object_id = cpu_to_le64(record->key->object_id - 1);
		key->name_len = (u8)dentry->d_name.len;
		memcpy(key->name, dentry->d_name.name,
				(size_t)dentry->d_name.len);
		vdfs4_release_record((struct vdfs4_btree_gen_record *)record);
		record = (struct vdfs4_cattree_record *)
				vdfs4_btree_find(tree, &key->gen_key,
				VDFS4_BNODE_MODE_RO);
		kfree(key);
		if (!IS_ERR(record) && (record->key->parent_id
			!= catalog_id || record->key->name_len !=
			dentry->d_name.len || memcmp(record->key->name,
				dentry->d_name.name,
				(size_t)record->key->name_len))) {
			vdfs4_release_record((struct vdfs4_btree_gen_record *)
					record);
			record = ERR_PTR(-ENOENT);
		}
	}

	if (!IS_ERR(record)) {
		if ((record->key->record_type == VDFS4_CATALOG_ILINK_RECORD) ||
				WARN_ON(vdfs4_cattree_is_orphan(record)))
			inode = NULL;
		else
			inode = vdfs4_get_inode_from_record(record, dir);
		vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
	} else if (record == ERR_PTR(-ENOENT))
		inode = NULL;
	else
		inode = ERR_CAST(record);
exit:
	vdfs4_cattree_r_unlock(sbi);
	ret = d_splice_alias(inode, dentry);
	VT_FINISH(vt_data);

	if (inode == ERR_PTR(-EAGAIN))
		goto again;
	return ret;
}

static struct inode *__vdfs4_iget(struct vdfs4_sb_info *sbi, ino_t ino)
{
	struct inode *inode;
	struct vdfs4_cattree_record *record;
	struct vdfs4_btree *tree = sbi->catalog_tree;
	struct inode *image_root = NULL;
	int ret = 0;

	vdfs4_assert_btree_lock(sbi->catalog_tree);
	record = vdfs4_cattree_get_first_child(sbi->catalog_tree, ino);

	if (IS_ERR(record)) {
		inode = ERR_CAST(record);
		goto out;
	}

again:
	if (record->key->parent_id != ino) {
		inode = ERR_PTR(-ENOENT);
		goto exit;
	}

	if (record->key->record_type == VDFS4_CATALOG_ILINK_RECORD) {
		struct vdfs4_cattree_record *ilink = record;

		record = vdfs4_cattree_find_inode(tree,
				ino, ilink->key->object_id,
				ilink->key->name, ilink->key->name_len,
				VDFS4_BNODE_MODE_RO);
		vdfs4_release_record((struct vdfs4_btree_gen_record *) ilink);
		if (IS_ERR(record)) {
			inode = (void*)record;
			goto out;
		}
	} else if (le64_to_cpu(record->key->object_id) == ino) {
		/* hard-link body */
	} else {
		/* it could be: first child not ilink */
		ret = vdfs4_get_next_btree_record(
				(struct vdfs4_btree_gen_record *) record);
		if (ret) {
			inode = ERR_PTR(ret);
			goto out;
		}
		goto again;
	}

	inode = vdfs4_get_inode_from_record(record, image_root);
exit:
	iput(image_root);
	vdfs4_release_record((struct vdfs4_btree_gen_record *)record);
out:
	return inode;
}

/*
 * @brief	Lookup inode by number
 */
struct inode *vdfs4_iget(struct vdfs4_sb_info *sbi, ino_t ino)
{
	struct inode *inode;

	inode = ilookup(sbi->sb, ino);
	if (!inode) {
		vdfs4_cattree_r_lock(sbi);
		inode = __vdfs4_iget(sbi, ino);
		vdfs4_cattree_r_unlock(sbi);
	}
	return inode;
}

/**
 * @brief		Get free inode index[es].
 * @param [in]	sbi	Pointer to superblock information
 * @param [out]	i_ino	Resulting inode number
 * @param [in]	count	Requested inode numbers count.
 * @return		Returns 0 if success, err code if fault
 */
int vdfs4_get_free_inode(struct vdfs4_sb_info *sbi, ino_t *i_ino,
		unsigned int count)
{
	struct page *page = NULL;
	void *data;
	__u64 last_used = atomic64_read(&sbi->free_inode_bitmap.last_used);
	pgoff_t page_index = (pgoff_t)last_used;
	/* find_from is modulo, page_index is result of div */
	__u64 find_from = do_div(page_index, VDFS4_BIT_BLKSIZE(PAGE_SIZE,
			INODE_BITMAP_MAGIC_LEN));
	/* first id on the page. */
	__u64 id_offset = page_index * VDFS4_BIT_BLKSIZE(PAGE_SIZE,
			INODE_BITMAP_MAGIC_LEN);
	/* bits per block */
	unsigned int data_size = VDFS4_BIT_BLKSIZE(PAGE_SIZE,
			INODE_BITMAP_MAGIC_LEN);
	int err = 0;
	int pass = 0;
	pgoff_t start_page = page_index;
	pgoff_t total_pages;
	*i_ino = 0;

	if (count > data_size)
		return -ENOMEM; /* todo we can allocate inode numbers chunk
		 only within one page*/

	down_read(&sbi->snapshot_info->tables_lock);
	total_pages = (pgoff_t)VDFS4_LAST_TABLE_INDEX(sbi,
			 VDFS4_FREE_INODE_BITMAP_INO) + 1;
	up_read(&sbi->snapshot_info->tables_lock);

	while (*i_ino == 0) {
		unsigned long *addr;

		page = vdfs4_read_or_create_page(sbi->free_inode_bitmap.inode,
				page_index, VDFS4_META_READ);
		if (IS_ERR_OR_NULL(page))
			return PTR_ERR(page);
		lock_page(page);

		data = kmap(page);
		addr = (void *)((char *)data + INODE_BITMAP_MAGIC_LEN);
		*i_ino = bitmap_find_next_zero_area(addr,
				data_size,
				(unsigned long)find_from,
				count, 0);
		/* free area is found */
		if ((unsigned int)(*i_ino + count - 1) < data_size) {
			VDFS4_BUG_ON(*i_ino + id_offset < VDFS4_1ST_FILE_INO,
							sbi);
			if (count > 1) {
				bitmap_set(addr, (int)*i_ino, (int)count);
			} else {
				int ret = vdfs4_test_and_set_bit((int)*i_ino, addr);

				if (ret) {
					destroy_layout(sbi);
					VDFS4_BUG_ON(1, sbi);
				}
			}
			*i_ino += (ino_t)id_offset;
			if (atomic64_read(&sbi->free_inode_bitmap.last_used) <
				(*i_ino  + (ino_t)count - 1lu))
				atomic64_set(&sbi->free_inode_bitmap.last_used,
					*i_ino + (ino_t)count - 1lu);

			vdfs4_add_chunk_bitmap(sbi, page, 1);
		} else { /* if no free bits in current page */
			struct vdfs4_layout_sb *vdfs4_sb = sbi->raw_superblock;
			*i_ino = 0;
			page_index++;
			/* if we reach last page go to first one */
			page_index = (page_index == total_pages) ? 0 :
					page_index;
			/* if it's second cycle expand the file */
			if (pass == 1)
				page_index = total_pages;
			/* if it's start page, increase pass counter */
			else if (page_index == start_page)
				pass++;
			id_offset = (__u64)page_index * (pgoff_t)data_size;
			/* if it's first page, increase the inode generation */
			if (page_index == 0) {
				/* for first page we should look up from
				 * VDFS4_1ST_FILE_INO bit*/
				atomic64_set(&sbi->free_inode_bitmap.last_used,
					VDFS4_1ST_FILE_INO);
				find_from = VDFS4_1ST_FILE_INO;
				/* increase generation of the inodes */
				le32_add_cpu(&(vdfs4_sb->exsb.generation), 1);
				vdfs4_dirty_super(sbi);
			} else
				find_from = 0;
			VDFS4_DEBUG_INO("move to next page"
				" ind = %lu, id_off = %llu, data = %d\n",
				page_index, id_offset, data_size);
		}

		kunmap(page);
		unlock_page(page);
		page_cache_release(page);

	}

	return err;
}

/**
 * @brief		Free several inodes.
 *		Agreement: inode chunks (for installed packtrees)
 *		can be allocated only within single page of inodes bitmap.
 *		So free requests also can not exceeds page boundaries.
 * @param [in]	sbi	Superblock information
 * @param [in]	inode_n	Start index of inodes to be free
 * @param [in]	count	Count of inodes to be free
 * @return		Returns error code
 */
int vdfs4_free_inode_n(struct vdfs4_sb_info *sbi, ino_t inode_n, int count)
{
	void *data;
	struct page *page = NULL;
	__u64 page_index = inode_n;
	/* offset inside page */
	__u32 int_offset = do_div(page_index, VDFS4_BIT_BLKSIZE(PAGE_SIZE,
			INODE_BITMAP_MAGIC_LEN));

	page = vdfs4_read_or_create_page(sbi->free_inode_bitmap.inode,
			(pgoff_t)page_index, VDFS4_META_READ);
	if (IS_ERR_OR_NULL(page))
		return PTR_ERR(page);

	lock_page(page);
	data = kmap(page);
	for (; count; count--)
		if (!vdfs4_test_and_clear_bit((long)int_offset + count - 1,
			(void *)((char *)data + INODE_BITMAP_MAGIC_LEN))) {
			VDFS4_DEBUG_INO("vdfs4_free_inode_n %lu"
				, inode_n);
			destroy_layout(sbi);
			VDFS4_BUG(sbi);
		}

	vdfs4_add_chunk_bitmap(sbi, page, 1);
	kunmap(page);
	unlock_page(page);
	page_cache_release(page);
	return 0;
}

/**
 * @brief		Unlink function.
 * @param [in]	dir		Pointer to inode
 * @param [in]	dentry	Pointer to directory entry
 * @return		Returns error codes
 */
static int vdfs4_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct vdfs4_sb_info *sbi = sb->s_fs_info;
	int ret = 0;

	VT_PREPARE_PARAM(vt_data);

	VDFS4_DEBUG_INO("unlink '%s', ino = %lu", dentry->d_iname,
			inode->i_ino);

	if (!inode->i_nlink) {
		VDFS4_ERR("inode #%lu has no links left!", inode->i_ino);
		return -EFAULT;
	}

	VT_IOPS_START(vt_data, vdfs_trace_iops_unlink, dentry);
	vdfs4_start_transaction(sbi);
	vdfs4_assert_i_mutex(inode);
	vdfs4_cattree_w_lock(sbi);

	drop_nlink(inode);
	VDFS4_BUG_ON(inode->i_nlink > VDFS4_LINK_MAX, sbi);

	if (is_vdfs4_inode_flag_set(inode, HARD_LINK)) {
		/* remove hard-link reference */
		ret = vdfs4_cattree_remove(sbi->catalog_tree, inode->i_ino,
				dir->i_ino, dentry->d_name.name,
				dentry->d_name.len,
				VDFS4_CATALOG_HLINK_RECORD);
		if (ret)
			goto exit_inc_nlink;
	} else if (inode->i_nlink) {
		VDFS4_ERR("inode #%lu has nlink=%u but it's not a hardlink!",
				inode->i_ino, inode->i_nlink + 1);
		ret = -EFAULT;
		goto exit_inc_nlink;
	}

	if (inode->i_nlink) {
		inode->i_ctime = vdfs4_current_time(dir);
		goto keep;
	}

	ret = vdfs4_add_to_orphan(sbi, inode);
	if (ret)
		goto exit_inc_nlink;
	ret = __vdfs4_write_inode(sbi, inode);
	if (ret) {
		vdfs4_fatal_error(sbi, "fail to update orphan list %d", ret);
		vdfs4_record_err_dump_disk(sbi, VDFS4_DEBUG_ERR_INODE_UNLINK,
			dir->i_ino, inode->i_ino, "fail update orphan", NULL, 0);
		goto exit_inc_nlink;
	}
keep:
	mark_inode_dirty(inode);
	vdfs4_cattree_w_unlock(sbi);

	vdfs4_assert_i_mutex(dir);
	if (dir->i_size != 0)
		dir->i_size--;
	else
		VDFS4_DEBUG_INO("Files count mismatch");

	dir->i_ctime = vdfs4_current_time(dir);
	dir->i_mtime = vdfs4_current_time(dir);
	mark_inode_dirty(dir);
exit:
	vdfs4_stop_transaction(sbi);
	VT_FINISH(vt_data);
	return ret;

exit_inc_nlink:
	inc_nlink(inode);
	vdfs4_cattree_w_unlock(sbi);
	goto exit;
}

/**
 * @brief		Gets file's extent with iblock less and closest
 *			to the given one
 * @param [in]	inode	Pointer to the file's inode
 * @param [in]	iblock	Requested iblock
 * @return		Returns extent, or err code on failure
 */
int vdfs4_get_iblock_extent(struct inode *inode, sector_t iblock,
		struct vdfs4_extent_info *result, sector_t *hint_block)
{
	struct vdfs4_inode_info *inode_info = VDFS4_I(inode);
	struct vdfs4_sb_info *sbi = VDFS4_SB(inode->i_sb);
	struct vdfs4_fork_info *fork = &inode_info->fork;
	int ret = 0;
	unsigned int pos;
	sector_t last_iblock;

	if (!fork->total_block_count || !fork->used_extents)
		return 0;


	for (pos = 0; pos < fork->used_extents; pos++) {
		last_iblock = fork->extents[pos].iblock +
				fork->extents[pos].block_count - 1;
		if ((iblock >= fork->extents[pos].iblock) &&
				(iblock <= last_iblock)) {
			/* extent is found */
			memcpy(result, &fork->extents[pos], sizeof(*result));
			goto exit;
		}
	}
	/* required extent is not found
	 * if no extent(s) for the inode in extents overflow tree
	 * the last used extent in fork can be used for allocataion
	 * hint calculation */
	if (fork->used_extents < VDFS4_EXTENTS_COUNT_IN_FORK) {
		memcpy(result, &fork->extents[pos - 1],
			sizeof(*result));
		goto not_found;
	}

	/* extent is't found in fork */
	/* now we must to look up for extent in extents overflow B-tree */
	ret = vdfs4_exttree_get_extent(sbi, inode, iblock, result);

	if (ret && ret != -ENOENT)
		return ret;

	if (result->first_block == 0) {
		/* no extents in extents overflow tree */
		memcpy(result, &fork->extents[VDFS4_EXTENTS_COUNT_IN_FORK - 1],
				sizeof(*result));
		goto not_found;
	}

	last_iblock = result->iblock + result->block_count - 1;
	/*check : it is a required extent or not*/
	if ((iblock >= result->iblock) && (iblock <= last_iblock))
		goto exit;

not_found:
	if (hint_block) {
		if (iblock == result->iblock + result->block_count)
			*hint_block = result->first_block + result->block_count;
		else
			*hint_block = 0;
	}

	result->first_block = 0;
exit:
	return 0;

}

/**
 * @brief			Add allocated space into the fork or the exttree
 * @param [in]	inode_info	Pointer to inode_info structure.
 * @param [in]	iblock		First logical block number of allocated space.
 * @param [in]	block		First physical block number of allocated space.
 * @param [in]	blk_cnt		Allocated space size in blocks.
 * @param [in]	update_bnode	It's flag which control the update of the
				bnode. 1 - update bnode rec, 0 - update only
				inode structs.
 * @param [in]	do_erase	It's flag which control erase block.
 * @return			Returns physical block number, or err_code
 */
static int insert_extent(struct vdfs4_inode_info *inode_info,
			 struct vdfs4_extent_info *extent,
			 int update_bnode, int do_erase)
{

	struct inode *inode = &inode_info->vfs_inode;
	struct vdfs4_sb_info *sbi = inode->i_sb->s_fs_info;
	struct vdfs4_fork_info *fork = &inode_info->fork;
	int ret = 0;
	unsigned int pos = 0, count;

	/* try to expand extent in vdfs4_inode_info fork by new extent*/
	sector_t last_iblock, last_extent_block;

	if (fork->used_extents == 0) {
		fork->used_extents++;
		memcpy(&fork->extents[pos], extent, sizeof(*extent));
		goto update_on_disk_layout;
	}

	if (extent->iblock < fork->extents[0].iblock)
		goto insert_in_fork;

	/* find a place for insertion */
	for (pos = 0; pos < fork->used_extents; pos++) {
		if (extent->iblock < fork->extents[pos].iblock)
			break;
	}
	/* we need previous extent */
	pos--;

	/* try to extend extent in fork */
	last_iblock = fork->extents[pos].iblock +
				fork->extents[pos].block_count - 1;

	last_extent_block = fork->extents[pos].first_block +
			fork->extents[pos].block_count - 1;

	if ((last_iblock + 1 == extent->iblock) &&
		(last_extent_block + 1 == extent->first_block)) {
		/* expand extent in fork */
		fork->extents[pos].block_count += extent->block_count;
		/* FIXME check overwrite next extent */
		goto update_on_disk_layout;
	}

	/* we can not expand last extent in fork */
	/* now we have a following options:
	 * 1. insert in fork
	 * 2. insert into extents overflow btree
	 * 3a. shift extents if fork to right, push out rightest extent
	 * 3b. shift extents in fork to right and insert in fork
	 * into extents overflow btee
	 * */
	pos++;
insert_in_fork:
	if (pos < VDFS4_EXTENTS_COUNT_IN_FORK &&
			fork->extents[pos].first_block == 0) {
		/* 1. insert in fork */
		memcpy(&fork->extents[pos], extent, sizeof(*extent));
		fork->used_extents++;
	} else if (pos == VDFS4_EXTENTS_COUNT_IN_FORK) {
		/* 2. insert into extents overflow btree */
		ret = vdfs4_extree_insert_extent(sbi, inode->i_ino,
						extent, 1);
		if (ret)
			goto exit;

		goto update_on_disk_layout;
	} else {
		if (fork->used_extents == VDFS4_EXTENTS_COUNT_IN_FORK) {
			/* 3a push out rightest extent into extents
			 * overflow btee */
			ret = vdfs4_extree_insert_extent(sbi, inode->i_ino,
				&fork->extents[VDFS4_EXTENTS_COUNT_IN_FORK - 1],
				 1);
			if (ret)
				goto exit;
		} else
			fork->used_extents++;

		/*  3b. shift extents in fork to right  */
		for (count = fork->used_extents - 1; count > pos; count--)
			memcpy(&fork->extents[count], &fork->extents[count - 1],
						sizeof(*extent));
		memcpy(&fork->extents[pos], extent, sizeof(*extent));
	}

update_on_disk_layout:
	/*
	 * erase blocks
	 */
	if (do_erase) {
		unsigned int sector_cnt_in_blk;
		sector_cnt_in_blk = sbi->log_block_size - SECTOR_SIZE_SHIFT;
		ret = blkdev_issue_discard(sbi->sb->s_bdev,
			extent->first_block << sector_cnt_in_blk,
			extent->block_count << sector_cnt_in_blk,
			GFP_NOFS, BLKDEV_DISCARD_ZERO);
		if (ret)
			ret = blkdev_issue_zeroout(sbi->sb->s_bdev,
				extent->first_block << sector_cnt_in_blk,
				extent->block_count << sector_cnt_in_blk,
				GFP_NOFS, 0);
	}

	/*
	 * update inode and sb info
	 */
	fork->total_block_count += extent->block_count;
	inode_add_bytes(inode, sbi->sb->s_blocksize * extent->block_count);
	if (update_bnode)
		mark_inode_dirty(inode);

exit:
	return ret;
}

void vdfs4_free_reserved_space(struct inode *inode, sector_t iblocks_count)
{
	struct vdfs4_sb_info *sbi = VDFS4_SB(inode->i_sb);
	/* if block count is valid and fsm exist, free the space.
	 * fsm may not exist in case of umount */
	if (iblocks_count && sbi->fsm_info) {
		mutex_lock(&sbi->fsm_info->lock);
		VDFS4_BUG_ON(sbi->reserved_blocks_count < iblocks_count, sbi);
		sbi->reserved_blocks_count -= iblocks_count;
		sbi->free_blocks_count += iblocks_count;
		mutex_unlock(&sbi->fsm_info->lock);
	}
}

static int vdfs4_reserve_space(struct inode *inode, sector_t iblocks_count)
{
	struct vdfs4_sb_info *sbi = VDFS4_SB(inode->i_sb);
	int ret = 0;

	mutex_lock(&sbi->fsm_info->lock);
	if (sbi->free_blocks_count >= iblocks_count) {
		sbi->free_blocks_count -= iblocks_count;
		sbi->reserved_blocks_count += iblocks_count;
	} else
		ret = -ENOSPC;

	mutex_unlock(&sbi->fsm_info->lock);

	return ret;
}

/**
 * @brief      This is a special get_block_t callback which is used by
 *              vdfs4_write_begin(). It will either return mapped block or
 *              reserved space for a single block.
 *              (prepare delayed allocation)
 * @param [in] inode           Pointer to inode_info structure.
 * @param [in] iblock          Logical block number to find
 * @param [out]        bh_result       Pointer to buffer_head.
 * @param [in] create          "Expand file allowed" flag.
 * @return                                     0 on success, or error code
 */
int vdfs4_get_block_prep_da(struct inode *inode, sector_t iblock,
		struct buffer_head *bh_result, int create) {
	struct vdfs4_inode_info *inode_info = VDFS4_I(inode);
	struct vdfs4_sb_info *sbi = inode->i_sb->s_fs_info;
	struct super_block *sb = inode->i_sb;
	sector_t offset_alloc_hint = 0, res_block;
	int err = 0;
	__u32 max_blocks = 1;
	__u32 buffer_size = (__u32)(bh_result->b_size >> sbi->block_size_shift);
	struct vdfs4_extent_info extent;

	if (!create)
		VDFS4_BUG(sbi);
	memset(&extent, 0x0, sizeof(extent));
	mutex_lock(&inode_info->truncate_mutex);

	/* get extent contains iblock*/
	err = vdfs4_get_iblock_extent(&inode_info->vfs_inode, iblock, &extent,
			&offset_alloc_hint);

	if (err)
		goto exit;

	if (extent.first_block)
		goto done;

	if (buffer_delay(bh_result))
		goto exit;

	err = vdfs4_check_meta_space(sbi);
	if (err)
		goto exit;

	if (S_ISLNK(inode->i_mode) &&
		!list_empty(&inode_info->runtime_extents) &&
		vdfs4_runtime_extent_exists(iblock, &inode_info->runtime_extents))
		/* already reserved in vdfs4_symlink() */
		goto map_only;

	err = vdfs4_reserve_space(inode, 1);
	if (err)
		/* not enough space to reserve */
		goto exit;

	err = vdfs4_runtime_extent_add(iblock, offset_alloc_hint,
			&inode_info->runtime_extents);
	if (err) {
		vdfs4_free_reserved_space(inode, 1);
		goto exit;
	}
map_only:
	map_bh(bh_result, inode->i_sb, VDFS4_INVALID_BLOCK);
	set_buffer_new(bh_result);
	set_buffer_delay(bh_result);
	goto exit;
done:
	res_block = extent.first_block + (iblock - extent.iblock);
	max_blocks = extent.block_count - (__u32)(iblock - extent.iblock);
	VDFS4_BUG_ON(res_block > extent.first_block + extent.block_count, sbi);

	if (res_block > (sector_t)(sb->s_bdev->bd_inode->i_size >>
				sbi->block_size_shift)) {
		if (!is_sbi_flag_set(sbi, IS_MOUNT_FINISHED)) {
			VDFS4_ERR("Block beyond block bound requested");
			err = -EFAULT;
			goto exit;
		} else {
			VDFS4_BUG(sbi);
		}
	}
	mutex_unlock(&inode_info->truncate_mutex);
	clear_buffer_new(bh_result);
	map_bh(bh_result, inode->i_sb, res_block);
	bh_result->b_size = sb->s_blocksize * min(max_blocks, buffer_size);

	return 0;
exit:
	mutex_unlock(&inode_info->truncate_mutex);
	return err;
}
/**
 * @brief				Logical to physical block numbers
 *					translation.
 * @param [in]		inode		Pointer to inode structure.
 * @param [in]		iblock		Requested logical block number.
 * @param [in, out]	bh_result	Pointer to buffer_head.
 * @param [in]		create		"Expand file allowed" flag.
 * @param [in]		fsm_flags	see VDFS4_FSM_*
 * @return				0 on success, or error code
 */
int vdfs4_get_int_block(struct inode *inode, sector_t iblock,
	struct buffer_head *bh_result, int create, int fsm_flags)
{
	struct vdfs4_inode_info *inode_info = VDFS4_I(inode);
	struct vdfs4_sb_info *sbi = inode->i_sb->s_fs_info;
	struct super_block *sb = inode->i_sb;
	sector_t offset_alloc_hint = 0, res_block;
	int alloc = 0;
	__u32 max_blocks = 1;
	int count = 1;
	__u32 buffer_size = (__u32)(bh_result->b_size >> sbi->block_size_shift);
	int err = 0;
	struct vdfs4_extent_info extent;

	VDFS4_BUG_ON(!mutex_is_locked(&inode_info->truncate_mutex), sbi);
	memset(&extent, 0x0, sizeof(extent));

	/* get extent contains iblock*/
	err = vdfs4_get_iblock_extent(&inode_info->vfs_inode, iblock, &extent,
			&offset_alloc_hint);

	if (err)
		goto exit;

	if (extent.first_block)
		goto done;

	if (!create)
		goto exit;

	if (fsm_flags & VDFS4_FSM_ALLOC_DELAYED) {
		if (!vdfs4_runtime_extent_exists(iblock,
				&inode_info->runtime_extents))
			VDFS4_BUG(sbi);
	} else {
		if (buffer_delay(bh_result))
			VDFS4_BUG(sbi);
	}
	extent.block_count = (u32)count;
	extent.first_block = vdfs4_fsm_get_free_block(sbi, offset_alloc_hint,
			&extent.block_count, extent.block_count, fsm_flags);

	if (!extent.first_block) {
		err = -ENOSPC;
		goto exit;
	}

	extent.iblock = iblock;
	err = insert_extent(inode_info, &extent, 1, 0);
	if (err) {
		fsm_flags |= VDFS4_FSM_FREE_UNUSED;
		if (fsm_flags & VDFS4_FSM_ALLOC_DELAYED) {
			fsm_flags |= VDFS4_FSM_FREE_RESERVE;
			clear_buffer_mapped(bh_result);
		}
		vdfs4_fsm_put_free_block(inode_info, extent.first_block,
				extent.block_count, fsm_flags);
		goto exit;
	}

	if (fsm_flags & VDFS4_FSM_ALLOC_DELAYED) {
		err = vdfs4_runtime_extent_del(extent.iblock,
			&inode_info->runtime_extents);
		VDFS4_BUG_ON(err, sbi);
	}

	alloc = 1;

done:
	res_block = extent.first_block + (iblock - extent.iblock);
	max_blocks = extent.block_count - (u32)(iblock - extent.iblock);
	VDFS4_BUG_ON(res_block > extent.first_block + extent.block_count, sbi);

	if (res_block > (sector_t)(sb->s_bdev->bd_inode->i_size >>
				sbi->block_size_shift)) {
		if (!is_sbi_flag_set(sbi, IS_MOUNT_FINISHED)) {
			VDFS4_ERR("Block beyond block bound requested");
			err = -EFAULT;
			goto exit;
		} else {
			VDFS4_BUG(sbi);
		}
	}

	clear_buffer_new(bh_result);
	map_bh(bh_result, inode->i_sb, res_block);
	clear_buffer_delay(bh_result);
	bh_result->b_size = sb->s_blocksize * min(max_blocks, buffer_size);

	if (alloc)
		set_buffer_new(bh_result);
	return 0;
exit:
	if (err && create && (fsm_flags & VDFS4_FSM_ALLOC_DELAYED))
		vdfs4_fatal_error(sbi, "delayed allocation failed for "
				"inode #%lu: %d", inode->i_ino, err);
	return err;
}

#ifdef CONFIG_VDFS4_SQUEEZE_PROFILING
void vdfs4_save_profiling_log(struct vdfs4_sb_info *sbi,
		ino_t ino, sector_t iblock, u32 blk_cnt)
{
	struct vdfs4_prof_data prof_data;
	const char *pname = CONFIG_VDFS4_SQUEEZE_PROFILING_PARTITION;

	if (VDFS4_IS_READONLY(sbi->sb) ||
		(strncmp(sbi->sb->s_id, pname, strlen(pname))))
		return;

	prof_data.stamp = vdfs4_encode_time(CURRENT_TIME);
	prof_data.ino = (__u32)ino;
	prof_data.block = (__u32)iblock;
	prof_data.count = (__u32)blk_cnt;

	kfifo_in_locked(&sbi->prof_fifo, &prof_data, sizeof(prof_data),
			&sbi->prof_lock);
}
#endif

/**
 * @brief				Logical to physical block numbers
 *					translation.
 * @param [in]		inode		Pointer to inode structure.
 * @param [in]		iblock		Requested logical block number.
 * @param [in, out]	bh_result	Pointer to buffer_head.
 * @param [in]		create		"Expand file allowed" flag.
 * @return                     0 on success, or error code
 */
int vdfs4_get_block(struct inode *inode, sector_t iblock,
	struct buffer_head *bh_result, int create)
{
	int ret = 0;
	struct vdfs4_inode_info *inode_info = VDFS4_I(inode);
	struct mutex *lock = &inode_info->truncate_mutex;
#ifdef CONFIG_VDFS4_SQUEEZE_PROFILING
	struct vdfs4_sb_info *sbi = inode->i_sb->s_fs_info;

	vdfs4_save_profiling_log(sbi, inode->i_ino, iblock, 1);
#endif
	mutex_lock(lock);
	ret = vdfs4_get_int_block(inode, iblock, bh_result, create, 0);
	mutex_unlock(lock);
	return ret;
}

int vdfs4_get_block_da(struct inode *inode, sector_t iblock,
	struct buffer_head *bh_result, int create)
{
	return vdfs4_get_int_block(inode, iblock, bh_result, create,
					VDFS4_FSM_ALLOC_DELAYED);
}

/**
 * @brief					This is a special get_block_t callback
 *							which is used by vdfs4_writepage().
 *							This function will be not called in normal.
 * @param [in]         inode           Pointer to inode structure.
 * @param [in]         iblock          Requested logical block number.
 * @param [in, out]    bh_result       Pointer to buffer_head.
 * @param [in]         create          "Expand file allowed" flag.
 * @return                     0 on success, or error code
 */
static int vdfs4_get_block_bug(struct inode *inode, sector_t iblock,
	struct buffer_head *bh_result, int create)
{
	VDFS4_BUG(VDFS4_SB(inode->i_sb));
	return 0;
}

static int vdfs4_releasepage(struct page *page, gfp_t gfp_mask)
{
	if (!page_has_buffers(page))
		return 0;

	if (buffer_delay(page_buffers(page)))
		return 0;

	return try_to_free_buffers(page);
}

#ifdef CONFIG_VDFS4_AUTHENTICATION

static int vdfs4_access_remote_vm(struct mm_struct *mm,
		unsigned long addr, void *buf, int len)
{
	struct vm_area_struct *vma;
	void *old_buf = buf;
	/* ignore errors, just check how much was successfully transferred */
	while (len) {
		int bytes = 0, ret, offset;
		void *maddr;
		struct page *page = NULL;

		ret = get_user_pages(NULL, mm, addr, 1,
				0, 1, &page, &vma);
		if (ret > 0) {
			bytes = len;
			offset = addr & (PAGE_SIZE-1);
			if (bytes > (int)PAGE_SIZE - offset)
				bytes = (int)PAGE_SIZE - offset;

			maddr = kmap(page);
			copy_from_user_page(vma, page, addr,
					buf, (char *)maddr + offset,
					(size_t)bytes);
			kunmap(page);
			page_cache_release(page);
		} else
			break;
		len -= bytes;
		buf = (char *)buf  + bytes;
		addr += (unsigned)bytes;
	}
	return (char *)buf - (char *)old_buf;
}

static unsigned int get_pid_cmdline(struct mm_struct *mm, char *buffer)
{
	unsigned int res = 0, len = mm->arg_end - mm->arg_start;

	if (len > PAGE_SIZE)
		len = PAGE_SIZE;
	res = (unsigned int)vdfs4_access_remote_vm(mm,
			mm->arg_start, buffer, (int)len);

	if (res > 0 && buffer[res-1] != '\0' && len < PAGE_SIZE) {
		len = strnlen(buffer, res);
		if (len < res) {
			res = len;
		} else {
			len = mm->env_end - mm->env_start;
			if (len > PAGE_SIZE - res)
				len = PAGE_SIZE - res;
			res += (unsigned int)
				vdfs4_access_remote_vm(mm, mm->env_start,
					buffer+res, (int)len);
			res = strnlen(buffer, res);
		}
	}
	return res;
}
/*
 * Returns true if currant task cannot read this inode
 * because it's alowed to read only authenticated files.
 */
static int current_reads_only_authenticated(struct inode *inode, bool mm_locked)
{
	struct task_struct *task = current;
	struct mm_struct *mm;
	int ret = 0;

	if (!S_ISREG(inode->i_mode) ||
	    !is_sbi_flag_set(VDFS4_SB(inode->i_sb), VOLUME_AUTH) ||
	    is_vdfs4_inode_flag_set(inode, VDFS4_AUTH_FILE))
		return ret;

	mm = get_task_mm(task);
	if (!mm)
		return ret;

	if (!mm_locked)
		down_read(&mm->mmap_sem);
	if (mm->exe_file) {
		struct inode *caller = mm->exe_file->f_path.dentry->d_inode;

		ret = !memcmp(&caller->i_sb->s_magic, VDFS4_SB_SIGNATURE,
			sizeof(VDFS4_SB_SIGNATURE) - 1) &&
			is_vdfs4_inode_flag_set(caller, VDFS4_READ_ONLY_AUTH);
		if (ret) {
#ifdef CONFIG_VDFS4_DEBUG_AUTHENTICAION
			if (!VDFS4_I(inode)->informed_about_fail_read) {
#endif
			unsigned int len;
			char *buffer = kzalloc(PAGE_SIZE, GFP_NOFS);

			VDFS4_ERR("mmap is not permited for:"
					" ino - %lu: name -%s, pid - %d,"
					" Can't read "
					"non-auth data from ino - %lu,"
					" name - %s ",
					caller->i_ino, VDFS4_I(caller)->name,
					task_pid_nr(task),
					inode->i_ino, VDFS4_I(inode)->name);
			if (!buffer)
				goto out;
			len = get_pid_cmdline(mm, buffer);
			if (len > 0) {
				size_t i = 0;

				VDFS4_ERR("Pid %d cmdline - ", task_pid_nr(task));
				for (i = 0; i <= len;
						i += strlen(buffer + i) + 1)
					pr_cont("%s ", buffer + i);
				pr_cont("\n");
			}
			kfree(buffer);
		}
#ifdef CONFIG_VDFS4_DEBUG_AUTHENTICAION
		}
#endif
	}
out:
	if (!mm_locked)
		up_read(&mm->mmap_sem);

	mmput(mm);

	return ret;
}
#endif

/**
 * @brief		Read page function.
 * @param [in]	file	Pointer to file structure
 * @param [out]	page	Pointer to page structure
 * @return		Returns error codes
 */
static int vdfs4_readpage(struct file *file, struct page *page)
{
	int ret;

	VT_PREPARE_PARAM(vt_data);
	VT_AOPS_START(vt_data, vdfs_trace_aops_readpage,
		      page->mapping->host, file, page->index, 1, AOPS_SYNC);
	ret = mpage_readpage(page, vdfs4_get_block);
	VT_FINISH(vt_data);
	return ret;
}


/**
 * @brief		Read page function.
 * @param [in]	file	Pointer to file structure
 * @param [out]	page	Pointer to page structure
 * @return		Returns error codes
 */
static int vdfs4_readpage_special(struct file *file, struct page *page)
{
	VDFS4_BUG(NULL);
}

/**
 * @brief			Read multiple pages function.
 * @param [in]	file		Pointer to file structure
 * @param [in]	mapping		Address of pages mapping
 * @param [out]	pages		Pointer to list with pages
 * param [in]	nr_pages	Number of pages
 * @return			Returns error codes
 */
static int vdfs4_readpages(struct file *file, struct address_space *mapping,
		struct list_head *pages, unsigned nr_pages)
{
	int ret;

	#define list_to_page(head) (list_entry((head)->prev, struct page, lru))
	struct page *page = list_to_page(pages);

	VT_PREPARE_PARAM(vt_data);
	VT_AOPS_START(vt_data, vdfs_trace_aops_readpages,
		      mapping->host, file, page->index, nr_pages, AOPS_SYNC);
	ret = mpage_readpages(mapping, pages, nr_pages, vdfs4_get_block);
	VT_FINISH(vt_data);
	return ret;
}

static int vdfs4_readpages_special(struct file *file,
		struct address_space *mapping, struct list_head *pages,
		unsigned nr_pages)
{
	VDFS4_BUG(NULL);
}

static enum compr_type get_comprtype_by_descr(
		struct vdfs4_comp_file_descr *descr)
{
	if (!memcmp(descr->magic + 1, VDFS4_COMPR_LZO_FILE_DESCR_MAGIC,
			sizeof(descr->magic) - 1))
		return VDFS4_COMPR_LZO;

	if (!memcmp(descr->magic + 1, VDFS4_COMPR_ZIP_FILE_DESCR_MAGIC,
			sizeof(descr->magic) - 1))
		return VDFS4_COMPR_ZLIB;

	if (!memcmp(descr->magic + 1, VDFS4_COMPR_GZIP_FILE_DESCR_MAGIC,
			sizeof(descr->magic) - 1))
		return VDFS4_COMPR_GZIP;

	return -EINVAL;
}

static int get_file_descr_length(struct vdfs4_comp_file_descr *descr)
{
	switch (descr->layout_version) {
	case VDFS4_COMPR_LAYOUT_VER_06:
		return VDFS4_COMPR_FILE_DESC_LEN_06;
	case VDFS4_COMPR_LAYOUT_VER_05:
		return VDFS4_COMPR_FILE_DESC_LEN_05;
	default:
		VDFS4_ERR("Unsupported compressed file layout %04x",
			descr->layout_version);
		return -1;
	}
}

static int vdfs4_file_descriptor_verify(struct vdfs4_inode_info *inode_i,
		struct vdfs4_comp_file_descr *descr)
{
	int ret = 0, i, supported = 0;
	enum compr_type compr_type;

	for (i = 0; i < VDFS4_NUM_OF_SUPPORTED_COMPR_LAYOUTS; i++) {
		if (le16_to_cpu(descr->layout_version) ==
					supported_compressed_layouts[i]) {
			supported = 1;
			break;
		}
	}
	if (!supported) {
		VDFS4_ERR("Wrong descriptor layout version %d (expected %d) file %s",
				le16_to_cpu(descr->layout_version), VDFS4_COMPR_LAYOUT_VER,
				INODEI_NAME(inode_i));
		ret = -EINVAL;
		goto err;
	}

	switch (descr->magic[0]) {
	case VDFS4_COMPR_DESCR_START:
	case VDFS4_SHA1_AUTH:
	case VDFS4_SHA256_AUTH:
	case VDFS4_MD5_AUTH:
		break;
	default:
		VDFS4_ERR("Wrong descriptor magic start %c "
			"in compressed file %s",
			descr->magic[0], INODEI_NAME(inode_i));
		ret = -EINVAL;
		goto err;
	}

	compr_type = get_comprtype_by_descr(descr);
	switch (compr_type) {
	case VDFS4_COMPR_ZLIB:
	case VDFS4_COMPR_GZIP:
	case VDFS4_COMPR_LZO:
		break;
	default:
		VDFS4_ERR("Wrong descriptor magic (%.*s) "
				"in compressed file %s",
			(int)sizeof(descr->magic), descr->magic,
			INODEI_NAME(inode_i));
		ret = -EOPNOTSUPP;
		goto err;
	}

err:
	if (ret) {
		VDFS4_MDUMP("Bad descriptor dump:", descr, sizeof(*descr));
		vdfs4_print_volume_verification(
					VDFS4_SB(inode_i->vfs_inode.i_sb));
	}
	return ret;
}

static int get_file_descriptor(struct vdfs4_inode_info *inode_i,
		struct vdfs4_comp_file_descr *descr)
{
	void *data;
	pgoff_t page_idx;
	int pos;
	loff_t descr_offset;
	int ret = 0;
	struct page *pages[2] = {0};

	if (inode_i->fbc->comp_size < sizeof(*descr))
		return -EINVAL;
	descr_offset = inode_i->fbc->comp_size - sizeof(*descr);
	page_idx = (pgoff_t)(descr_offset >> PAGE_CACHE_SHIFT);
	pos = descr_offset & (PAGE_CACHE_SIZE - 1);

	if (PAGE_CACHE_SIZE - (descr_offset -
			((descr_offset >> PAGE_CACHE_SHIFT)
			<< PAGE_CACHE_SHIFT)) < sizeof(*descr)) {
		ret = vdfs4_read_comp_pages(&inode_i->vfs_inode, page_idx,
			2, pages, VDFS4_FBASED_READ_M);
		if (ret)
			return ret;

		data = vdfs4_vmap(pages, 2, VM_MAP, PAGE_KERNEL);
		if (!data) {
			ret = -ENOMEM;
			goto err;
		}
		memcpy(descr, (char *)data + pos, sizeof(*descr));
		vunmap(data);
	} else {
		ret = vdfs4_read_comp_pages(&inode_i->vfs_inode, page_idx,
			1, pages, VDFS4_FBASED_READ_M);
		if (ret)
			return ret;

		data = kmap_atomic(pages[0]);
		memcpy(descr, (char *)data + pos, sizeof(*descr));
		kunmap_atomic(data);
	}

	if (le16_to_cpu(descr->layout_version) ==
			VDFS4_COMPR_LAYOUT_VER_05) {
#ifdef CONFIG_VDFS4_ALLOW_LEGACY_SIGN
		descr->sign_type = VDFS4_SIGN_RSA1024;
#else
		descr->sign_type = VDFS4_SIGN_MAX;
		ret = -EPERM;
		goto err;
#endif
	}
	ret = vdfs4_file_descriptor_verify(inode_i, descr);
err:
	for (page_idx = 0; page_idx < 2; page_idx++) {
		if (pages[page_idx]) {
			if (ret && ret != -ENOMEM) {
				lock_page(pages[page_idx]);
				ClearPageChecked(pages[page_idx]);
				unlock_page(pages[page_idx]);
			}
			mark_page_accessed(pages[page_idx]);
			page_cache_release(pages[page_idx]);
		}
	}
	return ret;
}

/**
 * @brief		Write pages.
 * @param [in]	page	List of pages
 * @param [in]	wbc		Write back control array
 * @return		Returns error codes
 */
static int vdfs4_writepage(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	struct buffer_head *bh;
	int ret = 0;

	VT_PREPARE_PARAM(vt_data);

	VDFS4_BUG_ON(inode->i_ino <= VDFS4_LSFILE, VDFS4_SB(inode->i_sb));

	if (!page_has_buffers(page))
		goto redirty_page;

	bh = page_buffers(page);
	if ((!buffer_mapped(bh) || buffer_delay(bh)) && buffer_dirty(bh))
		goto redirty_page;

	VT_AOPS_START(vt_data, vdfs_trace_aops_writepage,
		      page->mapping->host, NULL, 0, wbc->nr_to_write,
		      wbc->sync_mode);
	ret = block_write_full_page(page, vdfs4_get_block_bug, wbc);
#ifdef CONFIG_VDFS4_DEBUG
	if (ret)
		VDFS4_ERR("err = %d, ino#%lu name=%s, page index: %lu, "
				" wbc->sync_mode = %d", ret, inode->i_ino,
				VDFS4_I(inode)->name, page->index,
				wbc->sync_mode);
#endif
	VT_FINISH(vt_data);
	return ret;
redirty_page:
	redirty_page_for_writepage(wbc, page);
	unlock_page(page);
	return 0;
}

static int vdfs4_readpage_tuned_sw(struct file *file, struct page *page)
{
	int ret = 0, i;
	struct page **chunk_pages = NULL;
	struct vdfs4_comp_extent_info cext;
	struct inode *inode = page->mapping->host;
	struct vdfs4_inode_info *inode_i = VDFS4_I(inode);
	pgoff_t index = page->index & ~((1lu << (inode_i->fbc->log_chunk_size -
					(unsigned long)PAGE_SHIFT)) - 1lu);
	int pages_count = (1 << (inode_i->fbc->log_chunk_size -
			PAGE_SHIFT)) + 1;
	VT_PREPARE_PARAM(vt_data);

	chunk_pages = kzalloc(sizeof(struct page *) * pages_count, GFP_NOFS);

	if (!chunk_pages) {
		ret = -ENOMEM;
		unlock_page(page);
		goto exit;
	}

	if (page->index >= ((i_size_read(inode) + PAGE_CACHE_SIZE - 1) >>
					PAGE_CACHE_SHIFT)) {
		/* outside inode->i_size */
		clear_highpage(page);
		SetPageUptodate(page);
		unlock_page(page);
		goto exit;
	}
	VT_START(vt_data);

	unlock_page(page);
	/* read input data (read chunk from disk) */
	ret = vdfs4_read_chunk(page, chunk_pages, &cext);
	if (ret < 0) {
		VT_DECOMP_FINISH(vt_data, vdfs_trace_decomp_sw, NULL,
				 0, 0, 0, 1/*canceled*/, 0);
		goto exit;
	}
	ret = vdfs4_auth_decompress_sw(page->mapping->host, chunk_pages, index,
			&cext, page);

	for (i = 0; i < cext.blocks_n; i++) {
		if (ret) {
			lock_page(chunk_pages[i]);
			ClearPageUptodate(chunk_pages[i]);
			unlock_page(chunk_pages[i]);
		} else
			mark_page_accessed(chunk_pages[i]);
		page_cache_release(chunk_pages[i]);
	}
	VT_DECOMP_FINISH(vt_data, vdfs_trace_decomp_sw, inode,
			 (cext.start_block << PAGE_CACHE_SHIFT) + cext.offset,
			 cext.len_bytes,!!(inode_i->fbc->hash_fn),
			 !!(ret), (cext.flags&VDFS4_CHUNK_FLAG_UNCOMPR));
exit:
	kfree(chunk_pages);
	return ret;
}

#ifdef CONFIG_VDFS4_HW_DECOMPRESS_SUPPORT
#ifdef CONFIG_VDFS4_SQUEEZE
static int vdfs4_readpage_tuned_hw_generic(struct file *file, struct page *page)
{
	int ret = 0;
	struct inode *inode = page->mapping->host;
	struct vdfs4_inode_info *inode_i = VDFS4_I(inode);
	unsigned file_size_pg = ((i_size_read(inode) + PAGE_CACHE_SIZE - 1) >>
					PAGE_CACHE_SHIFT);

	if (page->index >= file_size_pg) {
		clear_highpage(page);
		SetPageUptodate(page);
		unlock_page(page);
		return 0;
	}

	if (inode_i->fbc->force_path == FORCE_SW)
		goto sw;

	/* We must lock all pages in the chunk one by one from the beginning,
	 * otherwise we might deadlock with concurrent read of other page. */
	unlock_page(page);

	ret = inode_i->fbc->hw_fn(inode, page);
	if (ret) {
		/* HW decompression/auth has failed, try software one */
		lock_page(page);
sw:
		ret = vdfs4_readpage_tuned_sw(file, page);
	}
	return ret;

}

static int vdfs4_readpage_tuned_hw(struct file *file, struct page *page)
{
	int ret;
	struct inode *inode = page->mapping->host;
	struct vdfs4_inode_info *inode_i = VDFS4_I(inode);
	unsigned file_size_pg = ((i_size_read(inode) + PAGE_CACHE_SIZE - 1) >>
						PAGE_CACHE_SHIFT);
	VT_PREPARE_PARAM(vt_data);

	VT_AOPS_START(vt_data, vdfs_trace_aops_tuned_chunk,
		      page->mapping->host, file, 0, 0, AOPS_SYNC);
	ret = vdfs4_readpage_tuned_hw_generic(file, page);
	if (ret)
		goto out;

	if (is_vdfs4_inode_flag_set(inode, VDFS4_PROFILED_FILE)) {
		struct page *ra_pg;
		unsigned cur_chunk_idx = (int)(page->index >>
			(inode_i->fbc->log_chunk_size - PAGE_SHIFT));
		unsigned next_chunk_idx, next_pg;

		if (inode_i->sci[cur_chunk_idx].order == VDFS4_COMPR_NON_SQUEEZE)
			next_chunk_idx = cur_chunk_idx + 1;
		else {
			struct list_head *ptr, *next;
			struct vdfs4_squeeze_chunk_info *entry;
			unsigned i = 0;

			spin_lock(&inode_i->to_read_lock);
			if (list_empty(&inode_i->to_read_list)) {
				/* every profiled chunk was read already */
				spin_unlock(&inode_i->to_read_lock);
				goto out;
			}

			list_for_each_safe(ptr, next, &inode_i->to_read_list) {
				entry = list_entry(ptr, struct vdfs4_squeeze_chunk_info,
								list);

				if (entry->order == cur_chunk_idx)
					list_del(&entry->list);
			}

			if (list_empty(&inode_i->to_read_list)) {
				spin_unlock(&inode_i->to_read_lock);
				goto out;
			}

			entry = list_first_entry(&inode_i->to_read_list,
						struct vdfs4_squeeze_chunk_info, list);
			list_del(&entry->list);
			spin_unlock(&inode_i->to_read_lock);

			next_chunk_idx = entry->order;
		}

		next_pg = next_chunk_idx <<
			(inode_i->fbc->log_chunk_size - PAGE_SHIFT);

		if (next_pg > file_size_pg)
			goto out;

		ra_pg = find_or_create_page(inode->i_mapping, next_pg, GFP_NOFS);
		if (!ra_pg)
			/* main read was done, so ignore read ahead error */
			goto out;

		file->f_ra.start = ra_pg->index;
		file->f_ra.size = 1 << (inode_i->fbc->log_chunk_size - PAGE_SHIFT);

		/* don't care about result */
		vdfs4_readpage_tuned_hw_generic(file, ra_pg);
	}
out:
	VT_FINISH(vt_data);
	return ret;
}
#else /* not CONFIG_VDFS4_SQUEEZE */
static int vdfs4_readpage_tuned_hw(struct file *file, struct page *page)
{
	int ret = 0;
	struct inode *inode = page->mapping->host;
	struct vdfs4_inode_info *inode_i = VDFS4_I(inode);
	unsigned file_size_pg = ((i_size_read(inode) + PAGE_CACHE_SIZE - 1) >>
					PAGE_CACHE_SHIFT);
	VT_PREPARE_PARAM(vt_data);

	if (page->index >= file_size_pg) {
		clear_highpage(page);
		SetPageUptodate(page);
		unlock_page(page);
		return 0;
	}
	VT_AOPS_START(vt_data, vdfs_trace_aops_tuned_chunk,
		      page->mapping->host, file, 0, 0, AOPS_SYNC);

	if (inode_i->fbc->force_path == FORCE_SW)
		goto sw;

	/* We must lock all pages in the chunk one by one from the beginning,
	 * otherwise we might deadlock with concurrent read of other page. */
	unlock_page(page);

	ret = inode_i->fbc->hw_fn(inode, page);
	if (ret) {
		/* HW decompression/auth has failed, try software one */
		lock_page(page);
sw:
		ret = vdfs4_readpage_tuned_sw(file, page);
	}

	VT_FINISH(vt_data);
	return ret;
}
#endif /* CONFIG_VDFS4_SQUEEZE */
#endif /* CONFIG_VDFS4_HW_DECOMPRESS_SUPPORT */

static int vdfs4_readpage_tuned_sw_retry(struct file *file, struct page *page)
{
	int i = 0, ret;

	do {
		if (i)
			lock_page(page);
		ret = vdfs4_readpage_tuned_sw(file, page);
		if (ret)
			VDFS4_ERR("read(sw) decompression retry: %d", i);
	} while (ret && (++i < 3));

	if (i && !ret)
		VDFS4_NOTICE("decompression retry successfully done");
	return ret;
}

#ifdef CONFIG_VDFS4_HW_DECOMPRESS_SUPPORT
static int vdfs4_readpage_tuned_hw_retry(struct file *file, struct page *page)
{
	int i = 0, ret;

	do {
		if (i)
			lock_page(page);
		ret = vdfs4_readpage_tuned_hw(file, page);
		if (ret)
			VDFS4_ERR("read(hw) decompression retry: %d", i);
	} while (ret && (++i < 3));

	if (i && !ret)
		VDFS4_NOTICE("decompression retry successfully done");
	return ret;
}
#endif

/**
 * @brief		Allocate physical space corresponding to extent(logical offset and size)
 * @param [in]	inode_info	Pointer to inode_info structure.
 * @param [in]	do_erase	It's flag which control erase.
 * @return		Returns error codes
 */
static int vdfs4_allocate_space(struct vdfs4_inode_info *inode_info,
				int do_erase)
{
	struct list_head *ptr;
	struct list_head *next;
	struct vdfs4_runtime_extent_info *entry;
	struct inode *inode = &inode_info->vfs_inode;
	struct vdfs4_sb_info *sbi = inode->i_sb->s_fs_info;
	u32 count = 0, total = 0;
	struct vdfs4_extent_info extent;
	int err = 0;

	memset(&extent, 0x0, sizeof(extent));

	mutex_lock(&inode_info->truncate_mutex);

	list_for_each_safe(ptr, next, &inode_info->runtime_extents) {
		entry = list_entry(ptr, struct vdfs4_runtime_extent_info, list);
again:
		count = entry->block_count;

		extent.first_block = vdfs4_fsm_get_free_block(sbi, entry->
				alloc_hint, &count, count, VDFS4_FSM_ALLOC_DELAYED);

		if (!extent.first_block) {
			/* it shouldn't happen because space
			 * was reserved early in aio_write */
			VDFS4_BUG(sbi);
			goto exit;
		}

		extent.iblock = entry->iblock;
		extent.block_count = count;
		err = insert_extent(inode_info, &extent, 0, do_erase);
		if (err) {
			vdfs4_fsm_put_free_block(inode_info,
				extent.first_block, extent.block_count,
				VDFS4_FSM_FREE_UNUSED | VDFS4_FSM_FREE_RESERVE);
			goto exit;
		}
		entry->iblock += count;
		entry->block_count -= count;
		total += count;
		/* if we still have blocks in the chunk */
		if (entry->block_count)
			goto again;
		else {
			list_del(&entry->list);
			kfree(entry);
		}
	}
exit:

	mutex_unlock(&inode_info->truncate_mutex);

	if (!err)
		mark_inode_dirty(inode);
	return err;
}

/**
 * @brief		Write some dirty pages.
 * @param [in]	mapping	Address space mapping (holds pages)
 * @param [in]	wbc		Writeback control - how many pages to write
 *			and write mode
 * @return		Returns 0 on success, errno on failure
 */

static int vdfs4_writepages(struct address_space *mapping,
		struct writeback_control *wbc)
{
	struct inode *inode = mapping->host;
	int ret;
	struct blk_plug plug;
	struct vdfs4_sb_info *sbi = inode->i_sb->s_fs_info;
	struct vdfs4_inode_info *inode_info = VDFS4_I(inode);
	struct vdfs4_mpage_data mpd = {
			.bio = NULL,
			.last_block_in_bio = 0,
	};

	VT_PREPARE_PARAM(vt_data);
	VT_AOPS_START(vt_data, vdfs_trace_aops_writepages,
		      mapping->host, NULL, wbc->range_start,
		      wbc->range_end - wbc->range_start,
		      wbc->sync_mode);

	vdfs4_start_writeback(sbi);
	/* if we have runtime extents, allocate space on volume*/
	if (!list_empty(&inode_info->runtime_extents))
		ret = vdfs4_allocate_space(inode_info, 0);

	blk_start_plug(&plug);
	/* write dirty pages */
	ret = write_cache_pages(mapping, wbc, vdfs4_mpage_writepage, &mpd);
	if (mpd.bio)
		vdfs4_mpage_bio_submit(WRITE, mpd.bio);
	blk_finish_plug(&plug);

	vdfs4_stop_writeback(sbi);

	VT_FINISH(vt_data);
	return ret;
}

/**
 * @brief		Write some dirty pages.
 * @param [in]	mapping	Address space mapping (holds pages)
 * @param [in]	wbc		Writeback control - how many pages to write
 *			and write mode
 * @return		Returns 0 on success, errno on failure
 */
static int vdfs4_writepages_special(struct address_space *mapping,
		struct writeback_control *wbc)
{
	return 0;
}
/**
 * @brief		Write begin with snapshots.
 * @param [in]	file	Pointer to file structure
 * @param [in]	mapping Address of pages mapping
 * @param [in]	pos		Position
 * @param [in]	len		Length
 * @param [in]	flags	Flags
 * @param [in]	pagep	Pages array
 * @param [in]	fs_data	Data array
 * @return		Returns error codes
 */
static int vdfs4_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	int rc = 0;

	VT_PREPARE_PARAM(vt_data);
	VT_AOPS_START(vt_data, vdfs_trace_aops_write_begin,
		      mapping->host, file, pos, len,
			  AOPS_SYNC_NONE);	/* FIXME */

	vdfs4_start_transaction(VDFS4_SB(mapping->host->i_sb));

	rc = block_write_begin(mapping, pos, len, flags, pagep,
		vdfs4_get_block_prep_da);

	if (rc)
		vdfs4_stop_transaction(VDFS4_SB(mapping->host->i_sb));

	VT_FINISH(vt_data);
	return rc;
}

/**
 * @brief		TODO Write begin with snapshots.
 * @param [in]	file	Pointer to file structure
 * @param [in]	mapping	Address of pages mapping
 * @param [in]	pos		Position
 * @param [in]	len		Length
 * @param [in]	copied	Whould it be copied
 * @param [in]	page	Page pointer
 * @param [in]	fs_data	Data
 * @return		Returns error codes
 */
static int vdfs4_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	int i_size_changed = 0;
	int ret;

	ret = block_write_end(file, mapping, pos, len, copied, page, fsdata);
	/*
	 * No need to use i_size_read() here, the i_size
	 * cannot change under us because we hold i_mutex.
	 *
	 * But it's important to update i_size while still holding page lock:
	 * page write out could otherwise come in and zero beyond i_size.
	 */
	if (pos + (loff_t)ret > inode->i_size) {
		i_size_write(inode, pos + copied);
		i_size_changed = 1;
	}

	unlock_page(page);
	page_cache_release(page);

	if (i_size_changed)
		mark_inode_dirty(inode);
	vdfs4_stop_transaction(VDFS4_SB(inode->i_sb));
	return ret;
}

/**
 * @brief		Called during file opening process.
 * @param [in]	inode	Pointer to inode information
 * @return		Returns error codes
 */
static int vdfs4_file_open_init_compressed(struct inode *inode)
{
	int rc = 0;
	struct vdfs4_inode_info *inode_info = VDFS4_I(inode);

	if (inode_info->fbc) {
		mutex_lock(&inode->i_mutex);
		if ((inode_info->fbc) &&
		    (inode_info->fbc->compr_type == VDFS4_COMPR_UNDEF)) {
			int retry_count = 0;

			do {
				rc = vdfs4_init_file_decompression(inode_info, 1);
				if (rc)
					VDFS4_ERR("init decompression retry: %d",
						retry_count);
			} while (rc && (++retry_count < 3));
		}
		mutex_unlock(&inode->i_mutex);
	}
	return rc;
}

/**
 * @brief		Called during file opening process.
 * @param [in]	inode	Pointer to inode information
 * @param [in]	file	Pointer to file structure
 * @return		Returns error codes
 */
static int vdfs4_file_open(struct inode *inode, struct file *filp)
{
	int rc = 0;

	VT_PREPARE_PARAM(vt_data);

	trace_vdfs4_file_open(inode, filp);
	VT_FOPS_START(vt_data, vdfs_trace_fops_open,
		      inode->i_sb->s_bdev->bd_part, inode, filp);

	if (is_vdfs4_inode_flag_set(inode, VDFS4_COMPRESSED_FILE)) {
		if (filp->f_flags & (O_CREAT | O_TRUNC | O_WRONLY | O_RDWR))
			rc = -EPERM;
		else
			rc = vdfs4_file_open_init_compressed(inode);
		if (rc)
			goto exit;
	}
#ifdef CONFIG_VDFS4_SQUEEZE
	if (is_vdfs4_inode_flag_set(inode, VDFS4_PROFILED_FILE)) {
		/* turn off standard read-ahead for this file */
		filp->f_ra.ra_pages = 0;
		filp->f_flags |= O_PROFILED;
	}
#endif

	rc = generic_file_open(inode, filp);
	if (!rc)
		atomic_inc(&(VDFS4_I(inode)->open_count));
exit:
	VT_FINISH(vt_data);
	return rc;
}

/**
 * @brief		Release file.
 * @param [in]	inode	Pointer to inode information
 * @param [in]	file	Pointer to file structure
 * @return		Returns error codes
 */
static int vdfs4_file_release(struct inode *inode, struct file *file)
{
	struct vdfs4_inode_info *inode_info = VDFS4_I(inode);

	trace_vdfs4_file_release(inode, file);
	VDFS4_DEBUG_INO("#%lu", inode->i_ino);
	atomic_dec(&(inode_info->open_count));
	return 0;
}

/**
 * @brief		Function mkdir.
 * @param [in]	dir	Pointer to inode
 * @param [in]	dentry	Pointer to directory entry
 * @param [in]	mode	Mode of operation
 * @return		Returns error codes
 */
static int vdfs4_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int rtn;

	VT_PREPARE_PARAM(vt_data);
	VT_IOPS_START(vt_data, vdfs_trace_iops_mkdir, dentry);
	rtn = vdfs4_create(dir, dentry, S_IFDIR | mode, NULL);
	VT_FINISH(vt_data);
	return rtn;
}

/**
 * @brief		Function rmdir.
 * @param [in]	dir	Pointer to inode
 * @param [in]	dentry	Pointer to directory entry
 * @return		Returns error codes
 */
static int vdfs4_rmdir(struct inode *dir, struct dentry *dentry)
{
	int rtn;

	VT_PREPARE_PARAM(vt_data);
	if (dentry->d_inode->i_size)
		return -ENOTEMPTY;
	VT_IOPS_START(vt_data, vdfs_trace_iops_rmdir, dentry);
	rtn = vdfs4_unlink(dir, dentry);
	VT_FINISH(vt_data);
	return rtn;
}

/**
 * @brief		Direct IO.
 * @param [in]	iocb	Pointer to io block
 * @param [in]	iov_iter	Pointer to io iter
 * @param [in]	offset	Offset
 * @return		Returns written size
 */
static ssize_t vdfs4_direct_IO(struct kiocb *iocb, struct iov_iter *iter,
						loff_t offset)
{
	ssize_t rc, inode_new_size = 0;
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_path.dentry->d_inode->i_mapping->host;
	struct vdfs4_sb_info *sbi = VDFS4_SB(inode->i_sb);

	VT_PREPARE_PARAM(vt_data);

	VT_AOPS_START(vt_data, vdfs_trace_aops_direct_io,
		      inode, file, iocb->ki_pos, iter->count, AOPS_SYNC);
	if (iov_iter_rw(iter))
		vdfs4_start_transaction(sbi);
	rc = blockdev_direct_IO(iocb, inode, iter, offset, vdfs4_get_block);
	if (!iov_iter_rw(iter))
		goto exit;

	vdfs4_assert_i_mutex(inode);

	if (!IS_ERR_VALUE(rc)) { /* blockdev_direct_IO successfully finished */
		if ((offset + rc) > i_size_read(inode))
			/* last accessed byte behind old inode size */
			inode_new_size = (ssize_t)(offset) + rc;
	} else if (VDFS4_I(inode)->fork.total_block_count >
			DIV_ROUND_UP(i_size_read(inode), VDFS4_BLOCK_SIZE))
		/* blockdev_direct_IO finished with error, but some free space
		 * allocations for inode may have occured, inode internal fork
		 * changed, but inode i_size stay unchanged. */
		inode_new_size =
			(ssize_t)VDFS4_I(inode)->fork.total_block_count <<
			sbi->block_size_shift;

	if (inode_new_size) {
		i_size_write(inode, inode_new_size);
		mark_inode_dirty(inode);
	}

	vdfs4_stop_transaction(VDFS4_SB(inode->i_sb));
exit:
	VT_FINISH(vt_data);
	return rc;
}

static int vdfs4_truncate_pages(struct inode *inode, loff_t newsize)
{
	int error = 0;

	error = inode_newsize_ok(inode, newsize);
	if (error)
		goto exit;

	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
			S_ISLNK(inode->i_mode))) {
		error = -EINVAL;
		goto exit;
	}

	if (IS_APPEND(inode) || IS_IMMUTABLE(inode)) {
		error = -EPERM;
		goto exit;
	}

	if (is_vdfs4_inode_flag_set(inode, VDFS4_COMPRESSED_FILE)) {
		VDFS4_ERR("Truncating compressed file is depricated");
		error = -EPERM;
		goto exit;
	}

	error = block_truncate_page(inode->i_mapping, newsize,
			vdfs4_get_block);
exit:
	return error;
}

static int vdfs4_update_inode(struct inode *inode, loff_t newsize)
{
	int error = 0;
	loff_t oldsize = inode->i_size;

	if (newsize < oldsize)
		error = vdfs4_truncate_blocks(inode, newsize);
	if (error)
		return error;

	i_size_write(inode, newsize);
	inode->i_mtime = inode->i_ctime = vdfs4_current_time(inode);

	return error;
}

/**
 * @brief		Set attributes.
 * @param [in]	dentry	Pointer to directory entry
 * @param [in]	iattr	Attributes to be set
 * @return		Returns error codes
 */
static int vdfs4_setattr(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = dentry->d_inode;
	int error = 0;

	VT_PREPARE_PARAM(vt_data);

	VT_IOPS_START(vt_data, vdfs_trace_iops_setattr, dentry);
	vdfs4_start_transaction(VDFS4_SB(inode->i_sb));
	error = inode_change_ok(inode, iattr);
	if (error)
		goto exit;

	vdfs4_assert_i_mutex(inode);

	if ((iattr->ia_valid & ATTR_SIZE) &&
			iattr->ia_size != i_size_read(inode)) {
		error = vdfs4_truncate_pages(inode, iattr->ia_size);
		if (error)
			goto exit;

		 truncate_pagecache(inode, iattr->ia_size);

		error = vdfs4_update_inode(inode, iattr->ia_size);
		if (error)
			goto exit;
	}

	setattr_copy(inode, iattr);

	mark_inode_dirty(inode);

#ifdef CONFIG_VDFS4_POSIX_ACL
	if (iattr->ia_valid & ATTR_MODE)
		error = posix_acl_chmod(inode, inode->i_mode);
#endif

exit:
	vdfs4_stop_transaction(VDFS4_SB(inode->i_sb));
	VT_FINISH(vt_data);
	return error;
}

/**
 * @brief		Make bmap.
 * @param [in]	mapping	Address of pages mapping
 * @param [in]	block	Block number
 * @return		TODO Returns 0 on success, errno on failure
 */
static sector_t vdfs4_bmap(struct address_space *mapping, sector_t block)
{
	sector_t ret;

	VT_PREPARE_PARAM(vt_data);
	VT_AOPS_START(vt_data, vdfs_trace_aops_bmap,
		      mapping->host, NULL, 0, 0, AOPS_SYNC);	/* FIXME */
	ret = generic_block_bmap(mapping, block, vdfs4_get_block);
	VT_FINISH(vt_data);
	return ret;
}

static int __get_record_type_on_mode(struct inode *inode, u8 *record_type)
{
	umode_t mode = inode->i_mode;

	if (is_vdfs4_inode_flag_set(inode, HARD_LINK))
		*record_type = VDFS4_CATALOG_HLINK_RECORD;
	else if (S_ISDIR(mode) || S_ISFIFO(mode) ||
		S_ISSOCK(mode) || S_ISCHR(mode) || S_ISBLK(mode))
		*record_type = VDFS4_CATALOG_FOLDER_RECORD;
	else if (S_ISREG(mode) || S_ISLNK(mode))
		*record_type = VDFS4_CATALOG_FILE_RECORD;
	else
		return -EINVAL;
	return 0;
}

/**
 * @brief			Function rename.
 * @param [in]	old_dir		Pointer to old dir struct
 * @param [in]	old_dentry	Pointer to old dir entry struct
 * @param [in]	new_dir		Pointer to new dir struct
 * @param [in]	new_dentry	Pointer to new dir entry struct
 * @return			Returns error codes
 */
static int vdfs4_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry)
{
	struct vdfs4_sb_info *sbi = old_dir->i_sb->s_fs_info;
	struct inode *mv_inode = old_dentry->d_inode;
	struct vdfs4_cattree_record *record;
	char *saved_name = NULL;
	u8 record_type;
	int ret;

	VT_PREPARE_PARAM(vt_data);

	if (new_dentry->d_name.len > VDFS4_FILE_NAME_LEN)
		return -ENAMETOOLONG;

	VT_IOPS_START(vt_data, vdfs_trace_iops_rename, old_dentry);
	vdfs4_start_transaction(sbi);

	if (new_dentry->d_inode) {
		if (S_ISDIR(new_dentry->d_inode->i_mode))
			ret = vdfs4_rmdir(new_dir, new_dentry);
		else
			ret = vdfs4_unlink(new_dir, new_dentry);
		if (ret)
			goto exit;
	}

	/*
	 * mv_inode->i_mutex is not always locked here, but this seems ok.
	 * We have source/destination dir i_mutex and catalog_tree which
	 * protects everything.
	 */

	/* Find old record */
	VDFS4_DEBUG_MUTEX("cattree mutex w lock");
	vdfs4_cattree_w_lock(sbi);
	VDFS4_DEBUG_MUTEX("cattree mutex w lock succ");

	if (!is_vdfs4_inode_flag_set(mv_inode, HARD_LINK)) {
		saved_name = kstrdup(new_dentry->d_name.name, GFP_NOFS);
		ret = -ENOMEM;
		if (!saved_name)
			goto error;
	}

	ret = __get_record_type_on_mode(mv_inode, &record_type);
	if (ret)
		goto error;

	/*
	 * Insert new record
	 */
	record = vdfs4_cattree_place_record(sbi->catalog_tree, mv_inode->i_ino,
			new_dir->i_ino, new_dentry->d_name.name,
			new_dentry->d_name.len, record_type);
	if (IS_ERR(record)) {
		ret = PTR_ERR(record);
		goto error;
	}

	/*
	 * Full it just in case, writeback anyway will fill it again.
	 */
	vdfs4_fill_cattree_record(mv_inode, record);
	vdfs4_release_dirty_record((struct vdfs4_btree_gen_record *) record);

	/*
	 * Remove old record
	 */
	ret = vdfs4_cattree_remove(sbi->catalog_tree, mv_inode->i_ino,
			old_dir->i_ino, old_dentry->d_name.name,
			old_dentry->d_name.len,
			VDFS4_I(mv_inode)->record_type);
	if (ret)
		goto remove_record;

	if (!(is_vdfs4_inode_flag_set(mv_inode, HARD_LINK))) {
		VDFS4_I(mv_inode)->parent_id = new_dir->i_ino;
		kfree(VDFS4_I(mv_inode)->name);
		VDFS4_I(mv_inode)->name = saved_name;
	}

	vdfs4_cattree_w_unlock(sbi);

	mv_inode->i_ctime = vdfs4_current_time(mv_inode);
	mark_inode_dirty(mv_inode);

	vdfs4_assert_i_mutex(old_dir);
	if (old_dir->i_size != 0)
		old_dir->i_size--;
	else
		VDFS4_DEBUG_INO("Files count mismatch");
	old_dir->i_ctime = old_dir->i_mtime = vdfs4_current_time(old_dir);
	mark_inode_dirty(old_dir);

	vdfs4_assert_i_mutex(new_dir);
	new_dir->i_size++;
	new_dir->i_ctime = new_dir->i_mtime = vdfs4_current_time(new_dir);
	mark_inode_dirty(new_dir);
exit:
	vdfs4_stop_transaction(sbi);
	VT_FINISH(vt_data);
	return ret;

remove_record:
	vdfs4_cattree_remove(sbi->catalog_tree, mv_inode->i_ino, new_dir->i_ino,
			new_dentry->d_name.name, new_dentry->d_name.len,
			VDFS4_I(mv_inode)->record_type);
error:
	vdfs4_cattree_w_unlock(sbi);
	vdfs4_stop_transaction(sbi);
	kfree(saved_name);
	VT_FINISH(vt_data);
	return ret;
}

/**
 * @brief			Function cross rename.
 * @param [in]	old_dir		Pointer to old dir struct
 * @param [in]	old_dentry	Pointer to old dir entry struct
 * @param [in]	new_dir		Pointer to new dir struct
 * @param [in]	new_dentry	Pointer to new dir entry struct
 * @return			Returns error codes
 */
static int vdfs4_cross_rename(struct inode *old_dir, struct dentry *old_dentry,
			      struct inode *new_dir, struct dentry *new_dentry)
{
	struct vdfs4_sb_info *sbi = old_dir->i_sb->s_fs_info;
	struct vdfs4_btree *tree = sbi->catalog_tree;
	struct inode *old_inode = d_inode(old_dentry);
	struct inode *new_inode = d_inode(new_dentry);
	struct vdfs4_cattree_record *old_record, *new_record, *record;
	u8 old_record_type, new_record_type;
	char *old_saved_name = NULL;
	char *new_saved_name = NULL;
	int ret = -ENOENT;

	VT_PREPARE_PARAM(vt_data);

	VT_IOPS_START(vt_data, vdfs_trace_iops_rename2, old_dentry);

	vdfs4_start_transaction(sbi);

	/*
	 * old/new_inode->i_mutex is not always locked here, but this seems ok.
	 * We have source/destination dir i_mutex and catalog_tree which
	 * protects everything.
	 */
	VDFS4_DEBUG_MUTEX("cattree mutex w lock");
	vdfs4_cattree_w_lock(sbi);
	VDFS4_DEBUG_MUTEX("cattree mutex w lock succ");

	/* handle old record */
	if (!is_vdfs4_inode_flag_set(old_inode, HARD_LINK)) {
		new_saved_name = kstrdup(new_dentry->d_name.name, GFP_NOFS);
		ret = -ENOMEM;
		if (!new_saved_name)
			goto error;
	}
	if (!is_vdfs4_inode_flag_set(new_inode, HARD_LINK)) {
		old_saved_name = kstrdup(old_dentry->d_name.name, GFP_NOFS);
		ret = -ENOMEM;
		if (!old_saved_name)
			goto error;
	}

	ret = __get_record_type_on_mode(old_inode, &old_record_type);
	if (ret)
		goto error;

	ret = __get_record_type_on_mode(new_inode, &new_record_type);
	if (ret)
		goto error;

	/* Insert old record to new entry */
	old_record = vdfs4_cattree_place_record(tree, old_inode->i_ino,
						new_dir->i_ino, new_dentry->d_name.name,
						new_dentry->d_name.len, old_record_type);
	if (IS_ERR(old_record)) {
		ret = PTR_ERR(old_record);
		goto error;
	}

	/* Insert new record to old entry */
	new_record = vdfs4_cattree_place_record(tree, new_inode->i_ino,
						old_dir->i_ino, old_dentry->d_name.name,
						old_dentry->d_name.len, new_record_type);
	if (IS_ERR(new_record)) {
		ret = PTR_ERR(new_record);
		goto remove_record1;
	}

	/* Full it just in case, writeback anyway will fill it again. */
	vdfs4_fill_cattree_record(old_inode, old_record);
	vdfs4_release_dirty_record((struct vdfs4_btree_gen_record *) old_record);
	vdfs4_fill_cattree_record(new_inode, new_record);
	vdfs4_release_dirty_record((struct vdfs4_btree_gen_record *) new_record);

	/* Remove Ex-record */
	ret = vdfs4_cattree_remove(tree, old_inode->i_ino,
				   old_dir->i_ino, old_dentry->d_name.name,
				   old_dentry->d_name.len,
				   VDFS4_I(old_inode)->record_type);
	if (ret)
		goto remove_record2;

	ret = vdfs4_cattree_remove(tree, new_inode->i_ino,
				   new_dir->i_ino, new_dentry->d_name.name,
				   new_dentry->d_name.len,
				   VDFS4_I(new_inode)->record_type);
	if (ret)
		goto remove_record3;

	if (!(is_vdfs4_inode_flag_set(old_inode, HARD_LINK))) {
		VDFS4_I(old_inode)->parent_id = new_dir->i_ino;
		kfree(VDFS4_I(old_inode)->name);
		VDFS4_I(old_inode)->name = new_saved_name;
	}

	if (!(is_vdfs4_inode_flag_set(new_inode, HARD_LINK))) {
		VDFS4_I(new_inode)->parent_id = old_dir->i_ino;
		kfree(VDFS4_I(new_inode)->name);
		VDFS4_I(new_inode)->name = old_saved_name;
	}

	vdfs4_cattree_w_unlock(sbi);

	old_inode->i_ctime = vdfs4_current_time(old_inode);
	mark_inode_dirty(old_inode);
	new_inode->i_ctime = vdfs4_current_time(new_inode);
	mark_inode_dirty(new_inode);

	vdfs4_assert_i_mutex(old_dir);
	old_dir->i_ctime = old_dir->i_mtime = vdfs4_current_time(old_dir);
	mark_inode_dirty(old_dir);

	vdfs4_assert_i_mutex(new_dir);
	new_dir->i_ctime = new_dir->i_mtime = vdfs4_current_time(new_dir);
	mark_inode_dirty(new_dir);

	vdfs4_stop_transaction(sbi);
	VT_FINISH(vt_data);
	return ret;

remove_record3:
	record = vdfs4_cattree_place_record(tree, old_inode->i_ino,
					    old_dir->i_ino, old_dentry->d_name.name,
					    old_dentry->d_name.len,
					    VDFS4_I(old_inode)->record_type);

	vdfs4_fill_cattree_record(old_inode, record);
	vdfs4_release_dirty_record((struct vdfs4_btree_gen_record *) record);

remove_record2:
	vdfs4_cattree_remove(tree, new_inode->i_ino,
			     old_dir->i_ino, old_dentry->d_name.name,
			     old_dentry->d_name.len, new_record_type);
remove_record1:
	vdfs4_cattree_remove(tree, old_inode->i_ino,
			     new_dir->i_ino, new_dentry->d_name.name,
			     new_dentry->d_name.len, old_record_type);
error:
	vdfs4_cattree_w_unlock(sbi);
	vdfs4_stop_transaction(sbi);
	kfree(old_saved_name);
	kfree(new_saved_name);
	VT_FINISH(vt_data);
	return ret;
}

static int vdfs4_rename2(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry,
			 unsigned int flags)
{
	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE))
		return -EINVAL;

	if (flags & RENAME_EXCHANGE)
		return vdfs4_cross_rename(old_dir, old_dentry,
					  new_dir, new_dentry);

	return vdfs4_rename(old_dir, old_dentry, new_dir, new_dentry);
}

/**
 * @brief			Add hardlink record .
 * @param [in]	cat_tree	Pointer to catalog tree
 * @param [in]	hlink_id	Hardlink id
 * @param [in]	par_ino_n	Parent inode number
 * @param [in]	file_mode	file mode (socket,block,char,normal...)
 * @param [in]	name		Name
 * @return			Returns error codes
 */
static int add_hlink_record(struct vdfs4_btree *cat_tree, ino_t ino_n,
		ino_t par_ino_n, umode_t file_mode, struct qstr *name)
{
	struct vdfs4_catalog_hlink_record *hlink_value;
	struct vdfs4_cattree_record *record;

	record = vdfs4_cattree_place_record(cat_tree, ino_n, par_ino_n,
			name->name, name->len, VDFS4_CATALOG_HLINK_RECORD);
	if (IS_ERR(record))
		return PTR_ERR(record);

	hlink_value = (struct vdfs4_catalog_hlink_record *)record->val;
	hlink_value->file_mode = cpu_to_le16(file_mode);

	vdfs4_release_dirty_record((struct vdfs4_btree_gen_record *) record);
	return 0;
}

/**
 * @brief       Transform record from regular file to hard link
 *              Resulting record length stays unchanged, but only a part of the
 *              record is used for real data
 * */
static int transform_into_hlink(struct inode *inode)
{
	struct vdfs4_sb_info *sbi = inode->i_sb->s_fs_info;
	struct vdfs4_cattree_record *record, *hlink;
	struct vdfs4_catalog_hlink_record *hlink_val;
	u8 record_type;
	int ret, val_len;

	/*
	 * Remove inode-link
	 */
	ret = vdfs4_cattree_remove_ilink(sbi->catalog_tree,
			inode->i_ino, VDFS4_I(inode)->parent_id,
			VDFS4_I(inode)->name,
			strlen(VDFS4_I(inode)->name));
	if (ret)
		goto out_ilink;

	ret = __get_record_type_on_mode(inode, &record_type);
	if (ret)
		goto out_hlink;

	/*
	 * Insert hard-link body
	 */
	hlink = vdfs4_cattree_place_record(sbi->catalog_tree,
			inode->i_ino, inode->i_ino, NULL, 0, record_type);
	ret = PTR_ERR(hlink);
	if (IS_ERR(hlink))
		goto out_hlink;

	record = vdfs4_cattree_find_inode(sbi->catalog_tree,
			inode->i_ino, VDFS4_I(inode)->parent_id,
			VDFS4_I(inode)->name,
			strlen(VDFS4_I(inode)->name),
			VDFS4_BNODE_MODE_RW);
	ret = PTR_ERR(record);
	if (IS_ERR(record))
		goto out_record;

	val_len = le16_to_cpu(record->key->gen_key.record_len) -
		  le16_to_cpu(record->key->gen_key.key_len);

	memcpy(hlink->val, record->val, (size_t)val_len);
	memset(record->val, 0, (size_t)val_len);
	record->key->record_type = VDFS4_CATALOG_HLINK_RECORD;
	hlink_val = record->val;
	hlink_val->file_mode = cpu_to_le16(inode->i_mode);

	VDFS4_I(inode)->parent_id = 0;
	kfree(VDFS4_I(inode)->name);
	VDFS4_I(inode)->name = NULL;
	set_vdfs4_inode_flag(inode, HARD_LINK);

	vdfs4_release_dirty_record((struct vdfs4_btree_gen_record *) hlink);
	vdfs4_release_dirty_record((struct vdfs4_btree_gen_record *) record);

	return 0;

out_record:
	/* FIXME ugly */
	vdfs4_release_record((struct vdfs4_btree_gen_record *) hlink);
	vdfs4_cattree_remove(sbi->catalog_tree, inode->i_ino, inode->i_ino,
			NULL, 0, VDFS4_I(inode)->record_type);
out_hlink:
	vdfs4_cattree_insert_ilink(sbi->catalog_tree, inode->i_ino,
			VDFS4_I(inode)->parent_id, VDFS4_I(inode)->name,
			strlen(VDFS4_I(inode)->name));
out_ilink:
	return ret;
}

/**
 * @brief			Create link.
 * @param [in]	old_dentry	Old dentry (source name for hard link)
 * @param [in]	dir		The inode dir pointer
 * @param [out]	dentry		Pointer to result dentry
 * @return			Returns error codes
 */
static int vdfs4_link(struct dentry *old_dentry, struct inode *dir,
	struct dentry *dentry)
{
	struct inode *inode = old_dentry->d_inode;
	struct vdfs4_sb_info *sbi = inode->i_sb->s_fs_info;
	int ret;

	VT_PREPARE_PARAM(vt_data);

	vdfs4_assert_i_mutex(inode);

	if (dentry->d_name.len > VDFS4_FILE_NAME_LEN)
		return -ENAMETOOLONG;

	if (inode->i_nlink >= VDFS4_LINK_MAX)
		return -EMLINK;

	VT_IOPS_START(vt_data, vdfs_trace_iops_link, dentry);
	vdfs4_start_transaction(sbi);
	vdfs4_cattree_w_lock(sbi);

	if (!is_vdfs4_inode_flag_set(inode, HARD_LINK)) {
		ret = transform_into_hlink(inode);
		if (ret)
			goto err_exit;
	}

	ret = add_hlink_record(sbi->catalog_tree, inode->i_ino, dir->i_ino,
			inode->i_mode, &dentry->d_name);
	if (ret)
		goto err_exit;

	VDFS4_DEBUG_MUTEX("cattree mutex w lock un");
	vdfs4_cattree_w_unlock(sbi);

	inode->i_ctime = vdfs4_current_time(inode);

	ihold(inode);
	d_instantiate(dentry, inode);
	inode_inc_link_count(inode);

	mark_inode_dirty(inode);

	vdfs4_assert_i_mutex(dir);
	dir->i_ctime = vdfs4_current_time(dir);
	dir->i_mtime = vdfs4_current_time(dir);
	dir->i_size++;
	mark_inode_dirty(dir);

	sbi->files_count++;
exit:
	vdfs4_stop_transaction(sbi);
	VT_FINISH(vt_data);
	return ret;
err_exit:
	vdfs4_cattree_w_unlock(sbi);
	goto exit;
}

/**
 * @brief			Make node.
 * @param [in,out]	dir		Directory where node will be created
 * @param [in]		dentry	Created dentry
 * @param [in]		mode	Mode for file
 * @param [in]		rdev	Device
 * @return			Returns 0 on success, errno on failure
 */
static int vdfs4_mknod(struct inode *dir, struct dentry *dentry,
			umode_t mode, dev_t rdev)
{
	struct inode *created_ino;
	int ret;

	VT_PREPARE_PARAM(vt_data);

	VT_IOPS_START(vt_data, vdfs_trace_iops_mknod, dentry);
	vdfs4_start_transaction(VDFS4_SB(dir->i_sb));

	if (!new_valid_dev(rdev)) {
		ret = -EINVAL;
		goto exit;
	}

	ret = vdfs4_create(dir, dentry, mode, NULL);
	if (ret)
		goto exit;

	created_ino = dentry->d_inode;
	init_special_inode(created_ino, created_ino->i_mode, rdev);
	mark_inode_dirty(created_ino);
exit:
	vdfs4_stop_transaction(VDFS4_SB(dir->i_sb));
	VT_FINISH(vt_data);
	return ret;
}

/**
 * @brief			Make symlink.
 * @param [in,out]	dir		Directory where node will be created
 * @param [in]		dentry	Created dentry
 * @param [in]		symname Symbolic link name
 * @return			Returns 0 on success, errno on failure
 */
static int vdfs4_symlink(struct inode *dir, struct dentry *dentry,
	const char *symname)
{
	int ret;
	struct inode *created_ino;
	int blocks_allocated = 1;
	int len = (int)strlen(symname);

	VT_PREPARE_PARAM(vt_data);

	if ((len > VDFS4_FULL_PATH_LEN) ||
			(dentry->d_name.len > VDFS4_FILE_NAME_LEN))
		return -ENAMETOOLONG;

	VT_IOPS_START(vt_data, vdfs_trace_iops_symlink, dentry);
	vdfs4_start_transaction(VDFS4_SB(dir->i_sb));

	ret = vdfs4_reserve_space(dir, blocks_allocated);
	if (ret)
		goto err_reserve;

	ret = vdfs4_create(dir, dentry, S_IFLNK | S_IRWXUGO, NULL);
	if (ret)
		goto err_create;
	created_ino = dentry->d_inode;

	mutex_lock(&VDFS4_I(created_ino)->truncate_mutex);
	ret = vdfs4_runtime_extent_add(0, 0,
			&VDFS4_I(created_ino)->runtime_extents);
	if (ret)
		goto err_ext_add;
	mutex_unlock(&VDFS4_I(created_ino)->truncate_mutex);

	ret = page_symlink(created_ino, symname, ++len);
	if (ret)
		goto err_symlink;

	vdfs4_stop_transaction(VDFS4_SB(dir->i_sb));
	VT_FINISH(vt_data);
	return 0;
err_symlink:
	/* There is no fail path in page_symlink() that clears
	 * runtime_extents but for safety sake lets count them */
	mutex_lock(&VDFS4_I(created_ino)->truncate_mutex);
	blocks_allocated = vdfs4_truncate_runtime_blocks(0,
			&VDFS4_I(created_ino)->runtime_extents);
err_ext_add:
	vdfs4_free_reserved_space(dir, blocks_allocated);
	mutex_unlock(&VDFS4_I(created_ino)->truncate_mutex);
	vdfs4_unlink(dir, dentry);
	vdfs4_stop_transaction(VDFS4_SB(dir->i_sb));
	VT_FINISH(vt_data);
	return ret;
err_create:
	vdfs4_free_reserved_space(dir, blocks_allocated);
err_reserve:
	vdfs4_stop_transaction(VDFS4_SB(dir->i_sb));
	VT_FINISH(vt_data);
	return ret;
}

/**
 * The eMMCFS address space operations.
 */
const struct address_space_operations vdfs4_aops = {
	.readpage	= vdfs4_readpage,
	.readpages	= vdfs4_readpages,
	.writepage	= vdfs4_writepage,
	.writepages	= vdfs4_writepages,
	.write_begin	= vdfs4_write_begin,
	.write_end	= vdfs4_write_end,
	.bmap		= vdfs4_bmap,
	.direct_IO	= vdfs4_direct_IO,
	.migratepage	= buffer_migrate_page,
	.releasepage = vdfs4_releasepage,
/*	.set_page_dirty = __set_page_dirty_buffers,*/

};

const struct address_space_operations vdfs4_tuned_aops = {
	.readpage	= vdfs4_readpage_tuned_sw_retry,
};


#ifdef CONFIG_VDFS4_HW_DECOMPRESS_SUPPORT
const struct address_space_operations vdfs4_tuned_aops_hw = {
	.readpage	= vdfs4_readpage_tuned_hw_retry,
};
#endif /* VDFS4_HW_DECOMPRESS_SUPPORT */

static int vdfs4_fail_migrate_page(struct address_space *mapping,
			struct page *newpage, struct page *page,
				enum migrate_mode mode)
{
	return -EIO;
}

/**
 * Special aops for meta inode.
 */
static const struct address_space_operations vdfs4_aops_special = {
	.readpage	= vdfs4_readpage_special,
	.readpages	= vdfs4_readpages_special,
	.writepages	= vdfs4_writepages_special,
	.write_begin	= vdfs4_write_begin,
	.write_end	= vdfs4_write_end,
	.bmap		= vdfs4_bmap,
	.direct_IO	= vdfs4_direct_IO,
	.migratepage	= vdfs4_fail_migrate_page,
/*	.set_page_dirty = __set_page_dirty_buffers,*/
};

/**
 * The eMMCFS directory inode operations.
 */
static const struct inode_operations vdfs4_dir_inode_operations = {
	/* d.voytik-TODO-19-01-2012-11-15-00:
	 * [vdfs4_dir_inode_ops] add to vdfs4_dir_inode_operations
	 * necessary methods */
	.create		= vdfs4_create,
	.symlink	= vdfs4_symlink,
	.lookup		= vdfs4_lookup,
	.link		= vdfs4_link,
	.unlink		= vdfs4_unlink,
	.mkdir		= vdfs4_mkdir,
	.rmdir		= vdfs4_rmdir,
	.mknod		= vdfs4_mknod,
	.rename2	= vdfs4_rename2,
	.setattr	= vdfs4_setattr,

	.setxattr	= vdfs4_setxattr,
	.getxattr	= vdfs4_getxattr,
	.removexattr	= vdfs4_removexattr,
	.listxattr	= vdfs4_listxattr,
#ifdef CONFIG_VDFS4_POSIX_ACL
	.get_acl	= vdfs4_get_acl,
	.set_acl	= vdfs4_set_acl,
#endif
};

/**
 * The eMMCFS symlink inode operations.
 */
static const struct inode_operations vdfs4_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
	.setattr	= vdfs4_setattr,

	.setxattr	= vdfs4_setxattr,
	.getxattr	= vdfs4_getxattr,
	.removexattr	= vdfs4_removexattr,
	.listxattr	= vdfs4_listxattr,
};


/**
 * The eMMCFS directory operations.
 */
const struct file_operations vdfs4_dir_operations = {
	/* d.voytik-TODO-19-01-2012-11-16-00:
	 * [vdfs4_dir_ops] add to vdfs4_dir_operations necessary methods */
	.llseek		= vdfs4_llseek_dir,
	.read		= generic_read_dir,
	.iterate	= vdfs4_iterate,
	.release	= vdfs4_release_dir,
	.unlocked_ioctl = vdfs4_dir_ioctl,
	.fsync		= vdfs4_dir_fsync,
};


/**
 * This writes unwitten data and metadata for one file ... and everything else.
 * It's impossible to flush single inode without flushing all changes in trees.
 */
static int vdfs4_file_fsync(struct file *file, loff_t start, loff_t end,
		int datasync)
{
	struct inode *inode = file->f_mapping->host;
	struct super_block *sb = inode->i_sb;
	int ret;

	VT_PREPARE_PARAM(vt_data);

	trace_vdfs4_file_fsync_enter(file, start, end, datasync);
	VT_FOPS_START(vt_data, vdfs_trace_fops_fsync,
		      inode->i_sb->s_bdev->bd_part,
		      file->f_path.dentry->d_inode, file);

	ret = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (ret)
		goto exit;

	if (!datasync || (inode->i_state & I_DIRTY_DATASYNC)) {
		down_read(&sb->s_umount);
		ret = sync_filesystem(sb);
		up_read(&sb->s_umount);
	}

	trace_vdfs4_file_fsync_exit(file, ret);
exit:
	VT_FINISH(vt_data);
	return ret;
}

static long vdfs4_fallocate(struct file *file, int mode,
			    loff_t offset, loff_t len)
{
	long ret = 0;
	struct inode *inode = file_inode(file);
	struct vdfs4_inode_info *i_info = VDFS4_I(inode);
	struct vdfs4_sb_info *sbi = inode->i_sb->s_fs_info;
	loff_t new_size = offset + len;
	sector_t offset_alloc_hint = 0;
	unsigned int i=0, lblk, max_blocks;
	struct vdfs4_extent_info extent;

	VDFS4_INFO("fallocate - filename:%s,mode:0x%08X,offset:%llu,len:%llu\n",
		   file->f_path.dentry->d_iname, mode, offset, len);
	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	/* vdfs fallocate support only KEEP_SIZE mode */
	if (mode & ~(FALLOC_FL_KEEP_SIZE))
		return -EOPNOTSUPP;

	if (new_size <= i_size_read(inode))
		return 0;

	if (!(mode & FALLOC_FL_KEEP_SIZE)) {
	    ret = inode_newsize_ok(inode, new_size);
		if (ret)
			return ret;
	}

	lblk = offset >> sbi->block_size_shift;
	max_blocks = (ALIGN(new_size, sbi->block_size)
		      >> sbi->block_size_shift) - lblk;

	mutex_lock(&inode->i_mutex);
	vdfs4_start_transaction(sbi);

	if (!max_blocks)
		goto out;

	mutex_lock(&i_info->truncate_mutex);

	if (vdfs4_check_meta_space(sbi))
		goto err_reserve;

	for (; i < max_blocks; i++) {
		memset( &extent, 0x00, sizeof(struct vdfs4_extent_info));
		ret = vdfs4_get_iblock_extent(inode, lblk+i,
					      &extent, &offset_alloc_hint);
		if (ret)
			goto err_reserve;
		if (extent.first_block)
			continue;
		ret = vdfs4_reserve_space(inode, 1);
		if (ret)
			goto err_reserve;
		ret = vdfs4_runtime_extent_add(lblk+i, offset_alloc_hint,
					       &i_info->runtime_extents);
		if (ret) {
			vdfs4_free_reserved_space(inode, 1);
			goto err_reserve;
		}
	}
	mutex_unlock(&i_info->truncate_mutex);
	ret = vdfs4_allocate_space(i_info, 1);
	if (ret)
		goto err_allocate;

out:
	inode->i_ctime = vdfs4_current_time(inode);
	if (!(mode & FALLOC_FL_KEEP_SIZE)) {
		i_size_write(inode, new_size);
		inode->i_mtime = vdfs4_current_time(inode);
	}
	mark_inode_dirty(inode);

	vdfs4_stop_transaction(sbi);
	mutex_unlock(&inode->i_mutex);
	return ret;

err_allocate:
	mutex_lock(&i_info->truncate_mutex);
err_reserve:
	while (i-- > 0) {
		u32 exist;
		exist = vdfs4_runtime_extent_exists(lblk + i,
						    &i_info->runtime_extents);
		if (!exist)
			continue;
		if (vdfs4_runtime_extent_del(lblk + i,
					     &i_info->runtime_extents)) {
			VDFS4_ERR("Failed to delete runtime extent"
				  "(rtn:%ld,iblk:%u)", ret, lblk+i);
			continue;
		}
		vdfs4_free_reserved_space(inode, 1);
	}
	mutex_unlock(&i_info->truncate_mutex);
	vdfs4_stop_transaction(sbi);
	mutex_unlock(&inode->i_mutex);
	if (ret == -ENOSPC)
		VDFS4_WARNING("fallocate: len over avail size(%s:%llu,%llu)\n",
		      i_info->name, len,
		      (sbi->free_blocks_count << sbi->block_size_shift));
	else
		VDFS4_ERR("fallocate: failed(%ld)(%s,%llu,%llu)",
			  ret, i_info->name, offset, len);
	return ret;
}

#define MAX(a, b) ((a) > (b) ? (a) : (b))

/**
 * @brief		Calculation of writing position in a case when data is
 *			appending to a target file
 * @param [in]	iocb	Struct describing writing file
 * @param [in]	pos	Position to write from
 * @return		Returns the writing position
 */
static inline loff_t get_real_writing_position(struct kiocb *iocb, loff_t pos)
{
	loff_t write_pos = 0;

	if (iocb->ki_filp->f_flags & O_APPEND)
		write_pos = i_size_read(INODE(iocb));

	write_pos = MAX(write_pos, pos);
	iocb->ki_pos = write_pos;
	return write_pos;
}

/**
	iocb->ki_pos = write_pos;
 * @brief		VDFS4 function for aio write
 * @param [in]	iocb	Struct describing writing file
 * @param [in]	iov_iter	Struct for writing data
 * @return		Returns number of bytes written or an error code
 */
static ssize_t vdfs4_file_write_iter(struct kiocb *iocb,
				     struct iov_iter *iov_iter)
{
	ssize_t ret = 0;
	struct inode *inode = INODE(iocb);

	VT_PREPARE_PARAM(vt_data);
	trace_vdfs4_file_write_iter(iocb, iov_iter);
	VT_FOPS_RW_START(vt_data, vdfs_trace_fops_write_iter,
			 iocb->ki_filp->f_inode->i_sb->s_bdev->bd_part,
			 inode, iocb->ki_filp,
			 iocb->ki_pos, iov_iter->count);
	ret = generic_file_write_iter(iocb, iov_iter);
	VT_FINISH(vt_data);
	return ret;
}

/**
 * @brief		VDFS4 function for read iter
 * @param [in]	iocb	Struct describing reading file
 * @param [in]	iov_iter	Struct for read data
 * @return		Returns number of bytes read or an error code
 */
static ssize_t vdfs4_file_read_iter(struct kiocb *iocb,
				    struct iov_iter *iov_iter)
{
	struct inode *inode = INODE(iocb);
	ssize_t ret;

	VT_PREPARE_PARAM(vt_data);

#ifdef CONFIG_VDFS4_AUTHENTICATION
	if (current_reads_only_authenticated(inode, false)) {
#ifdef CONFIG_VDFS4_DEBUG_AUTHENTICAION
		if (!VDFS4_I(inode)->informed_about_fail_read)
#endif
			VDFS4_ERR("read is not permited: %lu:%s",
				inode->i_ino, VDFS4_I(inode)->name);
#ifdef CONFIG_VDFS4_DEBUG_AUTHENTICAION
		VDFS4_I(inode)->informed_about_fail_read = 1;
#else
		return -EPERM;
#endif
	}
#endif

	trace_vdfs4_file_read_iter(iocb, iov_iter);
	VT_START(vt_data);

	ret = generic_file_read_iter(iocb, iov_iter);

#ifdef CONFIG_VDFS4_DEBUG
	if (ret < 0 && ret != -EIOCBQUEUED && ret != -EINTR)
		VDFS4_DEBUG_TMP("err = %d, ino#%lu name=%s",
			(int)ret, inode->i_ino, VDFS4_I(inode)->name);
#endif
	VT_FOPS_RW_FINISH(vt_data, vdfs_trace_fops_read_iter,
			 iocb->ki_filp->f_inode->i_sb->s_bdev->bd_part,
			 inode, iocb->ki_filp,
			 iocb->ki_pos - ((ret >= 0) ? ret : 0),
			 (ret >= 0) ? ret : 0);
	return ret;
}

static ssize_t vdfs4_file_splice_read(struct file *in, loff_t *ppos,
		struct pipe_inode_info *pipe, size_t len, unsigned int flags)
{
	ssize_t ret;

	VT_PREPARE_PARAM(vt_data);
	trace_vdfs4_file_splice_read(in, ppos, pipe, len, flags);

#ifdef CONFIG_VDFS4_AUTHENTICATION
	if (current_reads_only_authenticated(in->f_mapping->host, false)) {
		VDFS4_ERR("read is not permited:  %lu:%s",
			  in->f_mapping->host->i_ino,
			  VDFS4_I(in->f_mapping->host)->name);
#ifndef CONFIG_VDFS4_DEBUG_AUTHENTICAION
		return -EPERM;
#endif
	}
#endif
	VT_START(vt_data);
	ret = generic_file_splice_read(in, ppos, pipe, len, flags);
	VT_FOPS_RW_FINISH(vt_data, vdfs_trace_fops_splice_read,
			 in->f_inode->i_sb->s_bdev->bd_part,
			 in->f_path.dentry->d_inode, in,
			 *ppos - ((ret >= 0) ? ret : 0),
			 (ret >= 0) ? ret : 0);
	return ret;
}


#ifdef CONFIG_VDFS4_AUTHENTICATION
static int check_execution_available(struct inode *inode,
		struct vm_area_struct *vma)
{
	if (!is_sbi_flag_set(VDFS4_SB(inode->i_sb), VOLUME_AUTH))
		return 0;

	if (!is_vdfs4_inode_flag_set(inode, VDFS4_AUTH_FILE)) {
		if (vma->vm_flags & VM_EXEC) {
#ifdef CONFIG_VDFS4_DEBUG_AUTHENTICAION
			if (!VDFS4_I(inode)->informed_about_fail_read) {
				VDFS4_I(inode)->informed_about_fail_read = 1;
				VDFS4_SECURITY_ERR("Security violation detected [task:%s(%d)]."
						" Try to execute non-auth file %s(%lu).\n"
						" As debug/perf image is used, the execution will be PERMITTED.\n",
						current->comm,
						current->pid,
						VDFS4_I(inode)->name,
						inode->i_ino);
			}
		}
#else
			VDFS4_SECURITY_ERR("Security violation detected [task:%s(%d)]."
					" Try to execute non-auth file %s(%lu).\n",
					current->comm,
					current->pid,
					VDFS4_I(inode)->name,
					inode->i_ino);
			return -EPERM;
		}
		/* Forbid remmaping to executable */
		vma->vm_flags &= (unsigned long)~VM_MAYEXEC;
#endif
	}

	if (current_reads_only_authenticated(inode, true))
#ifndef CONFIG_VDFS4_DEBUG_AUTHENTICAION
		return -EPERM;
#else
		return 0;
#endif

	return 0;
}
#endif

static int vdfs4_file_mmap(struct file *file, struct vm_area_struct *vma)
{
#ifdef CONFIG_VDFS4_AUTHENTICATION
	struct inode *inode = file->f_path.dentry->d_inode;
	int ret;
#endif

	trace_vdfs4_file_mmap(file, vma);
#ifdef CONFIG_VDFS4_AUTHENTICATION
	ret = check_execution_available(inode, vma);
	if (ret)
		return ret;
#endif
	return generic_file_mmap(file, vma);
}

static int vdfs4_file_readonly_mmap(struct file *file,
		struct vm_area_struct *vma)
{
#ifdef CONFIG_VDFS4_AUTHENTICATION
	struct inode *inode = file->f_path.dentry->d_inode;
	int ret = check_execution_available(inode, vma);

	if (ret)
		return ret;
#endif
	return generic_file_readonly_mmap(file, vma);
}


/**
 * The eMMCFS file operations.
 */
static const struct file_operations vdfs4_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= vdfs4_file_read_iter,
	.write_iter	= vdfs4_file_write_iter,
	.mmap		= vdfs4_file_mmap,
	.splice_read	= vdfs4_file_splice_read,
	.open		= vdfs4_file_open,
	.release	= vdfs4_file_release,
	.fsync		= vdfs4_file_fsync,
	.unlocked_ioctl = vdfs4_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= vdfs4_compat_ioctl,
#endif
	.fallocate	= vdfs4_fallocate,
};

static const struct file_operations vdfs4_tuned_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= vdfs4_file_read_iter,
	.mmap		= vdfs4_file_readonly_mmap,
	.splice_read	= vdfs4_file_splice_read,
	.open		= vdfs4_file_open,
	.release	= vdfs4_file_release,
	.fsync		= vdfs4_file_fsync,
	.unlocked_ioctl = vdfs4_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= vdfs4_compat_ioctl,
#endif
};
const struct inode_operations vdfs4_special_inode_operations = {
	.setattr	= vdfs4_setattr,
	.setxattr	= vdfs4_setxattr,
	.getxattr	= vdfs4_getxattr,
	.listxattr	= vdfs4_listxattr,
	.removexattr	= vdfs4_removexattr,
#ifdef CONFIG_VDFS4_POSIX_ACL
	.get_acl	= vdfs4_get_acl,
	.set_acl	= vdfs4_set_acl,
#endif
};
/**
 * The eMMCFS files inode operations.
 */
static const struct inode_operations vdfs4_file_inode_operations = {
	.setattr	= vdfs4_setattr,
	.setxattr	= vdfs4_setxattr,
	.getxattr	= vdfs4_getxattr,
	.removexattr	= vdfs4_removexattr,
	.listxattr	= vdfs4_listxattr,
#ifdef CONFIG_VDFS4_POSIX_ACL
	.get_acl	= vdfs4_get_acl,
	.set_acl	= vdfs4_set_acl,
#endif
};

static int vdfs4_fill_inode(struct inode *inode,
		struct vdfs4_catalog_folder_record *folder_val)
{
	int ret = 0;

	VDFS4_I(inode)->flags = le32_to_cpu(folder_val->flags);

	/*
	 * Force to clear AUTH_FILE flag. It should be set only from driver.
	 */
	clear_vdfs4_inode_flag(inode, VDFS4_AUTH_FILE);

	vdfs4_set_vfs_inode_flags(inode);

	atomic_set(&(VDFS4_I(inode)->open_count), 0);

	inode->i_mode = le16_to_cpu(folder_val->file_mode);
	i_uid_write(inode, le32_to_cpu(folder_val->uid));
	i_gid_write(inode, le32_to_cpu(folder_val->gid));
	set_nlink(inode, (unsigned int)le64_to_cpu(folder_val->links_count));
	inode->i_generation = le32_to_cpu(folder_val->generation);
	VDFS4_I(inode)->next_orphan_id =
		le64_to_cpu(folder_val->next_orphan_id);

	inode->i_mtime = vdfs4_decode_time(folder_val->modification_time);
	inode->i_atime = vdfs4_decode_time(folder_val->access_time);
	inode->i_ctime = vdfs4_decode_time(folder_val->creation_time);

	if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &vdfs4_symlink_inode_operations;
		inode->i_mapping->a_ops = &vdfs4_aops;
		inode->i_fop = &vdfs4_file_operations;

	} else if (S_ISREG(inode->i_mode)) {
		inode->i_op = &vdfs4_file_inode_operations;
		inode->i_mapping->a_ops = &vdfs4_aops;
		inode->i_fop = &vdfs4_file_operations;

	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_size = (loff_t)le64_to_cpu(
				folder_val->total_items_count);
		inode->i_op = &vdfs4_dir_inode_operations;
		inode->i_fop = &vdfs4_dir_operations;
	} else if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) ||
			S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
		inode->i_mapping->a_ops = &vdfs4_aops;
		init_special_inode(inode, inode->i_mode,
			(dev_t)le64_to_cpu(folder_val->total_items_count));
		inode->i_op = &vdfs4_special_inode_operations;
	} else {
		/* UNKNOWN object type*/
		ret = -EINVAL;
	}

	return ret;
}

static u32 calc_compext_table_crc(void *data, int offset, size_t table_len)
{
	struct vdfs4_comp_file_descr *descr = NULL;
	void *tmp_descr;
	u32 crc = 0, stored_crc;

	tmp_descr = ((char *)data + offset + table_len - sizeof(*descr));
	descr = tmp_descr;
	stored_crc = descr->crc;
	descr->crc = 0;
	crc = crc32(crc, (char *)data + offset, table_len);
	descr->crc = stored_crc;
	return crc;
}

int vdfs4_prepare_compressed_file_inode(struct vdfs4_inode_info *inode_i)
{
	int ret = 0;
	struct vdfs4_comp_file_descr descr;
	struct inode *inode = &inode_i->vfs_inode;

	inode_i->fbc = kzalloc(sizeof(struct vdfs4_file_based_info), GFP_NOFS);
	if (!inode_i->fbc)
		return -ENOMEM;

	truncate_inode_pages(inode->i_mapping, 0);
	inode_i->fbc->comp_size = inode_i->vfs_inode.i_size;

	ret = get_file_descriptor(inode_i, &descr);
	if (ret)
		goto ERROR_FBC;

	switch (descr.magic[0]) {
	case VDFS4_COMPR_DESCR_START:
		break;
	case VDFS4_MD5_AUTH:
	case VDFS4_SHA1_AUTH:
	case VDFS4_SHA256_AUTH:
#ifdef CONFIG_VDFS4_AUTHENTICATION
		set_vdfs4_inode_flag(inode, VDFS4_AUTH_FILE);
#endif
		break;
	default:
		ret = -EINVAL;
		goto ERROR_FBC;
	}

	if (inode_i->fbc->comp_size <= (PAGE_SIZE*4))
		inode_i->fbc->force_path = FORCE_SW;
	else
		inode_i->fbc->force_path = FORCE_NONE;

	inode->i_size = (long long)le64_to_cpu(descr.unpacked_size);
	inode->i_fop = &vdfs4_tuned_file_operations;
	inode_i->fbc->sign_type = descr.sign_type;
	/* deny_write_access() */
	if (S_ISREG(inode->i_mode))
		atomic_set(&inode->i_writecount, -1);

	return ret;

ERROR_FBC:
	kfree(inode_i->fbc);
	inode_i->fbc = NULL;
	return ret;
}

static int vdfs4_init_hw_decompression(struct vdfs4_inode_info *inode_i)
{
#ifdef CONFIG_VDFS4_HW_DECOMPRESS_SUPPORT
	const struct hw_capability hw_cap = get_hw_capability();

	if (inode_i->fbc->log_chunk_size > hw_cap.max_size ||
			inode_i->fbc->log_chunk_size < hw_cap.min_size)
		return -EINVAL;

	inode_i->fbc->hw_fn = vdfs_get_hwdec_fn(inode_i);
	if (!inode_i->fbc->hw_fn)
		return -ENOTSUPP;

	inode_i->vfs_inode.i_mapping->a_ops = &vdfs4_tuned_aops_hw;
	return 0;
#else
	return -ENOTSUPP;
#endif
}

#ifdef CONFIG_VDFS4_SQUEEZE
static int vdfs4_init_squeeze_inode(struct vdfs4_inode_info *inode_i,
		struct vdfs4_comp_file_descr *descr, void *data)
{
	unsigned i, extents_num = le16_to_cpu(descr->extents_num);
	struct vdfs4_comp_extent *ext = (struct vdfs4_comp_extent *)data;

	inode_i->sci = kmalloc(extents_num *
					sizeof(struct vdfs4_squeeze_chunk_info), GFP_NOFS);
	if (!inode_i->sci)
		return -ENOMEM;

	spin_lock(&inode_i->to_read_lock);
	for (i = 0; i < extents_num; i++) {
		inode_i->sci[i].order = le16_to_cpu(ext[i].profiled_prio);
		if (ext[i].profiled_prio != VDFS4_SQUEEZE_PRIO_NON_PROFILED)
			list_add_tail(&inode_i->sci[i].list, &inode_i->to_read_list);
	}
	spin_unlock(&inode_i->to_read_lock);
	return 0;
}
#endif

int vdfs4_init_file_decompression(struct vdfs4_inode_info *inode_i, int debug)
{
	struct inode *inode = &inode_i->vfs_inode;
	struct page **pages;
	struct vdfs4_comp_file_descr descr;
	int ret = 0, descr_len, sign_len;
	pgoff_t start_idx;
	loff_t start_offset, unpacked_size;
	enum compr_type compr_type;
	unsigned long table_size_bytes;
	u32 crc = 0;
	unsigned extents_num;
	unsigned int pages_num, i;
	void *data = NULL;

	ret = get_file_descriptor(inode_i, &descr);
	if (ret)
		return ret;

	descr_len = get_file_descr_length(&descr);
	if (descr_len < 0) {
		VDFS4_BUG(VDFS4_SB(inode->i_sb));
		return -EINVAL;
	}

	compr_type = get_comprtype_by_descr(&descr);

	switch (compr_type) {
	case VDFS4_COMPR_ZLIB:
		inode_i->fbc->decomp_fn = vdfs4_unpack_chunk_zlib;
		break;
	case VDFS4_COMPR_GZIP:
		inode_i->fbc->decomp_fn = vdfs4_unpack_chunk_gzip;
		break;
	case VDFS4_COMPR_LZO:
		inode_i->fbc->decomp_fn = vdfs4_unpack_chunk_lzo;
		break;
	default:
		if (!debug)
			return -EOPNOTSUPP;
		return compr_type;
	}

	inode_i->fbc->compr_type = compr_type;
	extents_num = le16_to_cpu(descr.extents_num);
	unpacked_size = (long long)le64_to_cpu(descr.unpacked_size);
	table_size_bytes = extents_num * sizeof(struct vdfs4_comp_extent) +
		descr_len;
	sign_len = get_sign_length(descr.sign_type);

	if (sign_len < 0)
		return -EOPNOTSUPP;

	switch (descr.magic[0]) {
	case VDFS4_COMPR_DESCR_START:
		inode_i->fbc->hash_type = VDFS4_HASH_UNDEF;
		break;
	case VDFS4_MD5_AUTH:
		table_size_bytes += (unsigned long)VDFS4_MD5_HASH_LEN *
			(extents_num + 1lu) + sign_len;
#ifdef CONFIG_VDFS4_AUTHENTICATION
		if (is_sbi_flag_set(VDFS4_SB(inode->i_sb), VOLUME_AUTH))
			inode_i->fbc->hash_fn = calculate_sw_hash_md5;
#endif
		inode_i->fbc->hash_type = VDFS4_HASH_MD5;
		inode_i->fbc->hash_len = VDFS4_MD5_HASH_LEN;
		break;
	case VDFS4_SHA1_AUTH:
		table_size_bytes += (unsigned long)VDFS4_SHA1_HASH_LEN *
			(extents_num + 1lu) + sign_len;
#ifdef CONFIG_VDFS4_AUTHENTICATION
		if (is_sbi_flag_set(VDFS4_SB(inode->i_sb), VOLUME_AUTH))
			inode_i->fbc->hash_fn = calculate_sw_hash_sha1;
#endif
		inode_i->fbc->hash_type = VDFS4_HASH_SHA1;
		inode_i->fbc->hash_len = VDFS4_SHA1_HASH_LEN;
		break;
	case VDFS4_SHA256_AUTH:
		table_size_bytes += (unsigned long)VDFS4_SHA256_HASH_LEN *
			(extents_num + 1lu) + sign_len;
#ifdef CONFIG_VDFS4_AUTHENTICATION
		if (is_sbi_flag_set(VDFS4_SB(inode->i_sb), VOLUME_AUTH))
			inode_i->fbc->hash_fn = calculate_sw_hash_sha256;
#endif
		inode_i->fbc->hash_type = VDFS4_HASH_SHA256;
		inode_i->fbc->hash_len = VDFS4_SHA256_HASH_LEN;
		break;
	default:
		if (!debug)
			return -EOPNOTSUPP;
		return (int)descr.magic[0];
	}

	start_idx = (unsigned long int)((inode_i->fbc->comp_size -
		table_size_bytes) >> PAGE_CACHE_SHIFT);
	start_offset = inode_i->fbc->comp_size - table_size_bytes;
	pages_num = (unsigned int)(((inode_i->fbc->comp_size +
			PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT) - start_idx);

	/* Now we can now how many pages do we need, read the rest of them */
	pages = kmalloc(pages_num * sizeof(*pages), GFP_NOFS);
	if (!pages)
		return -ENOMEM;
	ret = vdfs4_read_comp_pages(inode, start_idx, (int)pages_num, pages,
				VDFS4_FBASED_READ_M);
	if (ret) {
		kfree(pages);
		return ret;
	}

	data = vdfs4_vmap(pages, (unsigned int)pages_num, VM_MAP, PAGE_KERNEL);
	if (!data) {
		kfree(pages);
		return -ENOMEM;
	}

	crc = calc_compext_table_crc(data, start_offset & (PAGE_SIZE - 1),
			table_size_bytes);
	if (crc != le32_to_cpu(descr.crc)) {
		struct vdfs4_sb_info *sbi = VDFS4_SB(inode_i->vfs_inode.i_sb);

		VDFS4_ERR("File based decompression crc mismatch: %s",
				inode_i->name);
		VDFS4_MDUMP("Original crc:", &descr.crc, sizeof(descr.crc));
		VDFS4_MDUMP("Calculated crc:", &crc, sizeof(crc));
#ifdef VDFS4_DEBUG_DUMP
		mutex_lock(&sbi->dump_meta);
		VDFS4_MDUMP("", (char *)data + (start_offset & (PAGE_SIZE - 1)),
				table_size_bytes);
		mutex_unlock(&sbi->dump_meta);
#endif
		vdfs4_print_volume_verification(sbi);
		ret = -EINVAL;
		goto out;
	}
	inode_i->fbc->comp_table_start_offset = start_offset;
	inode_i->fbc->comp_extents_n = (__u32)extents_num;
	inode_i->fbc->log_chunk_size =
					(size_t)le32_to_cpu(descr.log_chunk_size);

	if (inode_i->fbc->hash_fn) {
		ret = vdfs4_verify_file_signature(inode_i, descr.sign_type, data);
		if (ret)
			goto out;
		ret = vdfs4_check_hash_meta(inode_i, &descr);
		if (ret)
			goto out;
		/* Note : it is already set in lookup sequence */
		set_vdfs4_inode_flag(inode, VDFS4_AUTH_FILE);
	}

	inode->i_mapping->a_ops = &vdfs4_tuned_aops;
	vdfs4_init_hw_decompression(inode_i);

#ifdef CONFIG_VDFS4_SQUEEZE
	if (is_vdfs4_inode_flag_set(inode, VDFS4_PROFILED_FILE)) {
		ret = vdfs4_init_squeeze_inode(inode_i, &descr,
				data + (start_offset & (PAGE_SIZE - 1)));
		if (ret)
			goto out;
	}
#endif

out:
	vunmap(data);

	for (i = 0; i < pages_num; i++) {
		if (ret) {
			lock_page(pages[i]);
			ClearPageUptodate(pages[i]);
			ClearPageChecked(pages[i]);
			page_cache_release(pages[i]);
			unlock_page(pages[i]);

		} else {
			mark_page_accessed(pages[i]);
			page_cache_release(pages[i]);
		}
	}

	kfree(pages);
	return ret;
}

int vdfs4_disable_file_decompression(struct vdfs4_inode_info *inode_i)
{
	struct inode *inode = &inode_i->vfs_inode;
	struct vdfs4_file_based_info *fbc = inode_i->fbc;

	if (!fbc)
		return 0;

	inode_i->fbc = NULL;
	truncate_inode_pages(inode->i_mapping, 0);
	inode->i_size = fbc->comp_size;
	inode->i_mapping->a_ops = &vdfs4_aops;
	inode->i_fop = &vdfs4_file_operations;
	kfree(fbc);

	if (S_ISREG(inode->i_mode))
		atomic_set(&inode->i_writecount, 0);

	return 0;
}

#define FREEING_INODE	(1 << 31)
int vdfs4_inode_check(struct inode *inode, void *data)
{
	if (inode->i_ino != *(__u64 *)data)
		return 0;

	if (inode->i_state & I_FREEING) {
		*(__u64 *)data |= FREEING_INODE;
		return 0;
	}

	return 1;
}

int vdfs4_inode_set(struct inode *inode, void *data)
{
	__u64 ino = *(__u64*)data;

	if (ino & FREEING_INODE)
		return 1;
	else
		inode->i_ino = ino;

	return 0;
}

struct inode *vdfs4_get_inode_from_record(struct vdfs4_cattree_record *record,
		struct inode *parent)
{
	struct vdfs4_btree *tree;
	struct vdfs4_sb_info *sbi;
	struct vdfs4_catalog_folder_record *folder_rec = NULL;
	struct vdfs4_catalog_file_record *file_rec = NULL;
	struct vdfs4_cattree_record *hlink_rec = NULL;
	struct inode *inode;
	int ret = 0;
	__u64 ino;

	if (IS_ERR(record) || !record)
		return ERR_PTR(-EFAULT);

	tree = VDFS4_BTREE_REC_I((void *) record)->rec_pos.bnode->host;
	sbi = tree->sbi;

	ino = le64_to_cpu(record->key->object_id);
	if (tree->btree_type == VDFS4_BTREE_INST_CATALOG)
		ino += tree->start_ino;

	if (parent)
		inode = iget5_locked(sbi->sb, (unsigned long)ino, vdfs4_inode_check,
				vdfs4_inode_set, &ino);
	else
		inode = iget_locked(sbi->sb, (unsigned long)ino);

	if (!inode) {
		inode = ERR_PTR((ino & FREEING_INODE) ? -EAGAIN : -ENOMEM);
		goto exit;
	}

	if (!(inode->i_state & I_NEW))
		goto exit;

	/* follow hard link */
	if (record->key->record_type == VDFS4_CATALOG_HLINK_RECORD) {
		struct vdfs4_btree_record_info *rec_info =
					VDFS4_BTREE_REC_I((void *) record);
		struct vdfs4_btree *btree = rec_info->rec_pos.bnode->host;

		hlink_rec = vdfs4_cattree_find_hlink(btree,
				record->key->object_id, VDFS4_BNODE_MODE_RO);
		if (IS_ERR(hlink_rec)) {
			ret = PTR_ERR(hlink_rec);
			hlink_rec = NULL;
			goto error_exit;
		}
		if (hlink_rec->key->record_type == VDFS4_CATALOG_HLINK_RECORD) {
			ret = -EMLINK; /* hard link to hard link? */
			goto error_exit;
		}
		record = hlink_rec;
		set_vdfs4_inode_flag(inode, HARD_LINK);
	}

	VDFS4_I(inode)->record_type = record->key->record_type;
	/* create inode from catalog tree*/
	if (record->key->record_type == VDFS4_CATALOG_FILE_RECORD) {
		file_rec = record->val;
		folder_rec = &file_rec->common;
	} else if (record->key->record_type == VDFS4_CATALOG_FOLDER_RECORD) {
		folder_rec =
			(struct vdfs4_catalog_folder_record *)record->val;
	} else {
		if (!is_sbi_flag_set(sbi, IS_MOUNT_FINISHED)) {
			ret = -EFAULT;
			goto error_exit;
		} else {
			VDFS4_BUG(sbi);
		}
	}

	ret = vdfs4_fill_inode(inode, folder_rec);
	if (ret)
		goto error_exit;

	if (tree->btree_type == VDFS4_BTREE_INST_CATALOG)
		if (S_ISREG(inode->i_mode))
			/* deny_write_access() */
			atomic_set(&inode->i_writecount, -1);


	if (file_rec && (S_ISLNK(inode->i_mode) || S_ISREG(inode->i_mode))) {
		ret = vdfs4_parse_fork(inode, &file_rec->data_fork);
		if (ret)
			goto error_exit;
	}

	if (inode->i_nlink > 1 && !is_vdfs4_inode_flag_set(inode, HARD_LINK)) {
		VDFS4_ERR("inode #%lu has nlink=%u but it's not a hardlink!",
				inode->i_ino, inode->i_nlink);
		ret = -EFAULT;
		goto error_exit;
	}

	if (!hlink_rec) {
		char *new_name;
		struct vdfs4_cattree_key *key = record->key;

		new_name = kmalloc((size_t)key->name_len + 1lu, GFP_NOFS);
		if (!new_name) {
			ret = -ENOMEM;
			goto error_exit;
		}

		memcpy(new_name, key->name, key->name_len);
		new_name[key->name_len] = 0;
		VDFS4_BUG_ON(VDFS4_I(inode)->name, sbi);
		VDFS4_I(inode)->name = new_name;
		VDFS4_I(inode)->parent_id = le64_to_cpu(key->parent_id);
	}

#ifdef CONFIG_VDFS4_DEBUG_AUTHENTICAION
	VDFS4_I(inode)->informed_about_fail_read = 0;
#endif

	if (is_vdfs4_inode_flag_set(inode, VDFS4_COMPRESSED_FILE)) {
		ret = vdfs4_prepare_compressed_file_inode(VDFS4_I(inode));
		if (ret)
			goto error_exit;
	}

	if (hlink_rec)
		vdfs4_release_record((struct vdfs4_btree_gen_record *)hlink_rec);

	unlock_new_inode(inode);

exit:
	/* parent - install point */
	if (tree->btree_type != VDFS4_BTREE_CATALOG)
		VDFS4_I(inode)->parent_id += (VDFS4_I(inode)->parent_id ==
				VDFS4_ROOT_INO) ? (tree->start_ino - 1) :
						tree->start_ino;

	return inode;
error_exit:
	if (hlink_rec)
		vdfs4_release_record((struct vdfs4_btree_gen_record *)hlink_rec);
	iget_failed(inode);
	return ERR_PTR(ret);
}

/**
 * @brief		The eMMCFS inode constructor.
 * @param [in]	dir		Directory, where inode will be created
 * @param [in]	mode	Mode for created inode
 * @return		Returns pointer to inode on success, errno on failure
 */

static struct inode *vdfs4_new_inode(struct inode *dir, umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct  vdfs4_sb_info *sbi = VDFS4_SB(sb);
	ino_t ino = 0;
	struct inode *inode;
	int err, i;
	struct vdfs4_fork_info *ifork;
	struct vdfs4_layout_sb *vdfs4_sb = sbi->raw_superblock;

	err = vdfs4_get_free_inode(sb->s_fs_info, &ino, 1);

	if (err)
		return ERR_PTR(err);

	/*VDFS4_DEBUG_INO("#%lu", ino);*/
	inode = new_inode(sb);
	if (!inode) {
		err = -ENOMEM;
		goto err_exit;
	}

	inode->i_ino = ino;

	if (test_option(sbi, DMASK) && S_ISDIR(mode))
		mode = mode & (umode_t)(~sbi->dmask);

	if (test_option(sbi, FMASK) && S_ISREG(mode))
		mode = mode & (umode_t)(~sbi->fmask);

	inode_init_owner(inode, dir, mode);

	set_nlink(inode, 1);
	inode->i_size = 0;
	inode->i_generation = le32_to_cpu(vdfs4_sb->exsb.generation);
	inode->i_blocks = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime =
			vdfs4_current_time(inode);
	atomic_set(&(VDFS4_I(inode)->open_count), 0);

	/* todo actual inheritance mask and mode-dependent masking */
	VDFS4_I(inode)->flags = VDFS4_I(dir)->flags & VDFS4_FL_INHERITED;
	vdfs4_set_vfs_inode_flags(inode);

	if (S_ISDIR(mode))
		inode->i_op = &vdfs4_dir_inode_operations;
	else if (S_ISLNK(mode))
		inode->i_op = &vdfs4_symlink_inode_operations;
	else
		inode->i_op = &vdfs4_file_inode_operations;

	inode->i_mapping->a_ops = &vdfs4_aops;
	inode->i_fop = (S_ISDIR(mode)) ?
			&vdfs4_dir_operations : &vdfs4_file_operations;

	/* Init extents with zeros - file is empty */
	ifork = &(VDFS4_I(inode)->fork);
	ifork->used_extents = 0;
	for (i = VDFS4_EXTENTS_COUNT_IN_FORK - 1; i >= 0; i--) {
		ifork->extents[i].first_block = 0;
		ifork->extents[i].block_count = 0;
		ifork->extents[i].iblock = 0;
	}
	ifork->total_block_count = 0;
	ifork->prealloc_start_block = 0;
	ifork->prealloc_block_count = 0;

	VDFS4_I(inode)->parent_id = 0;

	return inode;
err_exit:
	if (vdfs4_free_inode_n(sb->s_fs_info, ino, 1))
		VDFS4_ERR("can not free inode while handling error");
	return ERR_PTR(err);
}


/**
 * @brief			Standard callback to create file.
 * @param [in,out]	dir		Directory where node will be created
 * @param [in]		dentry	Created dentry
 * @param [in]		mode	Mode for file
 * @param [in]		nd	Namedata for file
 * @return			Returns 0 on success, errno on failure
 */
static int vdfs4_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool excl)
{
	struct super_block *sb = dir->i_sb;
	struct vdfs4_sb_info *sbi = sb->s_fs_info;
	struct inode *inode;
	char *saved_name;
	int ret = 0;
	struct vdfs4_cattree_record *record;
	u8 record_type;

	VT_PREPARE_PARAM(vt_data);

	VDFS4_DEBUG_INO("'%s' dir = %ld", dentry->d_name.name, dir->i_ino);

	if (dentry->d_name.len > VDFS4_FILE_NAME_LEN)
		return -ENAMETOOLONG;

	saved_name = kzalloc(dentry->d_name.len + 1, GFP_NOFS);
	if (!saved_name)
		return -ENOMEM;

	VT_IOPS_START(vt_data, vdfs_trace_iops_create, dentry);
	vdfs4_start_transaction(sbi);
	inode = vdfs4_new_inode(dir, mode);

	if (IS_ERR(inode)) {
		kfree(saved_name);
		ret = PTR_ERR(inode);
		goto err_trans;
	}

	strncpy(saved_name, dentry->d_name.name, dentry->d_name.len + 1);

	VDFS4_I(inode)->name = saved_name;
	VDFS4_I(inode)->parent_id = dir->i_ino;
	vdfs4_cattree_w_lock(sbi);
	ret = __get_record_type_on_mode(inode, &record_type);
	if (ret)
		goto err_notree;
	record = vdfs4_cattree_place_record(sbi->catalog_tree, inode->i_ino,
			dir->i_ino, dentry->d_name.name,
			dentry->d_name.len, record_type);
	if (IS_ERR(record)) {
		ret = PTR_ERR(record);
		goto err_notree;
	}
	vdfs4_fill_cattree_record(inode, record);
	vdfs4_release_dirty_record((struct vdfs4_btree_gen_record *) record);
	vdfs4_cattree_w_unlock(sbi);

#ifdef CONFIG_VDFS4_POSIX_ACL
	ret = vdfs4_init_acl(inode, dir);
	if (ret)
		goto err_unlock;
#endif

	ret = security_inode_init_security(inode, dir,
			&dentry->d_name, vdfs4_init_security_xattrs, NULL);
	if (ret && ret != -EOPNOTSUPP)
		goto err_unlock;

	ret = insert_inode_locked(inode);
	if (ret)
		goto err_unlock;

	vdfs4_assert_i_mutex(dir);
	dir->i_size++;
	if (S_ISDIR(inode->i_mode))
		sbi->folders_count++;
	else
		sbi->files_count++;

	dir->i_ctime = vdfs4_current_time(dir);
	dir->i_mtime = vdfs4_current_time(dir);
	mark_inode_dirty(dir);
	d_instantiate(dentry, inode);
#ifdef CONFIG_VDFS4_DEBUG_AUTHENTICAION
	VDFS4_I(inode)->informed_about_fail_read = 0;
#endif
	unlock_new_inode(inode);
	/* some fields are updated after insering into tree */
	mark_inode_dirty(inode);
	vdfs4_stop_transaction(sbi);
	VT_FINISH(vt_data);
	return ret;

err_notree:
	vdfs4_cattree_w_unlock(sbi);
	vdfs4_free_inode_n(sbi, inode->i_ino, 1);
	inode->i_ino = 0;
err_unlock:
	clear_nlink(inode);
	iput(inode);
err_trans:
	vdfs4_stop_transaction(sbi);
	VT_FINISH(vt_data);
	return ret;
}

int __vdfs4_write_inode(struct vdfs4_sb_info *sbi, struct inode *inode)
{
	struct vdfs4_cattree_record *record;

	if (is_vdfs4_inode_flag_set(inode, HARD_LINK))
		record = vdfs4_cattree_find_hlink(sbi->catalog_tree,
				inode->i_ino, VDFS4_BNODE_MODE_RW);
	else
		record = vdfs4_cattree_find_inode(sbi->catalog_tree,
				inode->i_ino, VDFS4_I(inode)->parent_id,
				VDFS4_I(inode)->name,
				strlen(VDFS4_I(inode)->name),
				VDFS4_BNODE_MODE_RW);
	if (IS_ERR(record)) {
		vdfs4_fatal_error(sbi, "fail to update inode %lu", inode->i_ino);
		vdfs4_record_err_dump_disk(sbi, VDFS4_DEBUG_ERR_INODE_WRITE,
				inode->i_ino, 0, "fail update inode", NULL, 0);
		return PTR_ERR(record);
	}
	vdfs4_fill_cattree_value(inode, record->val);
	vdfs4_release_dirty_record((struct vdfs4_btree_gen_record *)record);
	return 0;
}

/**
 * @brief			Write inode to bnode.
 * @param [in,out]	inode	The inode, that will be written to bnode
 * @return			Returns 0 on success, errno on failure
 */
int vdfs4_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct super_block *sb = inode->i_sb;
	struct vdfs4_sb_info *sbi = sb->s_fs_info;
	int ret;

	trace_vdfs4_write_inode(inode, wbc);

	if (inode->i_ino < VDFS4_1ST_FILE_INO && inode->i_ino != VDFS4_ROOT_INO)
		return 0;
	vdfs4_start_writeback(sbi);
	vdfs4_cattree_w_lock(sbi);
	ret = __vdfs4_write_inode(sbi, inode);
	vdfs4_cattree_w_unlock(sbi);
	vdfs4_stop_writeback(sbi);

	return ret;
}

/**
 * @brief		Method to read inode to inode cache.
 * @param [in]	sb	Pointer to superblock
 * @param [in]	ino	The inode number
 * @return		Returns pointer to inode on success,
 *			ERR_PTR(errno) on failure
 */
struct inode *vdfs4_special_iget(struct super_block *sb, unsigned long ino)
{
	struct inode *inode;
	struct vdfs4_sb_info *sbi = sb->s_fs_info;
	int ret = 0;
	gfp_t gfp_mask;
	loff_t size;

	VDFS4_DEBUG_INO("inode #%lu", ino);
	inode = iget_locked(sb, ino);
	if (!inode) {
		ret = -ENOMEM;
		goto err_exit_no_fail;
	}

	if (!(inode->i_state & I_NEW))
		goto exit;

	inode->i_mode = 0;

	/* Metadata pages can not be migrated */
	gfp_mask = (mapping_gfp_mask(inode->i_mapping) & ~GFP_MOVABLE_MASK);
	mapping_set_gfp_mask(inode->i_mapping, gfp_mask);

	size = vdfs4_special_file_size(sbi, ino);
	inode->i_mapping->a_ops = &vdfs4_aops_special;

	i_size_write(inode, size);

	unlock_new_inode(inode);
exit:
	return inode;
err_exit_no_fail:
	VDFS4_DEBUG_INO("inode #%lu read FAILED", ino);
	return ERR_PTR(ret);
}

/**
 * @brief		Propagate flags from vfs inode i_flags
 *			to VDFS4_I(inode)->flags.
 * @param [in]	inode	Pointer to vfs inode structure.
  * @return		none.
 */
void vdfs4_get_vfs_inode_flags(struct inode *inode)
{
	VDFS4_I(inode)->flags &= ~(1lu << (unsigned long)VDFS4_IMMUTABLE);
	if (inode->i_flags & S_IMMUTABLE)
		VDFS4_I(inode)->flags |=
			(1lu << (unsigned long)VDFS4_IMMUTABLE);
}

/**
 * @brief		Set vfs inode i_flags according to
 *			VDFS4_I(inode)->flags.
 * @param [in]	inode	Pointer to vfs inode structure.
  * @return		none.
 */
void vdfs4_set_vfs_inode_flags(struct inode *inode)
{
	inode->i_flags &= ~(unsigned long)S_IMMUTABLE;
	if (VDFS4_I(inode)->flags & (1lu << (unsigned long)VDFS4_IMMUTABLE))
		inode->i_flags |= S_IMMUTABLE;
}
