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

#ifdef CONFIG_VDFS4_HW_DECOMPRESS_SUPPORT
#include <crypto/crypto_wrapper.h>
#include <mach/hw_decompress.h>
#endif

#include "vdfs4.h"
#include "cattree.h"
#include "debug.h"


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
		struct buffer_head *bh_result, int create) ;


/**
 * @brief		Allocate new inode.
 * @param [in]	dir		Parent directory
 * @param [in]	mode	Mode of operation
 * @return		Returns pointer to newly created inode on success,
 *			errno on failure
 */
static struct inode *vdfs4_new_inode(struct inode *dir, umode_t mode);
int __vdfs4_write_inode(struct vdfs4_sb_info *sbi, struct inode *inode);

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

	BUG_ON(!pvalue || IS_ERR(pvalue));

	VDFS4_I(inode)->record_type = record->key->record_type;

	if (VDFS4_GET_CATTREE_RECORD_TYPE(record) == VDFS4_CATALOG_HLINK_RECORD)
		vdfs4_fill_hlink_value(inode, pvalue);
	else
		vdfs4_fill_cattree_value(inode, pvalue);
}

/**
 * @brief		Method to read (list) directory.
 * @param [in]	filp	File pointer
 * @param [in]	dirent	Directory entry
 * @param [in]	filldir	Callback filldir for kernel
 * @return		Returns count of files/dirs
 */
static int vdfs4_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct dentry *dentry = filp->f_dentry;
	struct vdfs4_sb_info *sbi = inode->i_sb->s_fs_info;
	__u64 catalog_id = inode->i_ino;
	int ret = 0;
	struct vdfs4_cattree_record *record;
	struct vdfs4_btree *btree = NULL;
	loff_t pos = 2; /* "." and ".." */

	/* return 0 if no more entries in the directory */
	switch (filp->f_pos) {
	case 0:
		if (filldir(dirent, ".", 1, filp->f_pos++, inode->i_ino,
					DT_DIR))
			goto exit_noput;
		/* fallthrough */
		/* filp->f_pos increases and so processing is done immediately*/
	case 1:
		if (filldir(dirent, "..", 2, filp->f_pos++,
			dentry->d_parent->d_inode->i_ino, DT_DIR))
			goto exit_noput;
		break;
	default:
		break;
	}

	mutex_r_lock(sbi->catalog_tree->rw_tree_lock);
	btree = sbi->catalog_tree;

	if (IS_ERR(btree)) {
		mutex_r_unlock(sbi->catalog_tree->rw_tree_lock);
		return PTR_ERR(btree);
	}

	if (!filp->private_data) {
		record = vdfs4_cattree_get_first_child(btree, catalog_id);
	} else {
		char *name = filp->private_data;
		record = vdfs4_cattree_find(btree, catalog_id,
				name, strlen(name), VDFS4_BNODE_MODE_RO);
	}

	if (IS_ERR(record)) {
		ret = (PTR_ERR(record) == -EISDIR) ? 0 : PTR_ERR(record);
		goto fail;
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
			goto skip;

		if (!filp->private_data && pos < filp->f_pos)
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

		ret = filldir(dirent, record->key->name, record->key->name_len,
				filp->f_pos, obj_id, IFTODT(object_mode));

		if (ret) {
			char *private_data;

			if (!filp->private_data) {
				private_data = kmalloc(VDFS4_FILE_NAME_LEN + 1,
						GFP_NOFS);
				filp->private_data = private_data;
				if (!private_data) {
					ret = -ENOMEM;
					goto fail;
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

		++filp->f_pos;
next:
		++pos;
skip:
		ret = vdfs4_cattree_get_next_record(record);
		if ((ret == -ENOENT) ||
			record->key->parent_id != cpu_to_le64(catalog_id)) {
			/* No more entries */
			kfree(filp->private_data);
			filp->private_data = NULL;
			ret = 0;
			break;
		} else if (ret) {
			goto fail;
		}

	}

exit:
	vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
	mutex_r_unlock(sbi->catalog_tree->rw_tree_lock);
exit_noput:
	return ret;
fail:
	VDFS4_DEBUG_INO("finished with err (%d)", ret);
	if (!IS_ERR_OR_NULL(record))
		vdfs4_release_record((struct vdfs4_btree_gen_record *) record);

	VDFS4_DEBUG_MUTEX("cattree mutex r lock un");
	mutex_r_unlock(sbi->catalog_tree->rw_tree_lock);
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

static int vdfs4_dir_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct super_block *sb = file->f_dentry->d_sb;
	int ret = 0;

	if (!datasync) {
		down_read(&sb->s_umount);
		ret = sync_filesystem(sb);
		up_read(&sb->s_umount);
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

	if (dentry->d_name.len > VDFS4_FILE_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	mutex_r_lock(sbi->catalog_tree->rw_tree_lock);
	tree = sbi->catalog_tree;

	if (IS_ERR(tree)) {
		mutex_r_unlock(sbi->catalog_tree->rw_tree_lock);
		return (struct dentry *)tree;
	}

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
	mutex_r_unlock(sbi->catalog_tree->rw_tree_lock);
	ret = d_splice_alias(inode, dentry);
	if (IS_ERR(ret))
		return ret;
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
		mutex_r_lock(sbi->catalog_tree->rw_tree_lock);
		inode = __vdfs4_iget(sbi, ino);
		mutex_r_unlock(sbi->catalog_tree->rw_tree_lock);
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
	pgoff_t total_pages = (pgoff_t)VDFS4_LAST_TABLE_INDEX(sbi,
			VDFS4_FREE_INODE_BITMAP_INO) + 1;
	*i_ino = 0;

	if (count > data_size)
		return -ENOMEM; /* todo we can allocate inode numbers chunk
		 only within one page*/

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
			VDFS4_BUG_ON(*i_ino + id_offset < VDFS4_1ST_FILE_INO);
			if (count > 1) {
				bitmap_set(addr, (int)*i_ino, (int)count);
			} else {
				int ret = test_and_set_bit((int)*i_ino, addr);
				if (ret) {
					destroy_layout(sbi);
					VDFS4_BUG_ON(1);
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
		if (!test_and_clear_bit((long)int_offset + count - 1,
			(void *)((char *)data + INODE_BITMAP_MAGIC_LEN))) {
			VDFS4_DEBUG_INO("vdfs4_free_inode_n %lu"
				, inode_n);
			destroy_layout(sbi);
			VDFS4_BUG();
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

	VDFS4_DEBUG_INO("unlink '%s', ino = %lu", dentry->d_iname,
			inode->i_ino);

	if (!inode->i_nlink) {
		VDFS4_ERR("inode #%lu has no links left!", inode->i_ino);
		return -EFAULT;
	}

	vdfs4_start_transaction(sbi);
	vdfs4_assert_i_mutex(inode);
	mutex_w_lock(sbi->catalog_tree->rw_tree_lock);

	drop_nlink(inode);
	VDFS4_BUG_ON(inode->i_nlink > VDFS4_LINK_MAX);

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

	if (is_dlink(inode)) {
		struct inode *data_inode = VDFS4_I(inode)->data_link.inode;

		/*
		 * This is third i_mutex in the stack: parent locked as
		 * I_MUTEX_PARENT, target inode locked as I_MUTEX_NORMAL.
		 * I_MUTEX_XATTR is ok, newer kernels have more suitable
		 * I_MUTEX_NONDIR2 which is actually renamed I_MUTEX_QUOTA.
		 */
		mutex_lock_nested(&data_inode->i_mutex, I_MUTEX_XATTR);
		drop_nlink(data_inode);
		if (!data_inode->i_nlink) {
			ret = vdfs4_add_to_orphan(sbi, data_inode);
			if (ret) {
				inc_nlink(data_inode);
				mutex_unlock(&data_inode->i_mutex);
				goto exit_inc_nlink;
			}

			ret = __vdfs4_write_inode(sbi, data_inode);
			if (ret) {
				vdfs4_fatal_error(sbi, "fail to update orphan \
						list %d", ret);
				inc_nlink(data_inode);
				mutex_unlock(&data_inode->i_mutex);
				goto exit_inc_nlink;
			}
		}
		mark_inode_dirty(data_inode);
		mutex_unlock(&data_inode->i_mutex);
	}

	ret = vdfs4_add_to_orphan(sbi, inode);
	if (ret)
		goto exit_inc_nlink;
	ret = __vdfs4_write_inode(sbi, inode);
	if (ret) {
		vdfs4_fatal_error(sbi, "fail to update orphan list %d", ret);
		goto exit_inc_nlink;
	}
keep:
	mark_inode_dirty(inode);
	mutex_w_unlock(sbi->catalog_tree->rw_tree_lock);

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
	return ret;

exit_inc_nlink:
	inc_nlink(inode);
	mutex_w_unlock(sbi->catalog_tree->rw_tree_lock);
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
 * @return			Returns physical block number, or err_code
 */
static int insert_extent(struct vdfs4_inode_info *inode_info,
		struct vdfs4_extent_info *extent, int update_bnode)
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
		for (count = fork->used_extents - 1lu; count > pos; count--)
			memcpy(&fork->extents[count], &fork->extents[count - 1],
						sizeof(*extent));
		memcpy(&fork->extents[pos], extent, sizeof(*extent));
	}

update_on_disk_layout:
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
		BUG_ON(sbi->reserved_blocks_count < iblocks_count);
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
/*
 * */
int vdfs4_get_block_prep_da(struct inode *inode, sector_t iblock,
		struct buffer_head *bh_result, int create) {
	struct vdfs4_inode_info *inode_info = VDFS4_I(inode);
	struct vdfs4_sb_info *sbi = inode->i_sb->s_fs_info;
	struct super_block *sb = inode->i_sb;
	sector_t offset_alloc_hint = 0, res_block;
	int err = 0;
	__u32 max_blocks = 1;
	__u32 buffer_size = bh_result->b_size >> sbi->block_size_shift;

	struct vdfs4_extent_info extent;
	if (!create)
		BUG();
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

	err = vdfs4_reserve_space(inode, 1);
	if (err)
		/* not enough space to reserve */
		goto exit;
	map_bh(bh_result, inode->i_sb, VDFS4_INVALID_BLOCK);
	set_buffer_new(bh_result);
	set_buffer_delay(bh_result);
	err = vdfs4_runtime_extent_add(iblock, offset_alloc_hint,
			&inode_info->runtime_extents);
	if (err) {
		vdfs4_free_reserved_space(inode, 1);
		goto exit;
	}
	goto exit;
done:
	res_block = extent.first_block + (iblock - extent.iblock);
	max_blocks = extent.block_count - (__u32)(iblock - extent.iblock);
	BUG_ON(res_block > extent.first_block + extent.block_count);

	if (res_block > (sector_t)(sb->s_bdev->bd_inode->i_size >>
				sbi->block_size_shift)) {
		if (!is_sbi_flag_set(sbi, IS_MOUNT_FINISHED)) {
			VDFS4_ERR("Block beyond block bound requested");
			err = -EFAULT;
			goto exit;
		} else {
			BUG();
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
	__u32 buffer_size = bh_result->b_size >> sbi->block_size_shift;
	int err = 0;
	struct vdfs4_extent_info extent;

	BUG_ON(!mutex_is_locked(&inode_info->truncate_mutex));
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
		if(!vdfs4_runtime_extent_exists(iblock,
				&inode_info->runtime_extents))
			BUG();
	} else {
		if (buffer_delay(bh_result))
			BUG();
	}
	extent.block_count = (u32)count;
	extent.first_block = vdfs4_fsm_get_free_block(sbi, offset_alloc_hint,
			&extent.block_count, fsm_flags);

	if (!extent.first_block) {
		err = -ENOSPC;
		goto exit;
	}

	extent.iblock = iblock;
	err = insert_extent(inode_info, &extent, 1);
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
		BUG_ON(err);
	}

	alloc = 1;

done:
	res_block = extent.first_block + (iblock - extent.iblock);
	max_blocks = extent.block_count - (u32)(iblock - extent.iblock);
	BUG_ON(res_block > extent.first_block + extent.block_count);

	if (res_block > (sector_t)(sb->s_bdev->bd_inode->i_size >>
				sbi->block_size_shift)) {
		if (!is_sbi_flag_set(sbi, IS_MOUNT_FINISHED)) {
			VDFS4_ERR("Block beyond block bound requested");
			err = -EFAULT;
			goto exit;
		} else {
			BUG();
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

/**
 * @brief				Logical to physical block numbers
 *					translation.
 * @param [in]		inode		Pointer to inode structure.
 * @param [in]		iblock		Requested logical block number.
 * @param [in, out]	bh_result	Pointer to buffer_head.
 * @param [in]		create		"Expand file allowed" flag.
 * @return			Returns physical block number,
 *					0 if ENOSPC
 */
int vdfs4_get_block(struct inode *inode, sector_t iblock,
	struct buffer_head *bh_result, int create)
{
	int ret = 0;
	struct vdfs4_inode_info *inode_info= VDFS4_I(inode);
	struct mutex *lock = &inode_info->truncate_mutex;
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

static int vdfs4_get_block_bug(struct inode *inode, sector_t iblock,
	struct buffer_head *bh_result, int create)
{
	BUG();
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

#ifdef CONFIG_VDFS4_EXEC_ONLY_AUTHENTICATED

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
		struct inode *caller = mm->exe_file->f_dentry->d_inode;

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
	return mpage_readpage(page, vdfs4_get_block);
}


/**
 * @brief		Read page function.
 * @param [in]	file	Pointer to file structure
 * @param [out]	page	Pointer to page structure
 * @return		Returns error codes
 */
static int vdfs4_readpage_special(struct file *file, struct page *page)
{
	BUG();
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
	return mpage_readpages(mapping, pages, nr_pages, vdfs4_get_block);

}

static int vdfs4_readpages_special(struct file *file,
		struct address_space *mapping, struct list_head *pages,
		unsigned nr_pages)
{
	BUG();
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

	if (!memcmp(descr->magic + 1, VDFS4_COMPR_ZHW_FILE_DESCR_MAGIC,
			sizeof(descr->magic) - 1))
		return VDFS4_COMPR_ZHW;
	return -EINVAL;
}

static int vdfs4_file_descriptor_verify(struct vdfs4_inode_info *inode_i,
		struct vdfs4_comp_file_descr *descr)
{
	int ret = 0;
	enum compr_type compr_type;
	if (le32_to_cpu(descr->layout_version) != VDFS4_COMPR_LAYOUT_VER) {
		VDFS4_ERR("Wrong descriptor layout version %d (expected %d) file %s",
				le32_to_cpu(descr->layout_version), VDFS4_COMPR_LAYOUT_VER,
				INODEI_NAME(inode_i));
		ret = -EINVAL;
		goto err;
	}

	switch(descr->magic[0]) {
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
	case VDFS4_COMPR_ZHW:
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
	if(ret)
		VDFS4_MDUMP("Bad descriptor dump:", descr, sizeof(*descr));
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
		if(!data) {
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
	ret = vdfs4_file_descriptor_verify(inode_i, descr);
err:
	for (page_idx = 0; page_idx < 2; page_idx++) {
		if(pages[page_idx]) {
			if(ret && ret != -ENOMEM) {
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

static void copy_pages(struct page **src_pages, struct page **dst_pages,
		int src_offset, int dst_offset, unsigned long length)
{
	void *src, *dst;
	int len;
	while (length) {
		len = min(PAGE_SIZE - max(src_offset, dst_offset), length);
		src = kmap_atomic(*src_pages);
		dst = kmap_atomic(*dst_pages);
		memcpy((char *)dst + dst_offset, (char *)src + src_offset,
				(size_t)len);
		kunmap_atomic(dst);
		kunmap_atomic(src);
		length -= (unsigned long)len;
		src_offset += len;
		dst_offset += len;
		if (src_offset == PAGE_SIZE) {
			src_pages++;
			src_offset = 0;
		}
		if (dst_offset == PAGE_SIZE) {
			dst_pages++;
			dst_offset = 0;
		}
	}
}

static int vdfs4_data_link_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct inode *data_inode = VDFS4_I(inode)->data_link.inode;
	u64 offset = VDFS4_I(inode)->data_link.offset;
	pgoff_t index = page->index + (pgoff_t)(offset >> PAGE_CACHE_SHIFT);
	struct page *data[2];

	data[0] = read_mapping_page(data_inode->i_mapping, index, NULL);
	if (IS_ERR(data[0]))
		goto err0;
	if (offset % PAGE_CACHE_SIZE) {
		data[1] = read_mapping_page(data_inode->i_mapping,
					    index + 1, NULL);
		if (IS_ERR(data[1]))
			goto err1;
	}
	copy_pages(data, &page, offset % PAGE_CACHE_SIZE, 0, PAGE_CACHE_SIZE);
	if (offset % PAGE_CACHE_SIZE)
		page_cache_release(data[1]);
	page_cache_release(data[0]);
	SetPageUptodate(page);
	unlock_page(page);
	return 0;

err1:
	page_cache_release(data[0]);
	data[0] = data[1];
err0:
	unlock_page(page);
	return PTR_ERR(data[0]);
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

	BUG_ON(inode->i_ino <= VDFS4_LSFILE);

	if (!page_has_buffers(page))
		goto redirty_page;

	bh = page_buffers(page);
	if ((!buffer_mapped(bh) || buffer_delay(bh)) && buffer_dirty(bh))
		goto redirty_page;

	ret = block_write_full_page(page, vdfs4_get_block_bug, wbc);
#if defined(CONFIG_VDFS4_DEBUG)
	if (ret)
		VDFS4_ERR("err = %d, ino#%lu name=%s, page index: %lu, "
				" wbc->sync_mode = %d", ret, inode->i_ino,
				VDFS4_I(inode)->name, page->index,
				wbc->sync_mode);
#endif
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
	pgoff_t index = page->index & ~((1 << (inode_i->fbc->log_chunk_size -
					PAGE_SHIFT)) - 1);
	int pages_count = (1 << (inode_i->fbc->log_chunk_size -
			PAGE_SHIFT)) + 1;

	chunk_pages = kmalloc(sizeof(struct page *) * pages_count, GFP_NOFS);

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

	unlock_page(page);
	/* read input data (read chunk from disk) */
	ret = vdfs4_read_chunk(page, chunk_pages, &cext);
	if (ret < 0)
		goto exit;

	ret = vdfs4_auth_decompress(page->mapping->host, chunk_pages, index,
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
exit:
	kfree(chunk_pages);
	return ret;
}


#ifdef CONFIG_VDFS4_HW_DECOMPRESS_SUPPORT
static int vdfs4_readpage_tuned_hw(struct file *file, struct page *page)
{
	int ret = 0;
	struct inode *inode = page->mapping->host;
	struct vdfs4_inode_info *inode_i = VDFS4_I(inode);

	if (page->index >= ((i_size_read(inode) + PAGE_CACHE_SIZE - 1) >>
					PAGE_CACHE_SHIFT)) {
		clear_highpage(page);
		SetPageUptodate(page);
		unlock_page(page);
		return 0;
	}

	/* We must lock all pages in the chunk one by one from the beginning,
	 * otherwise we might deadlock with concurrent read of other page. */
	unlock_page(page);

	ret = inode_i->fbc->hw_fn(inode, page);
	if (ret) {
		/* HW decompression/auth has failed, try software one */
		lock_page(page);
		ret = vdfs4_readpage_tuned_sw(file, page);
	}

	return ret;
}
#endif

#ifdef CONFIG_VDFS4_RETRY
static int vdfs4_readpage_tuned_sw_retry(struct file *file, struct page *page)
{
	int i = 0, ret;

	do {
		if (i)
			lock_page(page);
		ret = vdfs4_readpage_tuned_sw(file, page);
		if (ret)
			i++;
	} while (ret && (i < 3));

	if (i && !ret)
		VDFS4_DEBUG_TMP("decomression retry successfully done");
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
			i++;
	} while (ret && (i < 3));

	if (i && !ret)
		VDFS4_DEBUG_TMP("decomression retry successfully done");
	return ret;
}
#endif
#endif

static int vdfs4_allocate_space(struct vdfs4_inode_info *inode_info)
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
				alloc_hint, &count, VDFS4_FSM_ALLOC_DELAYED);

		if (!extent.first_block) {
			/* it shouldn't happen because space
			 * was reserved early in aio_write */
			BUG();
			goto exit;
		}

		extent.iblock = entry->iblock;
		extent.block_count = count;
		err = insert_extent(inode_info, &extent, 0);
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
	vdfs4_start_writeback(sbi);
	/* if we have runtime extents, allocate space on volume*/
	if (!list_empty(&inode_info->runtime_extents))
		ret = vdfs4_allocate_space(inode_info);
	blk_start_plug(&plug);
	/* write dirty pages */
	ret = write_cache_pages(mapping, wbc, vdfs4_mpage_writepage, &mpd);
	if (mpd.bio)
		vdfs4_mpage_bio_submit(WRITE, mpd.bio);
	blk_finish_plug(&plug);
	vdfs4_stop_writeback(sbi);
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
	vdfs4_start_transaction(VDFS4_SB(mapping->host->i_sb));
	rc = block_write_begin(mapping, pos, len, flags, pagep,
		vdfs4_get_block_prep_da);

	if (rc)
		vdfs4_stop_transaction(VDFS4_SB(mapping->host->i_sb));
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
#ifdef CONFIG_VDFS4_RETRY
				int retry_count = 1;
				do {
#endif
					rc = vdfs4_init_file_decompression(inode_info, 1);
#ifdef CONFIG_VDFS4_RETRY
					if (rc)
						VDFS4_ERR("init decompression retry %d", retry_count);
				} while (rc && (retry_count++ < 3));
#endif
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

	if (is_vdfs4_inode_flag_set(inode, VDFS4_COMPRESSED_FILE))
	{
		if (filp->f_flags & (O_CREAT | O_TRUNC | O_WRONLY | O_RDWR))
			rc = -EPERM;
		else
			rc = vdfs4_file_open_init_compressed(inode);
	}

	/* dlink should never have COMPRESSED_FILE set, only link inode can */
	if (!rc && is_dlink(inode) && is_vdfs4_inode_flag_set(
			VDFS4_I(inode)->data_link.inode, VDFS4_COMPRESSED_FILE))
		rc = vdfs4_file_open_init_compressed(VDFS4_I(inode)->data_link.inode);

	if (rc)
		return rc;

	rc = generic_file_open(inode, filp);
	if (!rc)
		atomic_inc(&(VDFS4_I(inode)->open_count));

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
	return vdfs4_create(dir, dentry, S_IFDIR | mode, NULL);
}

/**
 * @brief		Function rmdir.
 * @param [in]	dir	Pointer to inode
 * @param [in]	dentry	Pointer to directory entry
 * @return		Returns error codes
 */
static int vdfs4_rmdir(struct inode *dir, struct dentry *dentry)
{
	if (dentry->d_inode->i_size)
		return -ENOTEMPTY;

	return vdfs4_unlink(dir, dentry);
}

/**
 * @brief		Direct IO.
 * @param [in]	rw		read/write
 * @param [in]	iocb	Pointer to io block
 * @param [in]	iov		Pointer to IO vector
 * @param [in]	offset	Offset
 * @param [in]	nr_segs	Number of segments
 * @return		Returns written size
 */
static ssize_t vdfs4_direct_IO(int rw, struct kiocb *iocb,
		const struct iovec *iov, loff_t offset, unsigned long nr_segs)
{
	ssize_t rc, inode_new_size = 0;
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_path.dentry->d_inode->i_mapping->host;
	struct vdfs4_sb_info *sbi = VDFS4_SB(inode->i_sb);

	if (rw)
		vdfs4_start_transaction(sbi);
	rc = blockdev_direct_IO(rw, iocb, inode, iov, offset, nr_segs,
			vdfs4_get_block);
	if (!rw)
		return rc;

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

		truncate_pagecache(inode, inode->i_size, iattr->ia_size);

		error = vdfs4_update_inode(inode, iattr->ia_size);
		if (error)
			goto exit;
	}

	setattr_copy(inode, iattr);

	mark_inode_dirty(inode);

#ifdef CONFIG_VDFS4_POSIX_ACL
	if (iattr->ia_valid & ATTR_MODE)
		error = vdfs4_chmod_acl(inode);
#endif

exit:
	vdfs4_stop_transaction(VDFS4_SB(inode->i_sb));

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
	return generic_block_bmap(mapping, block, vdfs4_get_block);
}

static int __get_record_type_on_mode(struct inode *inode, u8 *record_type)
{
	umode_t mode = inode->i_mode;

	if (is_vdfs4_inode_flag_set(inode, HARD_LINK))
		*record_type = VDFS4_CATALOG_HLINK_RECORD;
	else if (is_dlink(inode))
		*record_type = VDFS4_CATALOG_DLINK_RECORD;
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

	if (new_dentry->d_name.len > VDFS4_FILE_NAME_LEN)
		return -ENAMETOOLONG;

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
	mutex_w_lock(sbi->catalog_tree->rw_tree_lock);
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

	mutex_w_unlock(sbi->catalog_tree->rw_tree_lock);

	mv_inode->i_ctime = vdfs4_current_time(mv_inode);
	mark_inode_dirty(mv_inode);

	vdfs4_assert_i_mutex(old_dir);
	if (old_dir->i_size != 0)
		old_dir->i_size--;
	else
		VDFS4_DEBUG_INO("Files count mismatch");
	mark_inode_dirty(old_dir);

	vdfs4_assert_i_mutex(new_dir);
	new_dir->i_size++;
	mark_inode_dirty(new_dir);
exit:
	vdfs4_stop_transaction(sbi);
	return ret;

remove_record:
	vdfs4_cattree_remove(sbi->catalog_tree, mv_inode->i_ino, new_dir->i_ino,
			new_dentry->d_name.name, new_dentry->d_name.len,
			VDFS4_I(mv_inode)->record_type);
error:
	mutex_w_unlock(sbi->catalog_tree->rw_tree_lock);
	vdfs4_stop_transaction(sbi);
	kfree(saved_name);
	return ret;
}

/**
 * @brief			Add hardlink record .
 * @param [in]	cat_tree	Pointer to catalog tree
 * @param [in]	hlink_id	Hardlink id
 * @param [in]	par_ino_n	Parent inode number
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

	__get_record_type_on_mode(inode, &record_type);

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
	vdfs4_cattree_remove(sbi->catalog_tree, inode->i_ino, inode->i_ino, NULL,
			0, VDFS4_I(inode)->record_type);
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

	vdfs4_assert_i_mutex(inode);

	if (dentry->d_name.len > VDFS4_FILE_NAME_LEN)
		return -ENAMETOOLONG;

	if (inode->i_nlink >= VDFS4_LINK_MAX)
		return -EMLINK;

	vdfs4_start_transaction(sbi);
	mutex_w_lock(sbi->catalog_tree->rw_tree_lock);

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
	mutex_w_unlock(sbi->catalog_tree->rw_tree_lock);

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
	return ret;
err_exit:
	mutex_w_unlock(sbi->catalog_tree->rw_tree_lock);
	goto exit;
}

int vdfs4_data_link_create(struct dentry *parent, const char *name,
		struct inode *data_inode, __u64 data_offset, __u64 data_length)
{
	struct inode *dir = parent->d_inode;
	struct vdfs4_sb_info *sbi = dir->i_sb->s_fs_info;
	struct vdfs4_layout_sb *vdfs4_sb = sbi->raw_superblock;
	struct vdfs4_catalog_dlink_record *dlink;
	struct vdfs4_cattree_record *record;
	ino_t ino;
	int err;

	if (dir->i_sb != data_inode->i_sb || !S_ISREG(data_inode->i_mode) ||
			is_dlink(data_inode))
		return -EBADF;

	/*
	 * The same locking madness like in sys_link sequence.
	 */
	mutex_lock_nested(&dir->i_mutex, I_MUTEX_PARENT);
	mutex_lock(&data_inode->i_mutex);
	vdfs4_start_transaction(sbi);

	err = vdfs4_get_free_inode(sbi, &ino, 1);
	if (err)
		goto err_alloc_ino;

	mutex_w_lock(sbi->catalog_tree->rw_tree_lock);

	if (!is_vdfs4_inode_flag_set(data_inode, HARD_LINK)) {
		err = transform_into_hlink(data_inode);
		if (err)
			goto err_transform;
	}

	record = vdfs4_cattree_place_record(sbi->catalog_tree,
			ino, dir->i_ino, name, strlen(name),
			VDFS4_CATALOG_DLINK_RECORD);
	err = PTR_ERR(record);
	if (IS_ERR(record))
		goto err_place_record;

	dlink = (struct vdfs4_catalog_dlink_record *)record->val;

	dlink->common.flags = 0;
	dlink->common.file_mode = cpu_to_le16(S_IFREG |
				(data_inode->i_mode & 0555));
	dlink->common.uid = cpu_to_le32(i_uid_read(data_inode));
	dlink->common.gid = cpu_to_le32(i_gid_read(data_inode));
	dlink->common.total_items_count = cpu_to_le64(data_length);
	dlink->common.links_count = cpu_to_le64(1);
	dlink->common.creation_time = vdfs4_encode_time(data_inode->i_ctime);
	dlink->common.access_time = vdfs4_encode_time(data_inode->i_atime);
	dlink->common.modification_time = vdfs4_encode_time(data_inode->i_mtime);
	dlink->common.generation = le32_to_cpu(vdfs4_sb->exsb.generation);

	dlink->data_inode = le64_to_cpu(data_inode->i_ino);
	dlink->data_offset = le64_to_cpu(data_offset);
	dlink->data_length = le64_to_cpu(data_length);

	vdfs4_release_dirty_record((struct vdfs4_btree_gen_record *)record);
	mutex_w_unlock(sbi->catalog_tree->rw_tree_lock);

	inc_nlink(data_inode);
	mark_inode_dirty(data_inode);

	dir->i_ctime = vdfs4_current_time(dir);
	dir->i_mtime = vdfs4_current_time(dir);
	dir->i_size++;
	mark_inode_dirty(dir);

	vdfs4_stop_transaction(sbi);
	mutex_unlock(&data_inode->i_mutex);
	/* prune negative dentry */
	shrink_dcache_parent(parent);
	mutex_unlock(&dir->i_mutex);

	return 0;

err_place_record:
err_transform:
	mutex_w_unlock(sbi->catalog_tree->rw_tree_lock);
	vdfs4_free_inode_n(sbi, ino, 1);
err_alloc_ino:
	vdfs4_stop_transaction(sbi);
	mutex_unlock(&data_inode->i_mutex);
	mutex_unlock(&dir->i_mutex);
	return err;
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
	int len = (int)strlen(symname);

	if ((len > VDFS4_FULL_PATH_LEN) ||
			(dentry->d_name.len > VDFS4_FILE_NAME_LEN))
		return -ENAMETOOLONG;

	vdfs4_start_transaction(VDFS4_SB(dir->i_sb));

	ret = vdfs4_create(dir, dentry, S_IFLNK | S_IRWXUGO, NULL);
	if (ret)
		goto exit;

	created_ino = dentry->d_inode;
	ret = page_symlink(created_ino, symname, ++len);
exit:
	vdfs4_stop_transaction(VDFS4_SB(dir->i_sb));
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

const struct address_space_operations vdfs4_data_link_aops = {
	.readpage	= vdfs4_data_link_readpage,
};


#ifdef CONFIG_VDFS4_RETRY
const struct address_space_operations vdfs4_tuned_aops = {
	.readpage	= vdfs4_readpage_tuned_sw_retry,
};
#else
const struct address_space_operations vdfs4_tuned_aops = {
	.readpage	= vdfs4_readpage_tuned_sw,
};
#endif


#if (defined(CONFIG_VDFS4_USE_HW1_DECOMPRESS) \
		|| defined (CONFIG_VDFS4_USE_HW2_DECOMPRESS))
#ifdef CONFIG_VDFS4_RETRY
const struct address_space_operations vdfs4_tuned_aops_hw = {
	.readpage	= vdfs4_readpage_tuned_hw_retry,
};
#else
const struct address_space_operations vdfs4_tuned_aops_hw = {
	.readpage	= vdfs4_readpage_tuned_hw,
};
#endif /* CONFIG_VDFS4_RETRY */
#endif /* VDFS4_HW_DECOMPRESS_SUPPORT */

static int vdfs4_fail_migrate_page(struct address_space *mapping,
			struct page *newpage, struct page *page,
				enum migrate_mode mode)
{
#ifdef CONFIG_MIGRATION
	return fail_migrate_page(mapping, newpage, page);
#else
	return -EIO;
#endif
}


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
	.rename		= vdfs4_rename,
	.setattr	= vdfs4_setattr,

	.setxattr	= vdfs4_setxattr,
	.getxattr	= vdfs4_getxattr,
	.removexattr	= vdfs4_removexattr,
	.listxattr	= vdfs4_listxattr,
#ifdef VDFS4_POSIX_ACL
	.get_acl	= vdfs4_get_acl,
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
	.readdir	= vdfs4_readdir,
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

	ret = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (ret)
		return ret;

	if (!datasync || (inode->i_state & I_DIRTY_DATASYNC)) {
		down_read(&sb->s_umount);
		ret = sync_filesystem(sb);
		up_read(&sb->s_umount);
	}

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
 * @param [in]	iov	Struct for writing data
 * @param [in]	nr_segs	Number of segs to write
 * @param [in]	pos	Position to write from
 * @return		Returns number of bytes written or an error code
 */
static ssize_t vdfs4_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos)
{
	ssize_t ret = 0;

	/* We are trying to write iocb->ki_left bytes from iov->iov_base */
	ret = generic_file_aio_write(iocb, iov, nr_segs, pos);

	return ret;
}

/**
 * @brief		VDFS4 function for aio read
 * @param [in]	iocb	Struct describing reading file
 * @param [in]	iov	Struct for read data
 * @param [in]	nr_segs	Number of segs to read
 * @param [in]	pos	Position to read from
 * @return		Returns number of bytes read or an error code
 */
static ssize_t vdfs4_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos)
{
	struct inode *inode = INODE(iocb);
	ssize_t ret;

#ifdef CONFIG_VDFS4_EXEC_ONLY_AUTHENTICATED
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

	ret = generic_file_aio_read(iocb, iov, nr_segs, pos);
#if defined(CONFIG_VDFS4_DEBUG)
	if (ret < 0 && ret != -EIOCBQUEUED && ret != -EINTR)
		VDFS4_DEBUG_TMP("err = %d, ino#%lu name=%s",
			(int)ret, inode->i_ino, VDFS4_I(inode)->name);
#endif
	return ret;
}

static ssize_t vdfs4_file_splice_read(struct file *in, loff_t *ppos,
		struct pipe_inode_info *pipe, size_t len, unsigned int flags)
{
#ifdef CONFIG_VDFS4_EXEC_ONLY_AUTHENTICATED
	struct inode *inode = in->f_mapping->host;

	if (current_reads_only_authenticated(inode, false)) {
		VDFS4_ERR("read is not permited:  %lu:%s",
				inode->i_ino, VDFS4_I(inode)->name);
#ifndef CONFIG_VDFS4_DEBUG_AUTHENTICAION
		return -EPERM;
#endif
	}
#endif

	return generic_file_splice_read(in, ppos, pipe, len, flags);
}


#ifdef CONFIG_VDFS4_EXEC_ONLY_AUTHENTICATED
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
				VDFS4_DEBUG_TMP("Try to execute non-auth file %lu:%s",
						inode->i_ino,
						VDFS4_I(inode)->name);
			}
		}
#else
			VDFS4_ERR("Try to execute non-auth file %lu:%s",
				inode->i_ino,
				VDFS4_I(inode)->name);
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
#ifdef CONFIG_VDFS4_EXEC_ONLY_AUTHENTICATED
	struct inode *inode = file->f_dentry->d_inode;
	int ret = check_execution_available(inode, vma);
	if (ret)
		return ret;
#endif
	return generic_file_mmap(file, vma);
}

static int vdfs4_file_readonly_mmap(struct file *file,
		struct vm_area_struct *vma)
{
#ifdef CONFIG_VDFS4_EXEC_ONLY_AUTHENTICATED
	struct inode *inode = file->f_dentry->d_inode;
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
	.read		= do_sync_read,
	.aio_read	= vdfs4_file_aio_read,
	.write		= do_sync_write,
	.aio_write	= vdfs4_file_aio_write,
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
	.read		= do_sync_read,
	.aio_read	= vdfs4_file_aio_read,
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
};
/**
 * The eMMCFS files inode operations.
 */
static const struct inode_operations vdfs4_file_inode_operations = {
		/* FIXME & TODO is this correct : use same function as in
		vdfs4_dir_inode_operations? */
		/*.truncate	= vdfs4_file_truncate, depricated*/
		.setattr	= vdfs4_setattr,
		.setxattr	= vdfs4_setxattr,
		.getxattr	= vdfs4_getxattr,
		.removexattr	= vdfs4_removexattr,
		.listxattr	= vdfs4_listxattr,
};

static int vdfs4_fill_inode(struct inode *inode,
		struct vdfs4_catalog_folder_record *folder_val)
{
	int ret = 0;

	VDFS4_I(inode)->flags = le32_to_cpu(folder_val->flags);
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
		return ret;

	switch (descr.magic[0]) {
	case VDFS4_COMPR_DESCR_START:
		break;
	case VDFS4_MD5_AUTH:
	case VDFS4_SHA1_AUTH:
	case VDFS4_SHA256_AUTH:
#ifdef CONFIG_VDFS4_DATA_AUTHENTICATION
		set_vdfs4_inode_flag(inode, VDFS4_AUTH_FILE);
#endif
		break;
	default:
		return -EINVAL;
	}

	inode->i_size = (long long)le64_to_cpu(descr.unpacked_size);
	inode->i_fop = &vdfs4_tuned_file_operations;
	/* deny_write_access() */
	if (S_ISREG(inode->i_mode))
		atomic_set(&inode->i_writecount, -1);

	return ret;
}

static int vdfs4_init_hw_decompression(struct vdfs4_inode_info *inode_i)
{
#if (defined(CONFIG_VDFS4_USE_HW1_DECOMPRESS) \
		|| defined(CONFIG_VDFS4_USE_HW2_DECOMPRESS))
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

int vdfs4_init_file_decompression(struct vdfs4_inode_info *inode_i, int debug)
{
	struct inode *inode = &inode_i->vfs_inode;
	struct page **pages;
	struct vdfs4_comp_file_descr descr;
	int ret = 0;
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

	compr_type = get_comprtype_by_descr(&descr);

	switch (compr_type) {
	case VDFS4_COMPR_ZLIB:
	case VDFS4_COMPR_ZHW:
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
		sizeof(struct vdfs4_comp_file_descr);

	switch (descr.magic[0]) {
	case VDFS4_COMPR_DESCR_START:
		inode_i->fbc->hash_type = VDFS4_HASH_UNDEF;
		break;
	case VDFS4_MD5_AUTH:
		table_size_bytes += (unsigned long)VDFS4_MD5_HASH_LEN *
			(extents_num + 1lu) +
			(unsigned long)VDFS4_CRYPTED_HASH_LEN;
#ifdef CONFIG_VDFS4_DATA_AUTHENTICATION
		if (is_sbi_flag_set(VDFS4_SB(inode->i_sb), VOLUME_AUTH))
			inode_i->fbc->hash_fn = calculate_sw_hash_md5;
#endif
		inode_i->fbc->hash_type = VDFS4_HASH_MD5;
		inode_i->fbc->hash_len = VDFS4_MD5_HASH_LEN;
		break;
	case VDFS4_SHA1_AUTH:
		table_size_bytes += (unsigned long)VDFS4_SHA1_HASH_LEN *
			(extents_num + 1lu) +
			(unsigned long)VDFS4_CRYPTED_HASH_LEN;
#ifdef CONFIG_VDFS4_DATA_AUTHENTICATION
		if (is_sbi_flag_set(VDFS4_SB(inode->i_sb), VOLUME_AUTH))
			inode_i->fbc->hash_fn = calculate_sw_hash_sha1;
#endif
		inode_i->fbc->hash_type = VDFS4_HASH_SHA1;
		inode_i->fbc->hash_len = VDFS4_SHA1_HASH_LEN;
		break;
	case VDFS4_SHA256_AUTH:
		table_size_bytes += (unsigned long)VDFS4_SHA256_HASH_LEN *
			(extents_num + 1lu) +
			(unsigned long)VDFS4_CRYPTED_HASH_LEN;
#ifdef CONFIG_VDFS4_DATA_AUTHENTICATION
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

	start_idx = (long unsigned int)((inode_i->fbc->comp_size -
		table_size_bytes) >> PAGE_CACHE_SHIFT);
	start_offset = inode_i->fbc->comp_size - table_size_bytes;
	pages_num = (pgoff_t)(((inode_i->fbc->comp_size + PAGE_CACHE_SIZE - 1) >>
			PAGE_CACHE_SHIFT)) - start_idx;

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
		VDFS4_ERR("File based decompression crc mismatch: %s",
				inode_i->name);
		VDFS4_MDUMP("Original crc:", &descr.crc, sizeof(descr.crc));
		VDFS4_MDUMP("Calculated crc:", &crc, sizeof(crc));
		ret = -EINVAL;
		goto out;
	}
	inode_i->fbc->comp_table_start_offset = start_offset;
	inode_i->fbc->comp_extents_n = (__u32)extents_num;
	inode_i->fbc->log_chunk_size = (int)le32_to_cpu(descr.log_chunk_size);

	if (inode_i->fbc->hash_fn) {
		ret = vdfs4_verify_file_signature(inode_i, data);
		if (ret)
			goto out;
		ret = vdfs4_check_hash_meta(inode_i, &descr);
		if (ret)
			goto out;
		set_vdfs4_inode_flag(inode, VDFS4_AUTH_FILE);
	}

	inode->i_mapping->a_ops = &vdfs4_tuned_aops;

	vdfs4_init_hw_decompression(inode_i);
out:
	vunmap(data);

#ifdef CONFIG_VDFS4_RETRY
	if (ret) {
		for (i = 0; i < pages_num; i++) {
			lock_page(pages[i]);
			ClearPageUptodate(pages[i]);
			ClearPageChecked(pages[i]);
			page_cache_release(pages[i]);
			unlock_page(pages[i]);
		}
	} else
#endif
	for (i = 0; i < pages_num; i++) {
		mark_page_accessed(pages[i]);
		page_cache_release(pages[i]);
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

	inode = iget_locked(sbi->sb, (unsigned long)ino);

	if (!inode) {
		inode = ERR_PTR(-ENOMEM);
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
	} else if (record->key->record_type == VDFS4_CATALOG_DLINK_RECORD) {
		struct vdfs4_catalog_dlink_record *dlink = record->val;
		struct vdfs4_cattree_record *data_record;
		struct inode *data_inode;
		__u64 dlink_ino = le64_to_cpu(dlink->data_inode);

		if (tree->btree_type == VDFS4_BTREE_INST_CATALOG)
			dlink_ino += tree->start_ino;

		data_inode = ilookup(sbi->sb, (unsigned long)dlink_ino);
		if (!data_inode) {
			struct vdfs4_btree_record_info *rec_info =
					VDFS4_BTREE_REC_I((void *) record);
			struct vdfs4_btree *btree =
					rec_info->rec_pos.bnode->host;
			data_record = vdfs4_cattree_find_hlink(btree,
					le64_to_cpu(dlink->data_inode),
					VDFS4_BNODE_MODE_RO);
			if (IS_ERR(data_record)) {
				data_inode = ERR_CAST(data_record);
			} else {
				data_inode = vdfs4_get_inode_from_record(data_record,
						parent);
				vdfs4_release_record(
				(struct vdfs4_btree_gen_record *)data_record);
			}
		}
		if (IS_ERR(data_inode)) {
			ret = PTR_ERR(data_inode);
			goto error_exit;
		}
		if (!S_ISREG(data_inode->i_mode)) {
			iput(data_inode);
			ret = -EINVAL;
			goto error_exit;
		}

		folder_rec = &dlink->common;
		VDFS4_I(inode)->data_link.inode = data_inode;
		inode->i_size = (loff_t)le64_to_cpu(dlink->data_length);
		VDFS4_I(inode)->data_link.offset =
				le64_to_cpu(dlink->data_offset);
	} else {
		if (!is_sbi_flag_set(sbi, IS_MOUNT_FINISHED)) {
			ret = -EFAULT;
			goto error_exit;
		} else
			VDFS4_BUG();
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
		VDFS4_BUG_ON(VDFS4_I(inode)->name);
		VDFS4_I(inode)->name = new_name;
		VDFS4_I(inode)->parent_id = le64_to_cpu(key->parent_id);
	}

#ifdef CONFIG_VDFS4_DEBUG_AUTHENTICAION
	VDFS4_I(inode)->informed_about_fail_read = 0;
#endif

	if (record->key->record_type == VDFS4_CATALOG_DLINK_RECORD) {
		struct inode *data_inode = VDFS4_I(inode)->data_link.inode;
		struct vdfs4_inode_info *d_info = VDFS4_I(data_inode);

		if (is_vdfs4_inode_flag_set(VDFS4_I(inode)->data_link.inode,
				VDFS4_AUTH_FILE)) {
			set_vdfs4_inode_flag(inode, VDFS4_AUTH_FILE);
		}
		if (is_vdfs4_inode_flag_set(VDFS4_I(inode)->data_link.inode,
				VDFS4_READ_ONLY_AUTH))
			set_vdfs4_inode_flag(inode, VDFS4_READ_ONLY_AUTH);
		inode->i_mapping->a_ops = &vdfs4_data_link_aops;
		atomic_set(&inode->i_writecount, -1); /* deny_write_access() */

		if (S_ISLNK(inode->i_mode) && d_info->fbc &&
			(d_info->fbc->compr_type == VDFS4_COMPR_UNDEF)) {
			mutex_lock(&data_inode->i_mutex);
			if (d_info->fbc->compr_type == VDFS4_COMPR_UNDEF)
				ret = vdfs4_init_file_decompression(d_info, 1);
			mutex_unlock(&data_inode->i_mutex);
			if (ret)
				goto error_exit;
		}
	}

	if (is_vdfs4_inode_flag_set(inode, VDFS4_COMPRESSED_FILE)) {
		ret = vdfs4_prepare_compressed_file_inode(VDFS4_I(inode));
		if (ret)
			goto error_exit;
	}
	if (hlink_rec)
		vdfs4_release_record((struct vdfs4_btree_gen_record *)hlink_rec);

	unlock_new_inode(inode);

exit:
	if (tree->btree_type != VDFS4_BTREE_CATALOG) /*parent - install point*/
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
		inode->i_op =  &vdfs4_dir_inode_operations;
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

	VDFS4_DEBUG_INO("'%s' dir = %ld", dentry->d_name.name, dir->i_ino);

	if (dentry->d_name.len > VDFS4_FILE_NAME_LEN)
		return -ENAMETOOLONG;

	saved_name = kzalloc(dentry->d_name.len + 1, GFP_NOFS);
	if (!saved_name)
		return -ENOMEM;

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
	mutex_w_lock(sbi->catalog_tree->rw_tree_lock);
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
	mutex_w_unlock(sbi->catalog_tree->rw_tree_lock);

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
	return ret;

err_notree:
	mutex_w_unlock(sbi->catalog_tree->rw_tree_lock);
	vdfs4_free_inode_n(sbi, inode->i_ino, 1);
	inode->i_ino = 0;
err_unlock:
	clear_nlink(inode);
	iput(inode);
err_trans:
	vdfs4_stop_transaction(sbi);
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

	if (inode->i_ino < VDFS4_1ST_FILE_INO && inode->i_ino != VDFS4_ROOT_INO)
		return 0;

	vdfs4_start_writeback(sbi);
	mutex_w_lock(sbi->catalog_tree->rw_tree_lock);
	ret = __vdfs4_write_inode(sbi, inode);
	mutex_w_unlock(sbi->catalog_tree->rw_tree_lock);
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

struct inode *vdfs4_get_image_inode(struct vdfs4_sb_info *sbi,
		__u64 parent_id, __u8 *name, size_t name_len)
{
	struct inode *inode;
	struct vdfs4_cattree_record *record;

	mutex_r_lock(sbi->catalog_tree->rw_tree_lock);
	record = vdfs4_cattree_find(sbi->catalog_tree, parent_id, name, name_len,
			VDFS4_BNODE_MODE_RO);

	if (IS_ERR(record)) {
		/* Pass error code to return value */
		inode = (void *)record;
		goto err_exit;
	}

	inode = vdfs4_get_inode_from_record(record, NULL);
	vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
err_exit:
	mutex_r_unlock(sbi->catalog_tree->rw_tree_lock);
	return inode;
}
