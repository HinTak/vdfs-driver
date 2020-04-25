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

#include "vdfs4.h"
#include <linux/mount.h>
#include <linux/compat.h>
#include <linux/version.h>
#include <linux/file.h>
#include <../fs/internal.h>
#include <linux/namei.h>
#include <linux/buffer_head.h>

static int vdfs4_set_type_status(struct vdfs4_inode_info *inode_i,
		unsigned int status)
{
	struct vdfs4_sb_info *sbi = inode_i->vfs_inode.i_sb->s_fs_info;
	struct inode *inode = &inode_i->vfs_inode;
	int ret = 0;
#ifdef CONFIG_VDFS4_RETRY
	int retry_count = 0;
#endif
	if (inode->i_size == 0)
		return 0;
	if (status && (!is_vdfs4_inode_flag_set(inode, VDFS4_COMPRESSED_FILE))) {
		/* Write and flush, tuned inodes are read via bdev cache */
		filemap_write_and_wait(inode_i->vfs_inode.i_mapping);
		invalidate_bdev(inode->i_sb->s_bdev);
	} else if (status)
		return 0;

	mutex_lock(&inode->i_mutex);
	vdfs4_start_transaction(sbi);
	if (atomic_read(&inode_i->open_count) != 1) {
		ret = -EBUSY;
		goto out;
	}
	if (status) {
#ifdef CONFIG_VDFS4_RETRY
retry:
#endif
		ret = vdfs4_prepare_compressed_file_inode(inode_i);
		if (!ret)
			set_vdfs4_inode_flag(&inode_i->vfs_inode,
				VDFS4_COMPRESSED_FILE);
#ifdef CONFIG_VDFS4_RETRY
		else if (retry_count < 3) {
			retry_count++;
			VDFS4_ERR("init decompression retry %d",
					retry_count);
			goto retry;
		} else

#else
		else if (ret != -EOPNOTSUPP)
#endif
			goto out;
		ret = 0;
	}
	if (!is_vdfs4_inode_flag_set(inode, VDFS4_COMPRESSED_FILE)) {
		if (status) {
			VDFS4_ERR("Not compressed file");
			ret = -EINVAL;
		} else {
			ret = 0;
		}
		goto out;
	}
	if (!status) {
		if (is_vdfs4_inode_flag_set(inode, VDFS4_COMPRESSED_FILE)) {
			ret = vdfs4_disable_file_decompression(inode_i);
			if (ret)
				goto out;
			clear_vdfs4_inode_flag(&inode_i->vfs_inode,
					VDFS4_COMPRESSED_FILE);
		}
	}
	mark_inode_dirty(&inode_i->vfs_inode);

out:
	vdfs4_stop_transaction(sbi);
	mutex_unlock(&inode->i_mutex);

	return ret;
}

static __u8 vdfs4_get_type_status(struct vdfs4_inode_info *inode_i)
{
	return test_bit(VDFS4_COMPRESSED_FILE, &inode_i->flags) ? 1 : 0;
}

static __u32 vdfs4_get_compr_type(struct vdfs4_inode_info *inode_i)
{
	return inode_i->fbc == NULL ? VDFS4_COMPR_UNDEF :
			 (__u32)inode_i->fbc->compr_type;
}

static __u32 vdfs4_get_auth_status(struct vdfs4_inode_info *inode_i)
{
	return inode_i->flags & ((1 << VDFS4_AUTH_FILE) |
			(1 << VDFS4_READ_ONLY_AUTH));
}

static int vdfs4_get_encryption_status(struct vdfs4_inode_info *inode_i)
{
	return (int)(inode_i->flags & ((1 << VDFS4_ENCRYPTED_FILE)));
}

/**
 * @brief	ioctl (an abbreviation of input/output control) is a system
 *		call for device-specific input/output operations and other
 *		 operations which cannot be expressed by regular system calls
 * @param [in]	filp	File pointer.
 * @param [in]	cmd	IOCTL command.
 * @param [in]	arg	IOCTL command arguments.
 * @return		0 if success, error code otherwise.
 */
long vdfs4_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int flags;
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct vdfs4_sb_info *sbi = inode->i_sb->s_fs_info;
	int ret;

	switch (cmd) {
	case FS_IOC_SETFLAGS:
	case VDFS4_IOC_SET_DECODE_STATUS:
		ret = mnt_want_write_file(filp);
		if (ret)
			return ret;
	default:
		break;
	}

	switch (cmd) {
	case FS_IOC_GETFLAGS:
		flags = 0;
		vdfs4_get_vfs_inode_flags(inode);
		if (VDFS4_I(inode)->flags & (1 << VDFS4_IMMUTABLE))
			flags |= FS_IMMUTABLE_FL;
		ret = put_user((unsigned)(flags & FS_FL_USER_VISIBLE),
				(int __user *) arg);
		break;
	case FS_IOC_SETFLAGS:
		if (!inode_owner_or_capable(inode)) {
			ret = -EACCES;
			break;
		}

		if (get_user(flags, (int __user *) arg)) {
			ret = -EFAULT;
			break;
		}

		mutex_lock(&inode->i_mutex);

		/*
		 * The IMMUTABLE flag can only be changed by the relevant
		 * capability.
		 */
		if ((flags & FS_IMMUTABLE_FL) &&
			!capable(CAP_LINUX_IMMUTABLE)) {
			ret = -EPERM;
			goto unlock_inode_exit;
		}

		/* don't silently ignore unsupported flags */
		if (flags & ~FS_IMMUTABLE_FL) {
			ret = -EOPNOTSUPP;
			goto unlock_inode_exit;
		}

		vdfs4_start_transaction(sbi);
		if (flags & FS_IMMUTABLE_FL)
			VDFS4_I(inode)->flags |= (1u <<
					(unsigned)VDFS4_IMMUTABLE);
		else
			VDFS4_I(inode)->flags &= ~(1u <<
					(unsigned)VDFS4_IMMUTABLE);
		vdfs4_set_vfs_inode_flags(inode);
		inode->i_ctime = vdfs4_current_time(inode);
		mark_inode_dirty(inode);
		vdfs4_stop_transaction(sbi);

unlock_inode_exit:
		mutex_unlock(&inode->i_mutex);
		break;
	case VDFS4_IOC_GET_OPEN_COUNT:
		ret = put_user(atomic_read(&(VDFS4_I(inode)->open_count)),
			(int __user *) arg);
		break;
	case VDFS4_IOC_SET_DECODE_STATUS:
		ret = -EFAULT;
		if (get_user(flags, (int __user *) arg))
			break;
		ret = vdfs4_set_type_status(VDFS4_I(inode), (unsigned)flags);
		break;
	case VDFS4_IOC_GET_DECODE_STATUS:
		ret = put_user(vdfs4_get_type_status(VDFS4_I(inode)),
			(int __user *) arg);
		break;
	case VDFS4_IOC_GET_COMPR_TYPE:
		ret = put_user((int)vdfs4_get_compr_type(VDFS4_I(inode)),
			(int __user *) arg);
		break;
	case VDFS4_IOC_IS_AUTHENTICATED:
		ret = put_user((int)vdfs4_get_auth_status(VDFS4_I(inode)),
				(int __user *) arg);
		break;
	case VDFS4_IOC_IS_ENCRYPTED:
		ret = put_user((int)vdfs4_get_encryption_status(VDFS4_I(inode)),
				(int __user *) arg);
		break;
	case VDFS4_IOC_GET_FILE_INFORMATION:
#ifdef CONFIG_VDFS4_DEBUG
		if (arg != 0) {
			struct vdfs4_ioc_file_info ioc_file_info;
			memset( &ioc_file_info, 0x0, sizeof(struct vdfs4_ioc_file_info));
			ioc_file_info.open_count = 
				atomic_read(&(VDFS4_I(inode)->open_count));
			ioc_file_info.compressed_status = 
				vdfs4_get_type_status(VDFS4_I(inode));
			ioc_file_info.compressed_type = 
				(int)vdfs4_get_compr_type(VDFS4_I(inode));
			ioc_file_info.authenticated_status = 
				(int)vdfs4_get_auth_status(VDFS4_I(inode));
			ioc_file_info.encryption_status = 
				(int)vdfs4_get_encryption_status(VDFS4_I(inode));
			ioc_file_info.extents_num = 
				VDFS4_I(inode)->fork.used_extents;
			ioc_file_info.size = inode->i_size;
			if (ioc_file_info.compressed_status 
						&& VDFS4_I(inode)->fbc != NULL) {
				struct vdfs4_comp_extent *raw_extent;
				loff_t extent_offset;
				pgoff_t page_idx;
				struct page **pages;
				int pos, chunk_extable_size, pages_count, i;
				void *data;

				/* Copy comp info */
				ioc_file_info.compressed_size = VDFS4_I(inode)->fbc->comp_size;
				ioc_file_info.chunk_cnt = VDFS4_I(inode)->fbc->comp_extents_n;

				/* Count comp/uncomp chunk */
				extent_offset = VDFS4_I(inode)->fbc->comp_table_start_offset;
				page_idx = (pgoff_t)extent_offset >> PAGE_CACHE_SHIFT;
				pos = extent_offset & (PAGE_CACHE_SIZE - 1);
				chunk_extable_size = 
					ioc_file_info.chunk_cnt * sizeof(struct vdfs4_comp_extent);
				pages_count = ((pos+chunk_extable_size) / 4096) + 1;
				pages = kmalloc(pages_count * sizeof(*pages), GFP_NOFS);
				if (!pages) {
					ret = -ENOMEM;
					break;
				}

				ret = vdfs4_read_comp_pages( inode, page_idx, 
					pages_count, pages, VDFS4_FBASED_READ_M);
				if (ret) {
					kfree(pages);
					break;
				}
				data = vdfs4_vmap(pages, (unsigned int)pages_count, VM_MAP, PAGE_KERNEL);
				if (!data) {
					ret = -ENOMEM;
					kfree(pages);
					break;
				}
				raw_extent = (void*)((char *)data + pos);
				for (i=0;i < ioc_file_info.chunk_cnt;i++,raw_extent++) {
					if (raw_extent->flags & VDFS4_CHUNK_FLAG_UNCOMPR)
						ioc_file_info.uncompressed_chunk_cnt++;
					else
						ioc_file_info.compressed_chunk_cnt++;
				}
				vunmap(data);
				while (pages_count--) {
					lock_page(pages[pages_count]);
					ClearPageUptodate(pages[pages_count]);
					ClearPageChecked(pages[pages_count]);
					page_cache_release(pages[pages_count]);
					unlock_page(pages[pages_count]);
				}
				kfree(pages);
			}
			copy_to_user((void*)arg, 
						(void*)&ioc_file_info, 
						sizeof(struct vdfs4_ioc_file_info));
		} else {
			ret = -EINVAL;
		}
#else
		ret = -EINVAL;
#endif
		break;
	default:
		ret = -ENOTTY;
		break;
	}

	switch (cmd) {
	case FS_IOC_SETFLAGS:
	case VDFS4_IOC_SET_DECODE_STATUS:
		mnt_drop_write_file(filp);
	default:
		break;
	}

	return ret;
}

#ifdef CONFIG_COMPAT
long vdfs4_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	/* These are just misnamed, they actually get/put from/to user an int */
	switch (cmd) {
	case FS_IOC32_GETFLAGS:
		cmd = FS_IOC_GETFLAGS;
		break;
	case FS_IOC32_SETFLAGS:
		cmd = FS_IOC_SETFLAGS;
		break;
	case VDFS4_IOC32_GET_OPEN_COUNT:
		cmd = VDFS4_IOC_GET_OPEN_COUNT;
		break;
	default:
		return -ENOTTY;
	}
	return vdfs4_ioctl(filp, cmd, arg);
}
#endif /* CONFIG_COMPAT */

static int force_ro(struct super_block *sb)
{
	if (sb->s_writers.frozen != SB_UNFROZEN)
		return -EBUSY;

	shrink_dcache_sb(sb);
	sync_filesystem(sb);

	sb->s_readonly_remount = 1;
	smp_wmb();

	sb->s_flags = (sb->s_flags & ~(unsigned long)MS_RMT_MASK) |
		(unsigned long)MS_RDONLY;

	invalidate_bdev(sb->s_bdev);
	return 0;
}

/**
 * @brief	ioctl (an abbreviation of input/output control) is a system
 *		call for device-specific input/output operations and other
 *		operations which cannot be expressed by regular system calls
 * @param [in]	filp	File pointer.
 * @param [in]	cmd	IOCTL command.
 * @param [in]	arg	IOCTL command arguments.
 * @return		0 if success, error code otherwise.
 */
long vdfs4_dir_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct vdfs4_sb_info *sbi =
		((struct super_block *)inode->i_sb)->s_fs_info;
	struct super_block *sb = (struct super_block *)inode->i_sb;

	switch (cmd) {
	case VDFS4_IOC_FORCE_RO:
		ret = -EINVAL;
		if (test_option(sbi, FORCE_RO))
			break;
		down_write(&sb->s_umount);
		if (sb->s_root && sb->s_bdev && !(sb->s_flags & MS_RDONLY))
			force_ro(sb);

		up_write(&sb->s_umount);
		set_option(sbi, FORCE_RO);
		ret = 0;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}
