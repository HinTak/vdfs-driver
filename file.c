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

#include <linux/version.h>
#include "vdfs4.h"
#include "exttree.h"

/**
 * @brief			This function called when a file is opened with
 *				O_TRUNC or truncated with truncate()/
 *				ftruncate() system calls and truncate file
 *				exttree extents according new file size in
 *				blocks.
 * @param [in]	inode_info	inode_info pointer.
 * @param [in]	new_size	new file size in blocks.
 * @return			Returns TODO
 */
static int truncate_exttree(struct vdfs4_inode_info *inode_info,
	sector_t new_size)
{
	int ret = 0;
	__u64 object_id = inode_info->vfs_inode.i_ino;
	struct vdfs4_sb_info *sbi = inode_info->vfs_inode.i_sb->s_fs_info;
	struct vdfs4_exttree_record *record;
	struct vdfs4_fork_info *fork = &inode_info->fork;

	while (true) {
		__u64 iblock = 0;
		__u64 ext_off = 0;
		__u32 ext_len = 0;

		if (vdfs4_is_enospc(sbi, 25)) {
			mutex_w_unlock(sbi->extents_tree->rw_tree_lock);
			mutex_unlock(&inode_info->truncate_mutex);
			vdfs4_stop_transaction(sbi);
			flush_delayed_work(&sbi->delayed_commit);
			vdfs4_start_transaction(sbi);
			mutex_lock(&inode_info->truncate_mutex);
			mutex_w_lock(sbi->extents_tree->rw_tree_lock);
		}

		record = vdfs4_find_last_extent(sbi, object_id,
				VDFS4_BNODE_MODE_RW);
		if (IS_ERR(record)) {
			if (PTR_ERR(record) == -ENOENT)
				return 0;

			return PTR_ERR(record);
		}


		iblock = le64_to_cpu(record->key->iblock);
		ext_off = le64_to_cpu(record->lextent->begin);
		ext_len = le32_to_cpu(record->lextent->length);

		if (iblock >= new_size) {
			ret = vdfs4_fsm_put_free_block(inode_info,
					ext_off, ext_len, 0);
			if (ret) {
				VDFS4_ERR("can not free extent while "
						"truncating exttree "
						"ext_off = %llu "
						"ext_len = %u, err = %d",
						ext_off, ext_len, ret);
				break;
			}
			fork->total_block_count -= ext_len;
			inode_sub_bytes(&inode_info->vfs_inode,
				sbi->sb->s_blocksize * ext_len);
			vdfs4_release_record((struct vdfs4_btree_gen_record *)
					record);
			ret = vdfs4_exttree_remove(sbi->extents_tree,
					object_id, iblock);
			continue;
		} else if ((iblock + ext_len) > new_size) {
			u32 delta = (u32)(iblock + ext_len - new_size);
			ret = vdfs4_fsm_put_free_block(inode_info,
					ext_off + ext_len - delta, delta, 0);
			if (ret) {
				VDFS4_ERR("can not free part of extent while "
						"truncating exttree "
						"ext_off = %llu "
						"ext_len = %u, err = %d",
						ext_off, ext_len, ret);
				break;
			}

			record->lextent->length = cpu_to_le32(ext_len - delta);
			fork->total_block_count -= delta;
			inode_sub_bytes(&inode_info->vfs_inode,
				sbi->sb->s_blocksize * delta);
			vdfs4_mark_record_dirty((struct vdfs4_btree_gen_record *)
					record);
			break;
		} else {
			break;
		}
	}

	vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
	return ret;
}

/**
 * @brief			This function is called when a file is opened
 *				with O_TRUNC or truncated with truncate()/
 *				ftruncate() system calls and truncate internal
 *				fork according new file size in blocks.
 * @param [in]	inode_info	The inode_info pointer.
 * @param [in]	new_size	New file size in blocks.
 * @return	void
 */
static int truncate_fork(struct vdfs4_inode_info *inode_info,
		sector_t new_size_iblocks)
{
	struct vdfs4_fork_info *fork = &inode_info->fork;
	struct vdfs4_sb_info *sbi = inode_info->vfs_inode.i_sb->s_fs_info;
	int err = 0;
	unsigned int i;
	struct vdfs4_extent_info *extent = NULL;

	if (fork->used_extents == 0 ||
	    fork->extents[fork->used_extents - 1].iblock +
	    fork->extents[fork->used_extents - 1].block_count <=
						  new_size_iblocks)
		return 0;

	for (i = fork->used_extents; i > 0; i--) {
		extent = &fork->extents[i-1];
		if (extent->iblock >= new_size_iblocks) {
			err = vdfs4_fsm_put_free_block(inode_info,
				extent->first_block, extent->block_count, 0);
			if (err)
				goto exit;

			fork->total_block_count -= extent->block_count;
			inode_sub_bytes(&inode_info->vfs_inode,
				sbi->sb->s_blocksize * extent->block_count);
			fork->used_extents--;
			memset(extent, 0x0, sizeof(*extent));
		} else
			break;
	}

	if (extent->iblock + extent->block_count > new_size_iblocks) {
		sector_t block_count = extent->iblock + (u64)extent->block_count
				- new_size_iblocks;
		sector_t cut_from_block = extent->first_block +
				new_size_iblocks - extent->iblock;

		/* truncate extent */
		err = vdfs4_fsm_put_free_block(inode_info, cut_from_block,
				(u32)block_count, 0);
		if (err)
			goto exit;

		extent->block_count -= (u32)block_count;
		fork->total_block_count -= (u32)block_count;
		inode_sub_bytes(&inode_info->vfs_inode, (loff_t)
				(sbi->sb->s_blocksize *	block_count));
	}
exit:
	return err;
}

/**
 * @brief			This function is called when a file is opened
 *				with O_TRUNC or	truncated with truncate()/
 *				ftruncate() system calls.
 *				1) truncates exttree extents according to new
 *				file size.
 *				2) if fork intetnal extents contains more
 *				extents than new file size in blocks, internal
 *				fork also truncated.
 * @param [in]	inode		VFS inode pointer
 * @param [in]	new_size	New file size in bytes.
 * @return			Returns 0 on success, not null error code on
 *				failure.
 */
int vdfs4_truncate_blocks(struct inode *inode, loff_t new_size)
{
	int ret = 0;
	struct vdfs4_inode_info *inode_info = VDFS4_I(inode);
	struct vdfs4_fork_info *fork = &inode_info->fork;
	struct vdfs4_sb_info	*sbi = inode->i_sb->s_fs_info;
	sector_t new_size_iblocks;
	sector_t freed_runtime_iblocks;

	if (inode->i_ino < VDFS4_1ST_FILE_INO)
		VDFS4_BUG(sbi);
	if (!(S_ISREG(inode->i_mode) || S_ISLNK(inode->i_mode)))
		return -EPERM;

	new_size_iblocks = (sector_t)(new_size + sbi->block_size - 1ll) >>
			(sbi->block_size_shift);

	mutex_lock(&inode_info->truncate_mutex);

	VDFS4_DEBUG_FSM("truncate ino %lu\told_size %d\tnew_size %llu",
		inode->i_ino, fork->total_block_count, new_size);
	freed_runtime_iblocks = vdfs4_truncate_runtime_blocks(new_size_iblocks,
		&inode_info->runtime_extents);
	vdfs4_free_reserved_space(inode, freed_runtime_iblocks);
	if (fork->used_extents == VDFS4_EXTENTS_COUNT_IN_FORK) {
		mutex_w_lock(sbi->extents_tree->rw_tree_lock);
		ret = truncate_exttree(inode_info, new_size_iblocks);
		mutex_w_unlock(sbi->extents_tree->rw_tree_lock);
		if (ret)
			goto error_exit;
	}
	ret = truncate_fork(inode_info, new_size_iblocks);

error_exit:
	mutex_unlock(&inode_info->truncate_mutex);

	return ret;
}
