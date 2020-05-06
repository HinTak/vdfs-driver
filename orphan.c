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

static inline struct vdfs4_inode_info *
prev_orphan(struct vdfs4_sb_info *sbi, struct inode *inode)
{
	/*
	 * @inode must be in orphan list and not be the first,
	 */
	VDFS4_BUG_ON(list_empty(&VDFS4_I(inode)->orphan_list), sbi);
	VDFS4_BUG_ON(VDFS4_I(inode)->orphan_list.prev ==
					&sbi->orphan_inodes, sbi);

	return list_entry(VDFS4_I(inode)->orphan_list.prev,
			struct vdfs4_inode_info, orphan_list);
}

int vdfs4_add_to_orphan(struct vdfs4_sb_info *sbi, struct inode *inode)
{
	struct vdfs4_inode_info *prev;
	int ret = 0;

	set_vdfs4_inode_flag(inode, ORPHAN_INODE);
	VDFS4_I(inode)->next_orphan_id = 0;
	list_add_tail(&VDFS4_I(inode)->orphan_list, &sbi->orphan_inodes);

	prev = prev_orphan(sbi, inode);
	VDFS4_BUG_ON(prev->next_orphan_id != 0, sbi);
	prev->next_orphan_id = inode->i_ino;
	ret = __vdfs4_write_inode(sbi, &prev->vfs_inode);
	if (ret) {
		VDFS4_ERR("fail to add inode to orphan list:ino %lu %d",
				 inode->i_ino, ret);
		list_del_init(&VDFS4_I(inode)->orphan_list);
		prev->next_orphan_id = 0;
		clear_vdfs4_inode_flag(inode, ORPHAN_INODE);
		return ret;
	}
	mark_inode_dirty(&prev->vfs_inode);
	return 0;

}

#define FINAL_ORPHAN_ID ((u64) -1)
void vdfs4_del_from_orphan(struct vdfs4_sb_info *sbi, struct inode *inode)
{
	struct vdfs4_inode_info *prev;

	if (!list_empty(&VDFS4_I(inode)->orphan_list)) {
		int ret = 0;

		prev = prev_orphan(sbi, inode);
		VDFS4_BUG_ON(prev->next_orphan_id != inode->i_ino, sbi);
		prev->next_orphan_id = VDFS4_I(inode)->next_orphan_id;
		mark_inode_dirty(&prev->vfs_inode);
		ret = __vdfs4_write_inode(sbi, &prev->vfs_inode);
		if (ret) {
			vdfs4_fatal_error(sbi, "delete from orphan list");
			vdfs4_record_err_dump_disk(sbi, VDFS4_DEBUG_ERR_ORPHAN,
					inode->i_ino, 0, "fail delete orphan", NULL, 0);
		}
		clear_vdfs4_inode_flag(inode, ORPHAN_INODE);
		VDFS4_I(inode)->next_orphan_id = FINAL_ORPHAN_ID;
		list_del_init(&VDFS4_I(inode)->orphan_list);
	}
}

/**
 * @brief		After mount orphan inodes processing.
 * @param [in]	sbi	Superblock information structure pointer.
 * @return		Returns 0 on success, not null error code on failure.
 */
int vdfs4_process_orphan_inodes(struct vdfs4_sb_info *sbi)
{
	struct inode *root = sbi->sb->s_root->d_inode, *inode;

	while (VDFS4_I(root)->next_orphan_id) {
		inode = vdfs4_iget(sbi, (ino_t)VDFS4_I(root)->next_orphan_id);
		if (IS_ERR(inode))
			return -EINVAL;
		if (inode->i_nlink ||
		    !is_vdfs4_inode_flag_set(inode, ORPHAN_INODE)) {
			vdfs4_fatal_error(sbi,
					"non-orphan ino#%lu in orphan list",
					inode->i_ino);
			vdfs4_record_err_dump_disk(sbi, VDFS4_DEBUG_ERR_ORPHAN,
					inode->i_ino, 0, "non orphan", NULL, 0);
			return -EINVAL;
		}

		mutex_w_lock(sbi->catalog_tree->rw_tree_lock);
		list_add_tail(&VDFS4_I(inode)->orphan_list,
				&sbi->orphan_inodes);
		mutex_w_unlock(sbi->catalog_tree->rw_tree_lock);

		iput(inode); /* smash it */
	}

	return 0;
}
