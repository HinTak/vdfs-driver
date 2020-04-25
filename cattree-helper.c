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
#include "debug.h"
#include "cattree.h"


/**
 * @brief			Fill already allocated value area (file or
 *				folder) with data from VFS inode.
 * @param [in]	inode		The inode to fill value area with
 * @param [out] value_area	Pointer to already allocated memory area
 *				representing the corresponding eMMCFS object
 * @return			Returns 0 on success or type of record
 *				if it's < 0
 */
void vdfs4_fill_cattree_value(struct inode *inode, void *value_area)
{
	struct vdfs4_catalog_folder_record *comm_rec = value_area;

	vdfs4_get_vfs_inode_flags(inode);
	comm_rec->flags = cpu_to_le32(VDFS4_I(inode)->flags);

	/* TODO - set magic */
/*	memcpy(comm_rec->magic, get_magic(le16_to_cpu(comm_rec->record_type)),
			sizeof(VDFS4_CAT_FOLDER_MAGIC) - 1);*/
	comm_rec->file_mode = cpu_to_le16(inode->i_mode);
	comm_rec->uid = cpu_to_le32(i_uid_read(inode));
	comm_rec->gid = cpu_to_le32(i_gid_read(inode));

	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
		comm_rec->total_items_count = cpu_to_le64(inode->i_rdev);
	else
		comm_rec->total_items_count = cpu_to_le64(inode->i_size);

	comm_rec->links_count = cpu_to_le64(inode->i_nlink);

	comm_rec->creation_time = vdfs4_encode_time(inode->i_ctime);
	comm_rec->access_time = vdfs4_encode_time(inode->i_atime);
	comm_rec->modification_time = vdfs4_encode_time(inode->i_mtime);

	comm_rec->generation = cpu_to_le32(inode->i_generation);
	comm_rec->next_orphan_id = cpu_to_le64(VDFS4_I(inode)->next_orphan_id);

	if (S_ISLNK(inode->i_mode) || S_ISREG(inode->i_mode)) {
		struct vdfs4_catalog_file_record *file_rec = value_area;
		vdfs4_form_fork(&file_rec->data_fork, inode);
	}
}


/**
 * @brief			Fill already allocated value area (hardlink).
 * @param [in]	inode		The inode to fill value area with
 * @param [out]	hl_record	Pointer to already allocated memory area
 *				representing the corresponding eMMCFS
 *				hardlink object
 * @return	void
 */
void vdfs4_fill_hlink_value(struct inode *inode,
		struct vdfs4_catalog_hlink_record *hl_record)
{
	hl_record->file_mode = cpu_to_le16(inode->i_mode);
}

