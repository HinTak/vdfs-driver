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

/**
 * @brief		Prints super block parameters
 * @param [in] sbi	Pointer to super block info data structure
 * @return		void
 */
#if defined(CONFIG_VDFS4_DEBUG)
void vdfs4_debug_print_sb(struct vdfs4_sb_info *sbi)
{
	VDFS4_DEBUG_SB("\nbytes in block = %u\n"\
			"volume blocks count = %llu\n"
			"free blocks count = %llu\n"
			"files count = %llu",
			sbi->block_size,
			sbi->volume_blocks_count,
			sbi->free_blocks_count,
			sbi->files_count);
}
#endif

/**
 * @brief			free debug area.
 * @param [in] debug_pages	allocated pages for debug area
 * @param [in] pagecount count of allocated page.
 * @param [in] debug_area virtual address (vmapped pages)
 * @return			0 - if successfully or error code otherwise
 */
static int _free_debug_area(struct page **debug_pages,
			__le64 page_count, void *debug_area)
{
	__le64 count;
	sector_t  debug_page_count;
	if (!debug_pages||!debug_area)
		return -EINVAL;
	vunmap(debug_area);
	for (count = 0; count < page_count; count++)
		__free_page(debug_pages[count]);
	kfree(debug_pages);
	return 0;
}

/**
 * @brief			read debug area. It should sync with _free_debug_area()
 * @param [in] sbi	Pointer to super block info data structure
 * @param [out] debug_pages allocated pages for debug area
 * @param [out] page_count page count of debug area
 * @param [out] debug_area virtual address (vmapped pages)
 * @return			0 - if successfully or error code otherwise
 */
static int _load_debug_area( struct vdfs4_sb_info *sbi,
			struct page ***debug_pages, int *page_count,
			void **debug_area)
{
	int ret = 0, count;
	sector_t debug_area_start, debug_page_count;
	struct page **pages;
	void *vmapped_pages;
	if (!sbi||!debug_pages||!page_count||!debug_area)
		return -EINVAL;

	debug_area_start = ((struct vdfs4_layout_sb *)sbi->raw_superblock)
				->exsb.debug_area.begin;
	debug_page_count = ((struct vdfs4_layout_sb *)sbi->raw_superblock)
				->exsb.debug_area.length;

	pages = kzalloc(sizeof(struct page*)*debug_page_count,
				GFP_NOFS);
	if (!pages) {
		return -ENOMEM;
	}

	for (count = 0; count < (int)debug_page_count; count++) {
		pages[count] = alloc_page(GFP_NOFS|__GFP_ZERO);
		if (!pages[count]) {
			count--;
			for (; count >= 0; count--) {
				unlock_page(pages[count]);
				__free_page(pages[count]);
			}
			kfree(pages);
			return -ENOMEM;
		}
		lock_page(pages[count]);
	}

	ret = vdfs4_read_pages(sbi->sb->s_bdev, pages,
		debug_area_start << (PAGE_CACHE_SHIFT - SECTOR_SIZE_SHIFT),
		(unsigned int)debug_page_count);
	for (count = 0; count < (int)debug_page_count; count++) {
		unlock_page(pages[count]);
		if (!PageUptodate(pages[count]))
			ret = -EIO;
	}
	if (ret) {
		goto exit_free_pages;
	}

	vmapped_pages = 
		vdfs4_vmap(pages, debug_page_count, VM_MAP, PAGE_KERNEL);
	if (!vmapped_pages) {
		ret = -ENOMEM;
		goto exit_free_pages;
	}

	*debug_pages = pages;
	*page_count = (int)debug_page_count;
	*debug_area = vmapped_pages;
	return ret;

exit_free_pages:
	for (count = 0; count < (int)debug_page_count; count++)
		__free_page(pages[count]);
	kfree(pages);
	return ret;
}

static int _initialize_debug_area(void *debug_area)
{
	struct vdfs_dbg_area_map *debug_map =
		(struct vdfs_dbg_area_map*)debug_area;
	if (!debug_area)
		return -EINVAL;
	memset(debug_map, 0x00, sizeof(struct vdfs_dbg_area_map));
	memcpy(debug_map->magic, VDFS_DBG_AREA_MAGIC,
				sizeof(VDFS_DBG_AREA_MAGIC) - 1);
	debug_map->dbgmap_ver = VDFS_DBG_AREA_VER;
	return 0;
}

/**
 * @brief				Put err info into vdfs volume debug area
 * @param [in] sbi		Pointer to super block info data structure
 * @param [in] err_info 	error information
 * @param [in] debug_pages allocated debug pages for debug area
 * @param [in] debug_area vmapped debug area
 * @return				0 - if successfully or error code otherwise
 */
static int _put_err_info(struct vdfs4_sb_info *sbi,
			struct vdfs_err_info *err_info,
			struct page **debug_pages, void *debug_area)
{
	int ret=0;
	uint32_t ent_idx, count;
	sector_t debug_area_start, debug_page_count;
	struct vdfs_dbg_area_map *debug_map =
		(struct vdfs_dbg_area_map*)debug_area;

	if (!sbi || !err_info || !debug_pages || !debug_area)
		return -EINVAL;
	if (VDFS4_IS_READONLY(sbi->sb))
		return -EROFS;

	//set data
	if (memcmp(debug_map->magic, VDFS_DBG_AREA_MAGIC,
			sizeof(VDFS_DBG_AREA_MAGIC)-1)) {
		_initialize_debug_area(debug_area);
	}
	ent_idx = (debug_map->dbg.dbg_info.err_count)
					%VDFS_DBG_ERR_MAX_CNT;
	err_info->idx = debug_map->dbg.dbg_info.err_count;
	memcpy(&(debug_map->err.err_list[ent_idx]),
			err_info,
			sizeof(struct vdfs_err_info));
	debug_map->dbg.dbg_info.err_count += 1;

	//flush data
	debug_area_start = ((struct vdfs4_layout_sb *)
			    sbi->raw_superblock)->exsb.debug_area.begin;
	debug_page_count = ((struct vdfs4_layout_sb *)
			    sbi->raw_superblock)->exsb.debug_area.length;
	for (count = 0; count < (uint32_t)debug_page_count; count++) {
		sector_t sector_to_write =
			((debug_area_start + (sector_t)count)
				<<  (PAGE_CACHE_SHIFT - SECTOR_SIZE_SHIFT));
		lock_page(debug_pages[count]);
		set_page_writeback(debug_pages[count]);
		ret = vdfs4_write_page(sbi, debug_pages[count],
					sector_to_write, 8, 0, 1);
		unlock_page(debug_pages[count]);
		if (ret)
			return -EIO;
	}
	return ret;
}

/**
 * @brief			get vdfs err occured count
 * @param [in] debug_area vmapped debug area
 * @param [out] err_count err count of vdfs
 * @return			0 - if successfully or error code otherwise
 */
static int _get_err_count(void *debug_area, uint32_t *err_count)
{
	struct vdfs_dbg_area_map *debug_map =
		(struct vdfs_dbg_area_map*)debug_area;
	if (!debug_area || !err_count)
		return -EINVAL;

	if (memcmp(debug_map->magic, VDFS_DBG_AREA_MAGIC,
			sizeof(VDFS_DBG_AREA_MAGIC)-1)) { //In case of not dbg_area map
		*err_count = 0;
		return 0;
	}
	*err_count = debug_map->dbg.dbg_info.err_count;
	return 0;
}


#if defined(CONFIG_VDFS4_DEBUG)
/**
 * @brief get volume's update verification result
 * @param [in] debug_area vmapped debug area
 * @param [out] result 	volume verification result (1 is OK. 0 is FAIL)
 * @return				0 - if successfully or error code otherwise
 */
static int _get_volume_verification(
		void *debug_area, enum vdfs4_debug_img_verify_k *result)
{
	struct vdfs_dbg_area_map *debug_map =
		(struct vdfs_dbg_area_map*)debug_area;
	if (!debug_area || !result)
		return -EINVAL;

	if (memcmp(debug_map->magic, VDFS_DBG_AREA_MAGIC,
			sizeof(VDFS_DBG_AREA_MAGIC)-1)) {
		*result = vdfs4_debug_img_verify_no_data;
	} else {
		if (VDFS_DBG_VERIFY_OK == debug_map->dbg.dbg_info.verify_result)
			*result = vdfs4_debug_img_verify_ok;
		else if (VDFS_DBG_VERIFY_FAIL ==
			 debug_map->dbg.dbg_info.verify_result)
			*result = vdfs4_debug_img_verify_fail;
		else if (VDFS_DBG_VERIFY_START ==
			 debug_map->dbg.dbg_info.verify_result)
			*result = vdfs4_debug_img_verify_incompletion;
		else if (VDFS_DBG_VERIFY_MKFS ==
			 debug_map->dbg.dbg_info.verify_result)
			*result = vdfs4_debug_img_verify_mkfs_on_disk;
		else
			*result = vdfs4_debug_img_verify_no_data;
	}
	return 0;
}

/**
 * @brief				print volume update verification result in debug area
 * @param [in] sbi		Pointer to super block info data structure
 */
void vdfs4_debug_print_volume_verification(
		struct vdfs4_sb_info *sbi)
{
	int rtn;
	uint32_t err_cnt = 0;
	char bdev_name[BDEVNAME_SIZE];
	struct page **debug_pages=NULL;
	int page_count=0;
	void *debug_area=NULL;
	enum vdfs4_debug_img_verify_k result;
	if (!sbi)
		return;
	rtn = _load_debug_area( sbi, &debug_pages, &page_count, &debug_area);
	if (rtn) {
		VDFS4_ERR("Failed to read %s debug area.(rtn:%d)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), rtn);
		return;
	}
	if ((rtn = _get_volume_verification(debug_area, &result))) {
		VDFS4_ERR("Failed to get '%s' volume verification.(rtn:%d)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), rtn);
	}
	if ((rtn = _get_err_count(debug_area, &err_cnt))) {
		VDFS4_ERR("Failed to get '%s' volume err count.(rtn:%d)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), rtn);
	}
	_free_debug_area(debug_pages, page_count, debug_area);

	switch (result) {
	case vdfs4_debug_img_verify_ok:
		printk(KERN_NOTICE
			"vdfs4-NOTICE:%s volume verification result is no problem.(err_cnt:%u)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), err_cnt);
		break;
	case vdfs4_debug_img_verify_mkfs_on_disk:
		printk(KERN_NOTICE
			"vdfs4-NOTICE:%s volume mkfs on disk(err_cnt:%u)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), err_cnt);
		break;
	case vdfs4_debug_img_verify_incompletion:	//it was stoped while seret update.
		printk( KERN_ERR
			"vdfs4-ERR:%s volume was stoped while updating.(err_cnt:%u)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), err_cnt);
		break;
	case vdfs4_debug_img_verify_fail:	//It used crc mismatch image file.
		printk( KERN_ERR
			"vdfs4-ERR:%s was updated with invalid(crc mismatch) vdfs image.(err_cnt:%u)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), err_cnt);
		break;
	case vdfs4_debug_img_verify_no_data:	//no data case (ex>opt,swu,dd....)
	default:
		printk(KERN_WARNING
			"vdfs4-WARNING:%s doesn't have volume verification result.(err_cnt:%u)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), err_cnt);
		break;
	}
	if (err_cnt) {
		printk(KERN_ERR
			"vdfs4-ERR:%s volume have error count (err_cnt:%u)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), err_cnt);
	}
	return;
}
#endif

/**
 * @brief				print error count and list in debug area
 * @param [in] sbi		Pointer to super block info data structure
 */
void vdfs4_debug_print_err_list(struct vdfs4_sb_info *sbi)
{
	return;
}

/**
 * @brief				get error count of vdfs4 volume
 * @param [in] sbi		Pointer to super block info data structure
 * @param [out] result 	error count
 * @return				0 - if successfully or error code otherwise
 */
int vdfs4_debug_get_err_count(struct vdfs4_sb_info *sbi, uint32_t *err_count)
{
	int rtn;
	char bdev_name[BDEVNAME_SIZE];
	struct page **debug_pages=NULL;
	int page_count=0;
	void *debug_area=NULL;

	if (!sbi || !err_count)
		return -EINVAL;
	rtn = _load_debug_area( sbi, &debug_pages, &page_count, &debug_area);
	if (rtn) {
		VDFS4_ERR("Failed to load %s debug area.(rtn:%d)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), rtn);
		return rtn;
	}
	rtn = _get_err_count(sbi, err_count);
	_free_debug_area( debug_pages, page_count, debug_area);
	return rtn;
}

/**
 * @brief					Put err info into vdfs volume debug area
 * @param [in] sbi			Pointer to super block info data structure
 * @param [in] err_type 		error information
 * @param [in] page_idx 	page index of error
 * @param [in] pages_count 	page length
 * @param [in] note 		note
 * @return					0 - if successfully or error code otherwise
 */
int vdfs4_debug_put_err(struct vdfs4_sb_info *sbi,
	uint16_t err_type, uint32_t proof_1, uint32_t proof_2,
	const uint8_t *note)
{
	int rtn;
	char bdev_name[BDEVNAME_SIZE];
	struct page **debug_pages=NULL;
	int page_count=0;
	void *debug_area=NULL;
	struct vdfs_err_info err_info;

	if (!sbi)
		return -EINVAL;
	if (VDFS4_IS_READONLY(sbi->sb))
		return -EROFS;
	memset(&err_info, 0x00, sizeof(struct vdfs_err_info));
	err_info.vdfs_err_type_k = err_type;
	err_info.proof[0] = proof_1;
	err_info.proof[1] = proof_1;
	if (note)
		strncpy(err_info.note, note, sizeof(err_info.note));
	rtn = _load_debug_area(sbi, &debug_pages, &page_count, &debug_area);
	if (rtn) {
		VDFS4_ERR("Failed to load %s debug area.(rtn:%d)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), rtn);
		return rtn;
	}
	rtn = _put_err_info(sbi, &err_info, debug_pages, debug_area);
	if (rtn) {
		VDFS4_ERR("Failed to put %s err_info(rtn:%d)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), rtn);
	}
	_free_debug_area( debug_pages, page_count, debug_area);
	return rtn;
}

