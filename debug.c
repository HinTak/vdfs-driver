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

#ifdef VDFS4_DEBUG_DUMP
static inline void dump_bnode(void *data, struct page **pages,
		unsigned int page_per_node, unsigned int node_size_bytes) {
	int count;

	if (*pages)
		for (count = 0; count < (int)page_per_node; count++)
			VDFS4_NOTICE("index:%lu phy addr:0x%llx\n",
				pages[count]->index,
				(unsigned long long int)
				page_to_phys(pages[count]));

	VDFS4_MDUMP("", data, node_size_bytes);
}

void vdfs4_dump_bnode(struct vdfs4_bnode *bnode, void *data)
{
	struct vdfs4_sb_info *sbi = bnode->host->sbi;
	const char *device = sbi->sb->s_id;

	mutex_lock(&sbi->dump_meta);

	VDFS4_NOTICE("VDFS4(%s): error in %pf", device,
		__builtin_return_address(0));
	dump_bnode(data, bnode->pages, bnode->host->pages_per_node,
			bnode->host->node_size_bytes);

	mutex_unlock(&sbi->dump_meta);
}

void vdfs4_dump_basetable(struct vdfs4_sb_info *sbi,
				struct vdfs4_base_table *table,
				unsigned int table_size) {

	struct vdfs4_base_table *base_t;
	unsigned int length;

	if (table && table_size) {
		VDFS4_MDUMP("dump base table:", (void *)table, table_size);
	} else if (sbi) {
		base_t = sbi->snapshot_info->base_t;
		length = VDFS4_LAST_TABLE_INDEX(sbi, VDFS4_LSFILE)
			* sizeof(struct vdfs4_base_table_record)
			+ sizeof(struct vdfs4_base_table);

		VDFS4_MDUMP("dump base table:", base_t, length);
	}
}
#else
static inline void dump_bnode(void *data, struct page **pages,
		unsigned int page_per_node, unsigned int node_size_bytes) {};
void vdfs4_dump_bnode(struct vdfs4_bnode *bnode, void *data) {};
void vdfs4_dump_basetable(struct vdfs4_sb_info *sbi,
		struct vdfs4_base_table *table, unsigned int table_size) {};
#endif

/**
 * @brief			free debug area.
 * @param [in] debug_pages	allocated pages for debug area
 * @param [in] page_count	count of allocated page.
 * @param [in] debug_area	virtual address (vmapped pages)
 * @return			0 - if successfully or error code otherwise
 */
static int _free_debug_area(struct page **debug_pages,
			__le64 page_count, void *debug_area)
{
	__le64 count;
	sector_t  debug_page_count;

	if (!debug_pages || !debug_area)
		return -EINVAL;
	vunmap(debug_area);
	for (count = 0; count < page_count; count++)
		__free_page(debug_pages[count]);
	kfree(debug_pages);
	return 0;
}

/**
 * @brief			read debug area. It should sync with _free_debug_area()
 * @param [in] sbi		Pointer to super block info data structure
 * @param [out] debug_pages	allocated pages for debug area
 * @param [out] page_count	page count of debug area
 * @param [out] debug_area	virtual address (vmapped pages)
 * @return			0 - if successfully or error code otherwise
 */
static int _load_debug_area(struct vdfs4_sb_info *sbi,
			struct page ***debug_pages, int *page_count,
			void **debug_area)
{
	int ret = 0, count;
	sector_t debug_area_start, debug_page_count;
	struct page **pages;
	void *vmapped_pages;

	if (!sbi || !debug_pages || !page_count || !debug_area)
		return -EINVAL;

	debug_area_start = ((struct vdfs4_layout_sb *)sbi->raw_superblock)
				->exsb.debug_area.begin;
	debug_page_count = ((struct vdfs4_layout_sb *)sbi->raw_superblock)
				->exsb.debug_area.length;

	pages = kzalloc(sizeof(struct page *)*debug_page_count,
				GFP_NOFS);
	if (!pages)
		return -ENOMEM;

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
	if (ret)
		goto exit_free_pages;

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
		(struct vdfs_dbg_area_map *)debug_area;
	if (!debug_area)
		return -EINVAL;
	memset(debug_map, 0x00, sizeof(struct vdfs_dbg_area_map));
	memcpy(debug_map->magic, VDFS_DBG_AREA_MAGIC,
				sizeof(VDFS_DBG_AREA_MAGIC) - 1);
	debug_map->dbgmap_ver = VDFS_DBG_AREA_VER;
	return 0;
}

static uint32_t _calc_crash_val(struct vdfs4_sb_info *sbi)
{
	struct timespec ts;
	u64 ret = 0;

	getnstimeofday(&ts);

	if (!is_sbi_flag_set(sbi, IS_MOUNT_FINISHED))
		ret = 10;	/* mount fail case */
	else if (ts.tv_sec - sbi->mount_time < 300)
		ret = 5;	/* crash happens within 5 min (300s) */

	return ret;
}

/**
 * @brief			Record err info into vdfs volume debug area
 * @param [in] sbi		Pointer to super block info data structure
 * @param [in] err_type		error type
 * @param [in] proof_1		error type
 * @param [in] proof_2		error type
 * @param [in] note		error type
 * @param [in] debug_pages	allocated debug pages for debug area
 * @param [in] debug_area	vmapped debug area
 * @return			0 - if successfully or error code otherwise
 */
static int _record_err_info(struct vdfs4_sb_info *sbi,
	uint16_t err_type, uint32_t proof_1, uint32_t proof_2,
	const uint8_t *note,
	struct page **debug_pages, void *debug_area)
{
	int ret = 0;
	uint32_t ent_idx, count;
	struct vdfs_err_info err_info;
	sector_t debug_area_start, debug_page_count;
	struct vdfs_dbg_area_map *debug_map =
		(struct vdfs_dbg_area_map *)debug_area;

	if (!sbi || !debug_pages || !debug_area)
		return -EINVAL;
	if (VDFS4_IS_READONLY(sbi->sb))
		return -EROFS;

	memset(&err_info, 0x0, sizeof(struct vdfs_err_info));
	err_info.vdfs_err_type_k = err_type;
	err_info.proof[0] = proof_1;
	err_info.proof[1] = proof_1;
	if (note)
		strncpy(err_info.note, note, sizeof(err_info.note));

	/* set data */
	if (memcmp(debug_map->magic, VDFS_DBG_AREA_MAGIC,
			sizeof(VDFS_DBG_AREA_MAGIC) - 1)) {
		_initialize_debug_area(debug_area);
	}
	ent_idx = (debug_map->dbg_info.err_count)
			% VDFS_DBG_ERR_MAX_CNT;
	err_info.idx = debug_map->dbg_info.err_count;
	memcpy(&(debug_map->err_list[ent_idx]),
			&err_info,
			sizeof(struct vdfs_err_info));
	debug_map->dbg_info.err_count += 1;
	count = _calc_crash_val(sbi);
	debug_map->dbg_info.crash_val += count;
	VDFS4_ERR("Crash Val : %d (Total : %d)\n", count,
		debug_map->dbg_info.crash_val);

	/* flush data */
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
		ret = vdfs4_write_page(sbi, sector_to_write, debug_pages[count],
				       0, PAGE_SIZE, 1);
		unlock_page(debug_pages[count]);
		if (ret)
			return -EIO;
	}
	return ret;
}

/**
 * @brief			get vdfs err occured count
 * @param [in] debug_area	vmapped debug area
 * @param [out] err_count	err count of vdfs
 * @return			0 - if successfully or error code otherwise
 */
static int _get_err_count(void *debug_area, uint32_t *err_count)
{
	struct vdfs_dbg_area_map *debug_map =
		(struct vdfs_dbg_area_map *)debug_area;

	if (!debug_area || !err_count)
		return -EINVAL;

	if (memcmp(debug_map->magic, VDFS_DBG_AREA_MAGIC,
			sizeof(VDFS_DBG_AREA_MAGIC)-1)) {
		/* In case of not dbg_area map */
		*err_count = 0;
		return 0;
	}
	*err_count = debug_map->dbg_info.err_count;
	return 0;
}

/**
 * @brief			get vdfs crash_val
 * @param [in] debug_area	vmapped debug area
 * @param [out] crash_val	crash_val of vdfs
 * @return			0 - if successfully or error code otherwise
 */
static int _get_crash_val(void *debug_area, uint32_t *crash_val)
{
	struct vdfs_dbg_area_map *debug_map =
		(struct vdfs_dbg_area_map *)debug_area;

	if (!debug_area || !crash_val)
		return -EINVAL;

	if (memcmp(debug_map->magic, VDFS_DBG_AREA_MAGIC,
			sizeof(VDFS_DBG_AREA_MAGIC)-1)) {
		/* In case of not dbg_area map */
		*crash_val = 0;
		return 0;
	}

	*crash_val = debug_map->dbg_info.crash_val;
	return 0;
}

/**
 * @brief			core function for printing volume info in debug area
 * @param [in] sbi		Pointer to super block info data structure
 * @param [in] debug_area	Pointer to debug area
 * @return			0 - result of verification
 */
static unsigned int _print_volume_verification(
		struct vdfs4_sb_info *sbi, void *debug_area)
{
	char bdev_name[BDEVNAME_SIZE];
	struct vdfs_dbg_area_map *map =
		(struct vdfs_dbg_area_map *)debug_area;
	unsigned int result;

	if (!sbi || !debug_area)
		return -EINVAL;

	result = map->dbg_info.verify_result;

	if (result != VDFS_DBG_VERIFY_NODATA &&
		memcmp(map->magic, VDFS_DBG_AREA_MAGIC,
		sizeof(VDFS_DBG_AREA_MAGIC) - 1)) {
		VDFS4_WARNING("%s wrong magic or volume verification info (0x%x)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), result);
		return result;
	}

	switch (result) {
	case VDFS_DBG_VERIFY_MKFS:
		VDFS4_NOTICE("%s volume mkfs on disk.\n",
			bdevname(sbi->sb->s_bdev, bdev_name));
		break;
	case VDFS_DBG_VERIFY_START:
		/* It was stopped while seret update. */
		VDFS4_ERR("%s volume was stoped while updating.\n",
			bdevname(sbi->sb->s_bdev, bdev_name));
		break;
	case VDFS_DBG_VERIFY_FAIL:
		/* It used crc mismatch image file. */
		VDFS4_ERR("%s was updated with invalid(crc mismatch) vdfs image.\n",
			bdevname(sbi->sb->s_bdev, bdev_name));
		break;
	case VDFS_DBG_VERIFY_NODATA:
		/* no data case (ex>otp,swu,dd,success update in seret, etc... */
		VDFS4_NOTICE("%s update success or no volume verification info\n",
			bdevname(sbi->sb->s_bdev, bdev_name));
		break;
	default:
		VDFS4_WARNING("%s wrong volume verification info (0x%x)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), result);
		break;
	}

	return result;
}

#ifdef CONFIG_VDFS4_DEBUG
/**
 * @brief			print volume update verification result in debug area
 * @param [in] sbi		Pointer to super block info data structure
 */
void vdfs4_print_volume_verification(struct vdfs4_sb_info *sbi)
{
	int rtn;
	uint32_t err_cnt = 0;
	char bdev_name[BDEVNAME_SIZE];
	struct page **debug_pages = NULL;
	int page_count = 0;
	void *debug_area = NULL;

	if (!sbi)
		return;

	rtn = _load_debug_area(sbi, &debug_pages, &page_count, &debug_area);

	if (rtn) {
		VDFS4_ERR("Failed to read %s debug area.(rtn:%d)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), rtn);
		return;
	}

	_print_volume_verification(sbi, debug_area);

	rtn = _get_err_count(debug_area, &err_cnt);
	if (rtn)
		VDFS4_ERR("Failed to get '%s' volume err count.(rtn:%d)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), rtn);
	if (err_cnt)
		VDFS4_ERR("%s volume have error count (err_cnt:%u)\n",
			  bdevname(sbi->sb->s_bdev, bdev_name), err_cnt);

	_free_debug_area(debug_pages, page_count, debug_area);
}
#endif

/**
 * @brief			get error count of vdfs4 volume
 * @param [in]  sbi		Pointer to super block info data structure
 * @param [out] err_count	error count
 * @return			0 - if successfully or error code otherwise
 */
int vdfs4_debug_get_err_count(struct vdfs4_sb_info *sbi, uint32_t *err_count)
{
	int rtn;
	char bdev_name[BDEVNAME_SIZE];
	struct page **debug_pages = NULL;
	int page_count = 0;
	void *debug_area = NULL;

	if (!sbi || !err_count)
		return -EINVAL;
	rtn = _load_debug_area(sbi, &debug_pages, &page_count, &debug_area);
	if (rtn) {
		VDFS4_ERR("Failed to load %s debug area.(rtn:%d)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), rtn);
		return rtn;
	}
	rtn = _get_err_count(sbi, err_count);
	_free_debug_area(debug_pages, page_count, debug_area);
	return rtn;
}

/**
 * @brief			check debug area of vdfs4 volume
 * @param [in]  sbi		Pointer to super block info data structure
 * @return			0 - No problem in debug area
 */
int vdfs4_debugarea_check(struct vdfs4_sb_info *sbi)
{
	int rtn;
	char bdev_name[BDEVNAME_SIZE];
	struct page **debug_pages = NULL;
	unsigned int result;
	int page_count = 0;
	void *debug_area = NULL;
	int crash_val = 0;

	if (!sbi)
		return -EINVAL;

	rtn = _load_debug_area(sbi, &debug_pages, &page_count, &debug_area);
	if (rtn) {
		VDFS4_ERR("Failed to load %s debug area.(rtn:%d)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), rtn);
		/* return 0 as no problem */
		return 0;
	}

	result = _print_volume_verification(sbi, debug_area);
#ifdef CONFIG_VDFS4_DEBUG
	/* improperly update finished */
	if (result == VDFS_DBG_VERIFY_START || result == VDFS_DBG_VERIFY_FAIL) {
		VDFS4_ERR("%s image update or format was not finished completely\n",
			bdevname(sbi->sb->s_bdev, bdev_name));
		_free_debug_area(debug_pages, page_count, debug_area);
		return -EINVAL;
	}
#endif

#ifndef CONFIG_VDFS4_DEBUG
	/* NO working in Debug version to keep a problem status */
	_get_crash_val(debug_area, &crash_val);
	if (unlikely(crash_val >= 100)) {
		VDFS4_ERR("%s crash_val (%d) is bigger than 100\n",
			bdevname(sbi->sb->s_bdev, bdev_name), crash_val);
		rtn = -EINVAL;
	}
#endif

	_free_debug_area(debug_pages, page_count, debug_area);
	return rtn;
}

int vdfs4_dump_to_disk(void *mapped_chunk, size_t chunk_length,
			const char *name)
{
	int ret = 0;
	struct file *fd;
	char path[128];
	const char dir_path[] = "/mnt/systemrw";

	if (name == NULL || mapped_chunk == NULL)
		return -EINVAL;

	snprintf(path, 128, "%s/%s", dir_path, name);

	fd = filp_open((const char *)path,
			O_CREAT | O_WRONLY | O_TRUNC | O_SYNC, S_IRWXU);
	if (!IS_ERR(fd)) {
		loff_t pos;
		ssize_t written;
		mm_segment_t fs;

		pos = fd->f_path.dentry->d_inode->i_size;
		fs = get_fs();
		set_fs(KERNEL_DS);

		written = vfs_write(fd, mapped_chunk, chunk_length, &pos);
		if (written < 0) {
			VDFS4_ERR("cannot write to file %s err:%zd",
					path, written);
			ret = (int)written;
		}
		set_fs(fs);
		filp_close(fd, NULL);

		VDFS4_ERR("dump the chunk to file %s", path);
	} else {
		VDFS4_ERR("%s fails to dump", path);
	}

	return ret;
}

/**
 * @brief			table, debug area, extra info(ex:bnode) dump chunk
				and save kernel log into system rw
 * @param [in] sbi		Pointer to super block info data structure
 * @param [in] extra_buf	extra buf addr to dump chunk
 * @param [in] extra_len	length of extra buf to dump chunk
 * @return			0 - if successfully or error code otherwise
 */
static int vdfs4_dump_to_disk_all(struct vdfs4_sb_info *sbi,
				void *extra_buf, size_t extra_len)
{
	void *base;
	unsigned int length;
	struct page **pages = NULL;
	int page_count = 0;
	void *debug_area = NULL;

	/* 1. base table dump */
	base = (void *) sbi->snapshot_info->base_t;
	if (base) {
		length = VDFS4_LAST_TABLE_INDEX(sbi, VDFS4_LSFILE) *
			sizeof(struct vdfs4_base_table_record) +
			sizeof(struct vdfs4_base_table);

		if (length > 512 * 1024)
			length = 512 * 1024;

		vdfs4_dump_to_disk(base, length, "vdfs_basetable.dump");
	}

	/* 2. extra file dump */
	if (extra_buf)
		vdfs4_dump_to_disk(extra_buf, extra_len, "vdfs_extra.dump");

	/* 3. debug area dump */
	if (_load_debug_area(sbi, &pages, &page_count, &debug_area) == 0) {
		length = page_count << PAGE_CACHE_SHIFT;
		vdfs4_dump_to_disk(debug_area, length, "vdfs_debugarea.dump");
		_free_debug_area(pages, page_count, debug_area);
	}

	/* 4. kernel log dump */
	VDFS4_ERR("kernel log dump start\n");
	vdfs4_dump_to_disk((void *)log_buf_addr_get(), log_buf_len_get(),
				"vdfs_kernellog.dump");
	return 0;
}

/**
 * @brief			Put err info into vdfs volume debug area
 * @param [in] sbi		Pointer to super block info data structure
 * @param [in] err_type		error information
 * @param [in] proof_1		proof_1
 * @param [in] proof_2		proof_2
 * @param [in] note		note
 * @param [in] extra_buf	extra buf addr to dump
 * @param [in] extra_len	length of extra buf to dump
 * @return			0 - if successfully or error code otherwise
 */
int vdfs4_record_err_dump_disk(struct vdfs4_sb_info *sbi,
	uint16_t err_type, uint32_t proof_1, uint32_t proof_2,
	const uint8_t *note, void *extra_buf, size_t extra_len)
{
	int rtn;
	char bdev_name[BDEVNAME_SIZE];
	struct page **debug_pages = NULL;
	int page_count = 0;
	void *debug_area = NULL;
	uint32_t err_cnt = 0;

	if (!sbi)
		return -EINVAL;
	if (VDFS4_IS_READONLY(sbi->sb))
		return -EROFS;
	/*
	 * To keep first error info (preventing error count increation
	 * and initial dump info overwriting)
	 */
	if (atomic_inc_return(&sbi->running_errcnt) != 1)
		return -EINVAL;

	rtn = _load_debug_area(sbi, &debug_pages, &page_count, &debug_area);
	if (rtn) {
		VDFS4_ERR("Failed to load %s debug area.(rtn:%d)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), rtn);
		return rtn;
	}

	/* 1. print volume verification */
	_print_volume_verification(sbi, debug_area);

	rtn = _get_err_count(debug_area, &err_cnt);
	if (rtn)
		VDFS4_ERR("Failed to get '%s' volume err count.(rtn:%d)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), rtn);
	if (err_cnt)
		VDFS4_ERR("%s volume have error count (err_cnt:%u)\n",
			  bdevname(sbi->sb->s_bdev, bdev_name), err_cnt);


	/* 2. record error info into debug area */
	rtn = _record_err_info(sbi, err_type, proof_1, proof_2, note,
				debug_pages, debug_area);
	if (rtn) {
		VDFS4_ERR("Failed to put %s err_info(rtn:%d)\n",
			bdevname(sbi->sb->s_bdev, bdev_name), rtn);
		rtn = -EINVAL;
		goto dump_err;
	}

	/* 3. dump to disk (basetable, debug area, extra info and kernel log */
	vdfs4_dump_to_disk_all(sbi, extra_buf, extra_len);

dump_err:
	_free_debug_area(debug_pages, page_count, debug_area);

	return rtn;
}

/**
 * @brief		Print error message to kernel ring buffer.
 * @param [in]	fmt	Printf format string.
 * @return	void
 */
void VDFS4_MESSAGE(const char *func, const int line, const char *prefix,
		   const char *fmt, ...)
{
	char str[100];
	struct va_format vaf;
	va_list ap;

	va_start(ap, fmt);
	vaf.fmt = fmt;
	vaf.va = &ap;

	printk(KERN_ERR "%s%d:%s: %pV\n", prefix, line, func, &vaf);
	vsnprintf(str, sizeof(str), fmt, ap);
	va_end(ap);

	set_kpi_hw_error((char*)prefix, str);
}
