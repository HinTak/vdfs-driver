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

#include <linux/zlib.h>
#include <linux/stat.h>
#include <linux/namei.h>
#include <linux/vmalloc.h>
#include "vdfs4.h"
#include "debug.h"
#ifdef CONFIG_VDFS4_HW2_SUPPORT
#include <mach/hw_decompress.h>
#include <linux/blkdev.h>
#endif
#include <linux/lzo.h>


#define list_to_page(head) (list_entry((head)->prev, struct page, lru))
#define list_to_page_index(pos, head, index) \
	for (pos = list_entry((head)->prev, struct page, lru); \
		pos->index != index;\
	pos = list_entry((pos)->prev, struct page, lru))

static int sw_decompress(z_stream *strm, char *ibuff, int ilen,
	char *obuff, int olen, int compr_type)
{
	int rc = 0;

	strm->avail_out = (unsigned int)olen;
	strm->next_out = obuff;
	if (compr_type == VDFS4_COMPR_ZLIB) {
		strm->avail_in = (unsigned)ilen;
		strm->next_in = ibuff;
		rc = zlib_inflateInit(strm);
	} else if (compr_type == VDFS4_COMPR_GZIP) {
		strm->avail_in = (unsigned)(ilen - 10);
		strm->next_in = ibuff + 10;
		rc = zlib_inflateInit2(strm, -MAX_WBITS);
	} else {
		VDFS4_ERR("Unsupported compression type\n");
		return -EIO;
	}

	if (rc != Z_OK) {
		VDFS4_ERR("zlib_inflateInit error %d", rc);
		return rc;
	}

	rc = zlib_inflate(strm, Z_SYNC_FLUSH);
	if ((rc != Z_OK) && (rc != Z_STREAM_END)) {
		VDFS4_ERR("zlib_inflate error %d", rc);
		rc = (rc == Z_NEED_DICT) ? VDFS4_Z_NEED_DICT_ERR : rc;
		return rc;
	}

	rc = zlib_inflateEnd(strm);
	return rc;
}


#ifdef CONFIG_VDFS4_DEBUG

static void print_uncomp_err_dump_header(char *name, int name_len)
{
	VDFS4_ERR("--------------------------------------------------");
	VDFS4_ERR("Software decomression ERROR");
	VDFS4_ERR(" Current : %s(%d)", current->comm,
			task_pid_nr(current));
	VDFS4_ERR("--------------------------------------------------");
#if defined(VDFS4_GIT_BRANCH) && defined(VDFS4_GIT_REV_HASH) && \
		defined(VDFS4_VERSION)

	VDFS4_ERR("== VDFS4 Debugger - %15s ===== Core : %2d ===="
			, VDFS4_VERSION, current_thread_info()->cpu);
#endif
	VDFS4_ERR("--------------------------------------------------");
	VDFS4_ERR("Source image name : %.*s", name_len, name);
	VDFS4_ERR("--------------------------------------------------");
}

static void print_zlib_error(int unzip_error)
{
	switch (unzip_error) {
	case (Z_ERRNO):
		VDFS4_ERR("File operation error %d", Z_ERRNO);
		break;
	case (Z_STREAM_ERROR):
		VDFS4_ERR("The stream state was inconsistent %d",
				Z_STREAM_ERROR);
		break;
	case (Z_DATA_ERROR):
		VDFS4_ERR("Stream was freed prematurely %d", Z_DATA_ERROR);
		break;
	case (Z_MEM_ERROR):
		VDFS4_ERR("There was not enough memory %d", Z_MEM_ERROR);
		break;
	case (Z_BUF_ERROR):
		VDFS4_ERR("no progress is possible or if there was not "
				"enough room in the output buffer %d",
				Z_BUF_ERROR);
		break;
	case (Z_VERSION_ERROR):
		VDFS4_ERR("zlib library version is incompatible with"
			" the version assumed by the caller %d",
			Z_VERSION_ERROR);
		break;
	case (VDFS4_Z_NEED_DICT_ERR):
		VDFS4_ERR(" The Z_NEED_DICT error happened %d" ,
				VDFS4_Z_NEED_DICT_ERR);
		break;
	default:
		VDFS4_ERR("Unknown error code %d", unzip_error);
		break;
	}

}
#endif

#ifdef CONFIG_VDFS4_DEBUG
void vdfs4_dump_fbc_error(struct vdfs4_inode_info *inode_i, void *packed,
		struct vdfs4_comp_extent_info *cext)
{
	struct vdfs4_sb_info *sbi = VDFS4_SB(inode_i->vfs_inode.i_sb);
	char *fname = inode_i->name;
	int fname_len = fname ? (int)strlen(fname) : 0;
	void *chunk;
	char *file_name = NULL;
	int name_length;
	struct vdfs4_extent_info extent;
	int ret;

	mutex_lock(&sbi->dump_meta);
	_sep_printk_start();

	chunk = (char *)packed + cext->offset;
	print_uncomp_err_dump_header(fname, fname_len);

	memset(&extent, 0x0, sizeof(extent));
	ret = vdfs4_get_iblock_extent(&inode_i->vfs_inode,
				cext->start_block, &extent, 0);
	if (ret || (extent.first_block == 0))
		goto dump_to_console;


	file_name = kmalloc(VDFS4_FILE_NAME_LEN, GFP_NOFS);
	if (!file_name)
		VDFS4_ERR("cannot allocate space for file name\n");
	else {
		name_length = snprintf(file_name, VDFS4_FILE_NAME_LEN,
				"%lu_%.*s_%d_%llu_%d.dump",
			inode_i->vfs_inode.i_ino,
			strlen(fname),
			fname,
			(cext->flags & VDFS4_CHUNK_FLAG_UNCOMPR),
			((extent.first_block +
			cext->start_block) << 12) +
			(sector_t)cext->offset,
			1 << inode_i->fbc->log_chunk_size);


		if (name_length > 0)
			vdfs4_dump_chunk_to_disk(packed,
				(size_t)(1 << inode_i->fbc->log_chunk_size),
				(const char *)file_name, (unsigned)name_length);
	}
dump_to_console:

	/*
	for (count = 0; count < pages_num; count++)
		VDFS4_ERR("page index %lu phy addr:0x%llx",
				pages[count]->index,
				(long long unsigned int)
				page_to_phys(pages[count]));
	*/

	VDFS4_ERR("chunk info:\n\t"
			"offset = %llu\n\t"
			"len_bytes = %d\n\t"
			"blocks_n = %d\n\t"
			"is_uncompr = %d",
			((extent.first_block +
			cext->start_block) << 12) + (sector_t)cext->offset,
			cext->len_bytes, cext->blocks_n,
			cext->flags & VDFS4_CHUNK_FLAG_UNCOMPR);

	print_hex_dump(KERN_ERR, "", DUMP_PREFIX_ADDRESS, 16, 1, chunk,
			(size_t)cext->len_bytes, 1);

	_sep_printk_end();
	mutex_unlock(&sbi->dump_meta);
	kfree(file_name);
}
#endif

static int _unpack_chunk_zlib_gzip(void *src, void *dst, size_t offset,
		size_t len_bytes, size_t chunk_size, enum compr_type compr_type)
{
	z_stream strm;
	int ret = 0;

	strm.workspace =
		vdfs4_vmalloc((unsigned long)zlib_inflate_workspacesize());
	if (!strm.workspace)
		return -ENOMEM;

	ret = sw_decompress(&strm, (char *)src + offset, len_bytes, dst,
			chunk_size, compr_type);

	if (ret) {
#ifdef CONFIG_VDFS4_DEBUG
		print_zlib_error(ret);
#endif
		ret = -EIO;
	}

	vfree(strm.workspace);
	return ret;
}

int vdfs4_unpack_chunk_zlib(void *src, void *dst, size_t offset,
		size_t len_bytes, size_t chunk_size)
{
	return _unpack_chunk_zlib_gzip(src, dst, offset, len_bytes, chunk_size,
			VDFS4_COMPR_ZLIB);
}

int vdfs4_unpack_chunk_gzip(void *src, void *dst, size_t offset,
		size_t len_bytes, size_t chunk_size)
{
	return _unpack_chunk_zlib_gzip(src, dst, offset, len_bytes, chunk_size,
			VDFS4_COMPR_GZIP);
}

int vdfs4_unpack_chunk_lzo(void *src, void *dst, size_t offset,
		size_t len_bytes, size_t chunk_size)
{
	int res = 0;
	const unsigned char *packed_data;

	packed_data = (char *)src + offset;

	res = lzo1x_decompress_safe(packed_data, (size_t)len_bytes, dst,
			&chunk_size);
	if (res != LZO_E_OK)
		res = -EIO;

	return res;
}
