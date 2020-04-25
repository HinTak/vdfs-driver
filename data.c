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

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/swap.h>
#include <linux/vmalloc.h>

#include "vdfs4.h"
#include "debug.h"
#include <linux/vdfs_trace.h>	/* FlashFS : vdfs-trace */

#ifdef CONFIG_VDFS4_HW_DECOMPRESS_SUPPORT
#include <mach/hw_decompress.h>
#endif

/**
 * @brief		Finalize IO writing.
 * param [in]	bio	BIO structure to be written.
 * param [in]	err	With error or not.
 * @return	void
 */
static void end_io_write(struct bio *bio, int err)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	struct bio_vec *bvec = bio->bi_io_vec + bio->bi_vcnt - 1;

	do {
		struct page *page = bvec->bv_page;

		if (--bvec >= bio->bi_io_vec)
			prefetchw(&bvec->bv_page->flags);
		if (!uptodate) {
			SetPageError(page);
			if (page->mapping)
				set_bit(AS_EIO, &page->mapping->flags);
		}
		end_page_writeback(page);
	} while (bvec >= bio->bi_io_vec);

	if (bio->bi_private)
		complete(bio->bi_private);
	bio_put(bio);
}

/**
 * @brief		Finalize IO writing.
 * param [in]	bio	BIO structure to be read.
 * param [in]	err	With error or not.
 * @return	void
 */
static void read_end_io(struct bio *bio, int err)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	struct bio_vec *bvec = bio->bi_io_vec + bio->bi_vcnt - 1;
	struct completion *wait = bio->bi_private;

	do {
		struct page *page = bvec->bv_page;

		if (--bvec >= bio->bi_io_vec)
			prefetchw(&bvec->bv_page->flags);

		if (uptodate) {
			SetPageUptodate(page);
		} else {
			ClearPageUptodate(page);
			SetPageError(page);
		}
	} while (bvec >= bio->bi_io_vec);
	complete(wait);
	bio_put(bio);
}

/**
 * @brief			Allocate new BIO.
 * @param [in]	bdev		The eMMCFS superblock information.
 * @param [in]	first_sector	BIO first sector.
 * @param [in]	nr_vecs		Number of BIO pages.
 * @return			Returns pointer to allocated BIO structure.
 */
static struct bio *__allocate_new_bio(struct block_device *bdev,
		sector_t first_sector, unsigned int nr_vecs)
{
	gfp_t gfp_flags = GFP_NOFS | __GFP_HIGH;
	struct bio *bio = NULL;
	sector_t s_count = (sector_t)(bdev->bd_inode->i_size >>
			SECTOR_SIZE_SHIFT);
	sector_t s_nr_vecs = (sector_t) nr_vecs * SECTOR_PER_PAGE;

	if ((first_sector > s_count) ||
		((first_sector + s_nr_vecs) > s_count))
		return ERR_PTR(-EFAULT);

	bio = bio_alloc(gfp_flags, nr_vecs);

	if (bio == NULL && (current->flags & PF_MEMALLOC)) {
		while (!bio && (nr_vecs /= 2))
			bio = bio_alloc(gfp_flags, nr_vecs);
	}

	if (bio) {
		bio->bi_bdev = bdev;
		bio->bi_iter.bi_sector = first_sector;
	}

	return bio;
}


int vdfs4_get_table_sector(struct vdfs4_sb_info *sbi, sector_t iblock,
		sector_t *result)
{
	struct vdfs4_layout_sb *l_sb = sbi->raw_superblock;
	struct vdfs4_extent *extent_table = &l_sb->exsb.tables;

	sector_t max_size = (sector_t)(sbi->sb->s_bdev->bd_inode->i_size >>
			SECTOR_SIZE_SHIFT);

	if (iblock > le64_to_cpu(extent_table->length))
		return -EINVAL;

	*result = (le64_to_cpu(extent_table->begin) + iblock);
	*result <<= (sbi->block_size_shift - SECTOR_SIZE_SHIFT);

	if (*result >= max_size)
		return -EINVAL;

	return 0;
}

static void show_all_meta_extents(struct vdfs4_sb_info *sbi)
{
	struct vdfs4_layout_sb *l_sb = sbi->raw_superblock;
	struct vdfs4_extent *extents = &l_sb->exsb.meta[0];
	int count;

	for (count = 0; count < VDFS4_META_BTREE_EXTENTS; count++) {
		if (!le64_to_cpu(extents->begin))
			continue;

		VDFS4_ERR("[%d] begin:%lld, length:%lld", count,
				le64_to_cpu(extents->begin),
				le64_to_cpu(extents->length));
		extents++;
	}
}

static int get_meta_block(struct vdfs4_sb_info *sbi, sector_t iblock,
		sector_t *result, sector_t *length)
{
	struct vdfs4_layout_sb *l_sb = sbi->raw_superblock;
	struct vdfs4_extent *extents = &l_sb->exsb.meta[0];
	int count;
	sector_t first_iblock = 0;
	sector_t last_iblock = 0;

	for (count = 0; count < VDFS4_META_BTREE_EXTENTS; count++) {
		last_iblock += le64_to_cpu(extents->length);
		if (iblock >= first_iblock && iblock < last_iblock) {
			sector_t offset = iblock - first_iblock;
			*result = (le64_to_cpu(extents->begin)) +
					offset;
			*length = (le32_to_cpu(extents->length)) -
					offset;
			return 0;
		}
		first_iblock = last_iblock;
		extents++;
	}

	VDFS4_ERR("Fail to find matched one with %llu", iblock);
	show_all_meta_extents(sbi);
	return -EINVAL;
}

int vdfs4_get_block_file_based(struct inode *inode, pgoff_t page_idx,
		sector_t *res_block)
{
	int ret = 0;
	struct vdfs4_extent_info pext;

	ret = vdfs4_get_iblock_extent(inode, page_idx, &pext, NULL);
	if (ret)
		return ret;

	*res_block = pext.first_block + page_idx -
		pext.iblock;

	return 0;
}

static int get_block_meta_wrapper(struct inode *inode, pgoff_t page_idx,
		sector_t *res_block, int type, sector_t start_block)
{
	struct vdfs4_sb_info *sbi = inode->i_sb->s_fs_info;
	sector_t meta_iblock, length, start_iblock;
	sector_t iblock;
	struct buffer_head bh_result;
	int ret = 0;


	switch (type) {
	case VDFS4_META_READ:
		VDFS4_BUG_ON((inode->i_ino < VDFS4_FSFILE) ||
				(inode->i_ino > VDFS4_LSFILE), sbi);
		/*
			need to protect against metadata translation table
			modification
		*/
		down_read(&sbi->snapshot_info->tables_lock);
		ret = vdfs4_get_meta_iblock(sbi, inode->i_ino, page_idx,
			&start_iblock);
		if (ret) {
			up_read(&sbi->snapshot_info->tables_lock);
			return ret;
		}

		meta_iblock = start_iblock;
		if (is_tree(inode->i_ino)) {
			unsigned int mask;

			mask = ((unsigned int)1 << (sbi->log_blocks_in_leb +
				sbi->block_size_shift -
				(unsigned int)PAGE_CACHE_SHIFT)) -
				(unsigned int)1;
			meta_iblock += (page_idx & (pgoff_t)mask)
				<< (PAGE_CACHE_SHIFT - sbi->block_size_shift);
		}
		*res_block = 0;
		ret = get_meta_block(sbi, meta_iblock, res_block, &length);
		up_read(&sbi->snapshot_info->tables_lock);
		VDFS4_BUG_ON(*res_block == 0, sbi);
		break;
	case VDFS4_PACKTREE_READ:
		bh_result.b_blocknr = 0;
		iblock = ((sector_t)page_idx) << (PAGE_CACHE_SHIFT -
				sbi->block_size_shift);
		ret = vdfs4_get_block(inode, iblock, &bh_result, 0);
		*res_block = bh_result.b_blocknr;
		break;
	case VDFS4_FBASED_READ_M:
	case VDFS4_FBASED_READ_C:
		*res_block = page_idx;
		break;
	case VDFS4_FBASED_READ_UNC:
		ret = vdfs4_get_block_file_based(inode, (pgoff_t)start_block +
			(page_idx & ((1lu <<
			(pgoff_t)((pgoff_t)VDFS4_I(inode)->fbc->log_chunk_size -
			(pgoff_t)PAGE_SHIFT)) - 1lu)), res_block);
		break;
	default:
		return -EINVAL;
	}

	return ret;
}

static void table_end_IO(struct bio *bio, int err)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	struct bio_vec *bvec = bio->bi_io_vec + bio->bi_vcnt - 1;

	do {
		struct page *page = bvec->bv_page;

		if (--bvec >= bio->bi_io_vec)
			prefetchw(&bvec->bv_page->flags);
		if (!uptodate)
			SetPageError(page);
		unlock_page(page);
	} while (bvec >= bio->bi_io_vec);

	bio_put(bio);
}

/**
 * @brief			Write meta data (struct page **)
 *				The function supports metadata fragmentation
 * @param [in]	sbi		The VDFS4 superblock information.
 * @param [in]	pages		Pointer to locked pages.
 * @param [in]	sector_addr	Start isector address.
 * @param [in]	page_count	Number of pages to be written.
 *				    and write snapshot head page in sync mode
 * @return			Returns 0 on success, errno on failure.
 */
int vdfs4_table_IO(struct vdfs4_sb_info *sbi, void *buffer,
		__u64 buffer_size, int rw, sector_t *iblock)
{
	struct block_device *bdev = sbi->sb->s_bdev;
	struct bio *bio;
	sector_t start_sector = 0;
	sector_t submited_pages = 0;
	int ret;
	unsigned int count = 0, nr_vectr;
	unsigned int pages_count = (unsigned int)DIV_ROUND_UP(buffer_size,
			(__u64)PAGE_SIZE);
	struct blk_plug plug;
	struct page *page;

	blk_start_plug(&plug);

	do {
		nr_vectr = (pages_count < BIO_MAX_PAGES) ? pages_count :
				BIO_MAX_PAGES;

		ret = vdfs4_get_table_sector(sbi, *iblock, &start_sector);
		if (ret)
			goto error_exit;

		start_sector += submited_pages << (PAGE_CACHE_SHIFT -
						SECTOR_SIZE_SHIFT);

		bio = __allocate_new_bio(bdev, start_sector, nr_vectr);
		if (IS_ERR_OR_NULL(bio)) {
			ret = -ENOMEM;
			goto error_exit;
		}

		bio->bi_end_io = table_end_IO;

		do {
			int size;

			page = vmalloc_to_page((char *)buffer +
					(submited_pages << PAGE_SHIFT));
			VDFS4_BUG_ON(!page, sbi);
			lock_page(page);
			size = bio_add_page(bio, page, PAGE_SIZE, 0);
			if (!size && (!bio->bi_vcnt)) {
				/* fail to add data into BIO */
				ret = -EFAULT;
				unlock_page(page);
				bio_put(bio);
				goto error_exit;
			} else if (!size) {
				/* no space left in bio */
				unlock_page(page);
				break;
			}
			pages_count--;
			submited_pages++;
		} while (pages_count > 0);
		submit_bio(rw, bio);

	} while (pages_count > 0);

error_exit:
	blk_finish_plug(&plug);

	for (count = 0; count < submited_pages; count++) {
		page = vmalloc_to_page((char *)buffer + (count << PAGE_SHIFT));
		VDFS4_BUG_ON(!page, sbi);
		wait_on_page_locked(page);
		if (TestClearPageError(page))
			ret = -EIO;
	}

	if (!ret)
		*iblock += submited_pages;

	return ret;
}

/**
 * @brief		Calculates count of pages needed for
 *				chunk after decompression
 * param [in]	inode Compressed file inode
 * param [in]	comp_extent_id	Chunk index
 * @return	int Page count
 */
static inline int vdfs4_chunk_page_count(struct inode *inode,
		int comp_extent_idx)
{
	struct vdfs4_inode_info *inode_i = VDFS4_I(inode);
	loff_t i_size;

	VDFS4_BUG_ON(!inode_i->fbc, VDFS4_SB(inode->i_sb));
	VDFS4_BUG_ON(comp_extent_idx >= inode_i->fbc->comp_extents_n,
		VDFS4_SB(inode->i_sb));

	/* size of all chunks except last one is
	 * 1 << inode_i->fbc->log_chunk_size */
	if (comp_extent_idx < (inode_i->fbc->comp_extents_n - 1))
		goto log_chunk_size;

	i_size = i_size_read(inode);
	/* get size of last chunk */
	i_size &= (loff_t)((1<<inode_i->fbc->log_chunk_size) - 1);

	/* i_size is aligned to (1<<inode_i->fbc->log_chunk_size) */
	if (!i_size)
		goto log_chunk_size;

	/* div round up by PAGE_SIZE */
	return (i_size + PAGE_CACHE_SIZE-1) >> PAGE_CACHE_SHIFT;

log_chunk_size:
	return (1 << (inode_i->fbc->log_chunk_size - PAGE_CACHE_SHIFT));
}

/**
 * @brief			Read page from the given sector address.
 *				Fill the locked page with data located in the
 *				sector address. Read operation is synchronous,
 *				and caller must unlock the page.
 *				Shall be used for sb/metadata only !
 * @param [in]	bdev		Pointer to block device.
 * @param [in]	page		Pointer to locked page.
 * @param [in]	sector_addr	Sector address.
 * @param [in]	page_count	Number of pages to be read.
 * @return			Returns 0 on success, errno on failure
 */
int vdfs4_read_pages(struct block_device *bdev,
			struct page **page,
			sector_t sector_addr,
			unsigned int pages_count)
{
	struct bio *bio;
	struct completion wait;
	unsigned int count = 0;
	int continue_load = 0;

	struct blk_plug plug;

	if (pages_count > BIO_MAX_PAGES || pages_count == 0) {
		VDFS4_ERR("wrong page_count to read : %d", pages_count);
		return -EINVAL;
	}

	init_completion(&wait);
again:
	blk_start_plug(&plug);

	/* Allocate a new bio */
	bio = __allocate_new_bio(bdev, sector_addr, pages_count);
	if (IS_ERR_OR_NULL(bio)) {
		blk_finish_plug(&plug);
		VDFS4_ERR("failed to allocate bio\n");
		return PTR_ERR(bio);
	}

	bio->bi_end_io = read_end_io;

	/* Initialize the bio */
	for (; count < pages_count; count++) {
		if ((unsigned) bio_add_page(bio, page[count],
				PAGE_CACHE_SIZE, 0) < PAGE_CACHE_SIZE) {
			if (bio->bi_vcnt) {
				continue_load = 1;
				sector_addr += ((sector_t)count <<
						(PAGE_CACHE_SHIFT - SECTOR_SIZE_SHIFT));
			} else {
				VDFS4_ERR("FAIL to add page to BIO");
				bio_put(bio);
				blk_finish_plug(&plug);
				return -EFAULT;
			}

			break;
		}
	}
	bio->bi_private = &wait;
	submit_bio(READ | REQ_META | REQ_META, bio);
	blk_finish_plug(&plug);

	/* Synchronous read operation */
	wait_for_completion(&wait);

	if (continue_load) {
		continue_load = 0;
		goto again;
	}

	return 0;
}

/**
 * @brief			Read page from the given sector address.
 *				Fill the locked page with data located in the
 *				sector address. Read operation is synchronous,
 *				and caller must unlock the page.
 *				Shall be used for sb/metadata only !
 * @param [in]	bdev		Pointer to block device.
 * @param [in]	page		Pointer to locked page.
 * @param [in]	sector_addr	Sector address.
 * @param [in]	sector_count	Number of sectors to be read.
 * @param [in]	offset		Offset value in page.
 * @return			Returns 0 on success, errno on failure.
 */
int vdfs4_read_page(struct block_device *bdev,
			struct page *page,
			sector_t sector_addr,
			unsigned int sector_count,
			unsigned int offset)
{
	struct bio *bio;
	struct completion wait;
	struct blk_plug plug;

	if (sector_count > SECTOR_PER_PAGE + 1)
		return -EINVAL;

	if (PageUptodate(page))
		return 0;

	/* Allocate a new bio */
	bio = __allocate_new_bio(bdev, sector_addr, 1);
	if (IS_ERR_OR_NULL(bio))
		return PTR_ERR(bio);

	init_completion(&wait);
	blk_start_plug(&plug);

	/* Initialize the bio */
	bio->bi_end_io = read_end_io;
	if ((unsigned) bio_add_page(bio, page, SECTOR_SIZE * sector_count,
			offset)	< SECTOR_SIZE * sector_count) {
		VDFS4_ERR("FAIL to add page to BIO");
		bio_put(bio);
		blk_finish_plug(&plug);
		return -EFAULT;
	}
	bio->bi_private = &wait;
	submit_bio(READ | REQ_META | REQ_META, bio);
	blk_finish_plug(&plug);

	/* Synchronous read operation */
	wait_for_completion(&wait);

	if (PageError(page))
		return -EFAULT;

	return 0;
}

/**
 * @brief			Write page to the given sector address.
 *				Write the locked page to the sector address.
 *				Write operation is synchronous, and caller
 *				must unlock the page.
 *				Shall be used for sb/metadata only !
 * @param [in]	sbi		The VDFS4 superblock information.
 * @param [in]	dest_sector	Destination sector offset in the volume.
 * @param [in]	src_page	Pointer to locked page.
 * @param [in]	offset_in_page	Byte offset within the page.
 * @param [in]	len		Data length in byte.
 * @param [in]	is_sync		Synchronous mode
 * @return			Returns 0 on success, errno on failure.
 */
int vdfs4_write_page(struct vdfs4_sb_info *sbi,
		     sector_t dest_sector, struct page *src_page,
		     unsigned int offset_in_src, unsigned int len, int is_sync)
{
	struct bio *bio;
	struct completion wait;
	struct block_device *bdev = sbi->sb->s_bdev;
	struct blk_plug plug;

	if (PAGE_SIZE < offset_in_src + len) {
		end_page_writeback(src_page);
		return -EINVAL;
	}

	if (VDFS4_IS_READONLY(sbi->sb)) {
		end_page_writeback(src_page);
		return 0;
	}

	/* Allocate a new bio */
	bio = __allocate_new_bio(bdev, dest_sector, 1);
	if (IS_ERR_OR_NULL(bio)) {
		end_page_writeback(src_page);
		return PTR_ERR(bio);
	}

	blk_start_plug(&plug);
	if (is_sync)
		init_completion(&wait);

	/* Initialize the bio */
	bio->bi_end_io = end_io_write;
	if ((unsigned) bio_add_page(bio, src_page, len, offset_in_src) < len) {
		VDFS4_ERR("FAIL to add page to BIO");
		bio_put(bio);
		blk_finish_plug(&plug);
		end_page_writeback(src_page);
		return -EFAULT;
	}
	if (is_sync)
		bio->bi_private = &wait;

	submit_bio(WRITE_FLUSH_FUA | REQ_META | REQ_PRIO, bio);
	blk_finish_plug(&plug);
	if (is_sync) {
		/* Synchronous write operation */
		wait_for_completion(&wait);
	}
	return 0;
}

/**
 * @brief		Sign  pages with crc number
 * @param [in]	mapping	Mapping with pages to sign
 * @param [in]	magic_len	Length of the magic string, the first
 *				magic_len bytes will be skiped during crc
 *				calculation.
 * @return			0 - if page signed successfully
 *				or error code otherwise
 */
static int vdfs4_check_and_sign_pages(struct page *page, char *magic,
		unsigned int magic_len, __u64 version)
{
	void *data;

	data = kmap(page);
	if (!data) {
		VDFS4_ERR("Can not allocate virtual memory");
		return -ENOMEM;
	}
#ifdef CONFIG_VDFS4_META_SANITY_CHECK
	if (memcmp(data, magic, magic_len - VERSION_SIZE) !=
					0) {
		VDFS4_ERR(" invalide bitmap magic for %s,"
			" %lu, actual = %s\n", magic,
			page->mapping->host->i_ino, (char *)data);
		VDFS4_BUG(VDFS4_SB(page->mapping->host->i_sb));
	}
#endif
	memcpy((char *)data + magic_len - VERSION_SIZE, &version, VERSION_SIZE);
	vdfs4_update_block_crc(data, PAGE_SIZE, magic_len);
	kunmap(page);
	return 0;
}

static int vdfs4_validate_bitmap(struct page *page, void *buff,
		unsigned int buff_size, const char *magic,
		unsigned int magic_len)
{
	struct vdfs4_sb_info *sbi = VDFS4_SB(page->mapping->host->i_sb);
	__le64 real_version, version = vdfs4_get_page_version(sbi,
			page->mapping->host, page->index);
#ifdef CONFIG_VDFS4_META_SANITY_CHECK
	unsigned int crc;
#endif
	int ret_val = 0;
	struct vdfs4_meta_block *p_buff = buff;


	/* check magic */
	if (magic) {
		/* if magic is not valid */
		if (memcmp(buff, magic, magic_len - VERSION_SIZE) != 0) {
			VDFS4_ERR("read %s bitmap from disk fail: wrong magic"
					, magic);
			ret_val = -EINVAL;
			destroy_layout(sbi);
		}
	}

	real_version = ((((__le64)(p_buff->mount_count)) << 32)
			| p_buff->sync_count);
	if (real_version != version) {
		VDFS4_ERR("read bitmap %s from disk fail:version mismatch "
				"iblock:%lu,"
				"must be :%u.%u, "
				"readed :%u.%u", magic,
				page->index,
				VDFS4_MOUNT_COUNT(version),
				VDFS4_SYNC_COUNT(version),
				VDFS4_MOUNT_COUNT(real_version),
				VDFS4_SYNC_COUNT(real_version));
		ret_val = -EINVAL;
		destroy_layout(sbi);
	}

#ifdef CONFIG_VDFS4_META_SANITY_CHECK
	crc = cpu_to_le32(crc32(0, (char *)buff + magic_len, buff_size -
			(CRC32_SIZE + magic_len)));
	if (memcmp(VDFS4_CRC32_OFFSET((char *)buff, buff_size), &crc,
				CRC32_SIZE) != 0) {
		ret_val = -EINVAL;
		VDFS4_ERR("read bimap %s:%lu from disk fail: CRC mismatch"
				, magic, page->index);
		VDFS4_ERR("index:%lu phy addr: 0x%llx", page->index,
				(unsigned long long int)
				page_to_phys(page));
#ifdef VDFS4_DEBUG_DUMP
		mutex_lock(&sbi->dump_meta);
		VDFS4_MDUMP("", buff, buff_size);
		mutex_unlock(&sbi->dump_meta);
#endif
		vdfs4_record_err_dump_disk(sbi, VDFS4_DEBUG_ERR_BITMAP_VALIDATE,
				*((unsigned int *)VDFS4_CRC32_OFFSET((char *)buff,
				buff_size)), crc, "bitmap validate err",
				(void *)buff, buff_size);
		destroy_layout(sbi);
	}
#endif
	return ret_val;
}
/**
 * @brief		Validata page crc and magic number
 * @param [in]	page	page to validate
 * @param [in]	magic	magic to validate
 * @param [in]	magic_len	magic len in bytes
 * @return			0 - if crc and magic are valid
 *				1 - if crc or magic is invalid
 */
static int vdfs4_validate_page(struct page *page)
{
	void *data;
	int ret_val = 0;
	char *magic;
	unsigned int magic_len;
	ino_t ino = page->mapping->host->i_ino;

	if ((ino > (ino_t)VDFS4_LSFILE) || is_tree(ino))
		return 0;

	BUG_ON(!PageLocked(page));

	switch (ino) {
	case VDFS4_FREE_INODE_BITMAP_INO:
		magic = INODE_BITMAP_MAGIC;
		magic_len = INODE_BITMAP_MAGIC_LEN;
		break;
	case VDFS4_SPACE_BITMAP_INO:
		magic = FSM_BMP_MAGIC;
		magic_len = FSM_BMP_MAGIC_LEN;
		break;
	default:
		return ret_val;
	}
	data = kmap(page);
	if (!data) {
		VDFS4_ERR("Can not allocate virtual memory");
		return -ENOMEM;
	}
	ret_val = vdfs4_validate_bitmap(page, data, PAGE_SIZE,
					magic, magic_len);

	kunmap(page);
	return ret_val;
}

/**
 * @brief				Update the buffer with magic and crc
 *					numbers. the magic will be placed in
 *					first bytes, the crc will be placed
 *					in last 4 bytes.
 * @param [in]	buff			Buffer to update.
 * @param [in]	block_size		Block size
 * @param [in]	magic_len		Length of the magic string, the first
 *				magic_len bytes will be skiped during crc
 *				calculation.
 */
#ifdef CONFIG_VDFS4_META_SANITY_CHECK
void vdfs4_update_block_crc(char *buff, unsigned int blck_size,
		unsigned int magic_len)
{
	unsigned int crc = 0;
	/* set crc to the end of the buffer */
	crc = cpu_to_le32(crc32(0, buff + magic_len,
		blck_size - (CRC32_SIZE  +
		magic_len)));
	memcpy(VDFS4_CRC32_OFFSET(buff, blck_size), &crc, CRC32_SIZE);
}
#else
void vdfs4_update_block_crc(char *buff, unsigned int blck_size,
		unsigned int magic_len){}
#endif

/**
 * @brief				Set bits inside buffer and update
 *					sign and crc values for updated
 *					buffer.
 * @param [in]	buff			Buffer to validate.
 * @param [in]	buff_size		Size of the buffer
 * @param [in]	offset			Offset of the start bit for setting
 * @param [in]	count			Number of bits to be set
 * @param [in]	magic_len		Length of the magic word in bytes
 * @param [in]	block_size		Size of block for block device.

 */
int vdfs4_set_bits(char *buff, int buff_size, unsigned int offset,
		unsigned int count, unsigned int magic_len,
		unsigned int blck_size) {
	/* data block size in bits */
	const unsigned int datablock_size = (blck_size - (magic_len
				+ CRC32_SIZE)) << 3;
	/* pointer to begin of start block */
	char *start_blck = buff + ((offset / datablock_size) * blck_size);
	/* pointer to last block */
	char *end_blck =  buff + (((offset + count - 1) / datablock_size) *
			blck_size);
	char *cur_blck = NULL;
	unsigned int cur_position = 0;
	u_int32_t length = 0, i = 0;
	char *end_buff;


	for (cur_blck = start_blck; cur_blck <= end_blck;
				cur_blck += blck_size) {
		/* if it first block */
		if (cur_blck == start_blck)
			cur_position = offset % datablock_size;
		else
			cur_position = 0;

		length = (datablock_size - cur_position);
		if (count < length)
			length = count;
		else
			count -= length;
		end_buff = cur_blck + blck_size - CRC32_SIZE;
		/* set bits */
		for (i = 0; i < length; i++) {
			/* check the bound of array */
			if ((cur_blck + (cur_position>>3) +
					magic_len) > end_buff)
				return -EFAULT;
			/* set bits */
			if (vdfs4_test_and_set_bit((int)cur_position,
				(void *)(cur_blck + magic_len)))
				return -EFAULT;

			cur_position++;
		}
	}
	return 0;
}

/**
 * @brief			Clear bits inside buffer and update
 *					sign and crc values for updated
 *					buffer.
 * @param [in]	buff			Buffer to validate.
 * @param [in]	buff_size		Size of the buffer
 * @param [in]	offset			Offset of the start bit for setting
 * @param [in]	count			Number of bits to be set
 * @param [in]	magic_len		Length of the magic word in bytes
 * @param [in]	block_size		Size of block for block device.
 * @return				Error code or 0 if success
 */
int vdfs4_clear_bits(char *buff, int buff_size, unsigned int offset,
		unsigned int count, unsigned int magic_len,
		unsigned int blck_size) {
	/* data block size in bits */
	const unsigned int datablock_size = (blck_size - (magic_len
				+ CRC32_SIZE))<<3;
	/* pointer to begin of start block */
	char *start_blck = buff + ((offset / datablock_size) * blck_size);
	/* pointer to last block */
	char *end_blck =  buff + (((offset + count - 1) / datablock_size) *
			blck_size);
	char *cur_blck = NULL;
	unsigned int cur_position = 0;
	u_int32_t length = 0, i = 0;
	char *end_buff;

	/* go through all blcoks */
	for (cur_blck = start_blck; cur_blck <= end_blck;
				cur_blck += blck_size) {
		/* if it first block */
		if (cur_blck == start_blck)
			cur_position = offset % datablock_size;
		else
			cur_position = 0;

		length = (datablock_size - cur_position);
		if (count < length) {
			length = count;
			count -= length;
		} else
			count -= length;
		end_buff = cur_blck + blck_size - CRC32_SIZE;
		/* set bits */
		for (i = 0; i < length; i++) {
			/* check the boundary of array */
			if ((cur_blck + (cur_position>>3) + magic_len)
					> end_buff)
				return -EFAULT;

			/* set bits */
			if (!vdfs4_test_and_clear_bit((int)cur_position,
					(void *)(cur_blck + magic_len))) {
#ifdef VDFS4_DEBUG_DUMP
				VDFS4_ERR("bit cleared offset: %u, position: %u",
					  offset, cur_position);
				VDFS4_MDUMP("space bitmap:", (void *)(cur_blck),
					  blck_size);
#endif
				return -EFAULT;
			}
			cur_position++;
		}
	}
	return 0;
}

/**
 * @brief			Fill buffer with zero and update the
 *				buffer with magic.
 * @param [in]	buff		Buffer to update.
 * @param [in]	block_size	Block size
 * @param [in]	ino		Inode number
 */
static int vdfs4_init_bitmap_page(struct vdfs4_sb_info *sbi, ino_t ino_n,
		struct page *page)
{
	void *bitmap;
	struct vdfs4_layout_sb *vdfs4_sb = sbi->raw_superblock;

	__u64 version = ((__u64)le32_to_cpu(vdfs4_sb->exsb.mount_counter) << 32)
			| sbi->snapshot_info->sync_count;

	if (ino_n == VDFS4_FREE_INODE_BITMAP_INO) {
		bitmap = kmap_atomic(page);
		if (!bitmap)
			return -ENOMEM;
		memset((char *)bitmap, 0, PAGE_CACHE_SIZE);
		memcpy((char *)bitmap, INODE_BITMAP_MAGIC,
				INODE_BITMAP_MAGIC_LEN - VERSION_SIZE);
		memcpy((char *)bitmap + INODE_BITMAP_MAGIC_LEN - VERSION_SIZE,
				&version, VERSION_SIZE);
		kunmap_atomic(bitmap);
	}

	return 0;
}

static void __dump_tagged_pages(struct address_space *mapping, unsigned tag)
{
	struct radix_tree_iter iter;
	void **slot;

	radix_tree_for_each_tagged(slot, &mapping->page_tree, &iter, 0, tag) {
		struct page *page = *slot;

		VDFS4_ERR("mapping %p index %ld page %p",
		       mapping, iter.index, page);
		if (page)
			VDFS4_ERR("page %ld mapping %p index %ld "
			       "flags %lx refcount %d",
			       page_to_pfn(page), page->mapping, page->index,
			       page->flags, page_count(page));
	}
}

static void dump_tagged_pages(struct address_space *mapping, unsigned tag)
{
	spin_lock_irq(&mapping->tree_lock);
	__dump_tagged_pages(mapping, tag);
	spin_unlock_irq(&mapping->tree_lock);
}

static struct address_space *vdfs4_next_mapping(struct vdfs4_sb_info *sbi,
		struct address_space *current_mapping)
{
	ino_t ino;

	ino = (current_mapping == NULL) ? 0 : current_mapping->host->i_ino;

	switch (ino) {
	case (0):
		return sbi->catalog_tree->inode->i_mapping;
	break;
	case (VDFS4_CAT_TREE_INO):
		return sbi->fsm_info->bitmap_inode->i_mapping;
	break;
	case (VDFS4_SPACE_BITMAP_INO):
		return sbi->extents_tree->inode->i_mapping;
	break;
	case (VDFS4_EXTENTS_TREE_INO):
		return sbi->free_inode_bitmap.inode->i_mapping;
	break;
	case (VDFS4_FREE_INODE_BITMAP_INO):
		return sbi->xattr_tree->inode->i_mapping;
	case (VDFS4_XATTR_TREE_INO):
		return NULL;
	default:
	return NULL;
	}
}

static int vdfs4_sign_mapping_pages(struct vdfs4_sb_info *sbi,
		struct pagevec *pvec, unsigned long ino);

static int get_pages_from_mapping(struct vdfs4_sb_info *sbi,
		struct address_space **current_mapping,
		struct pagevec *pvec, pgoff_t *index)
{
	unsigned nr_pages = 0;
	ino_t ino;
	int ret;
	unsigned long size;

	do {
		if (*current_mapping) {
			size = (is_tree(current_mapping[0]->host->i_ino)) ?
					(unsigned long)
					(PAGEVEC_SIZE - (PAGEVEC_SIZE %
					(1 << (sbi->log_blocks_in_page
					+ sbi->log_blocks_in_leb)))) :
					(unsigned long)PAGEVEC_SIZE;
			nr_pages = pagevec_lookup_tag(pvec, *current_mapping,
				index, PAGECACHE_TAG_DIRTY, size);

			ino = current_mapping[0]->host->i_ino;

			ret = vdfs4_sign_mapping_pages(sbi, pvec, ino);
			if (ret) {
				pagevec_release(pvec);
				return ret;
			}
		}

		if (!nr_pages) {
			*current_mapping = vdfs4_next_mapping(sbi,
					*current_mapping);
			*index = 0;

			if (*current_mapping &&
			    mapping_tagged(*current_mapping,
				    PAGECACHE_TAG_WRITEBACK)) {
				VDFS4_ERR("inode #%ld already has writeback",
					   (*current_mapping)->host->i_ino);
				dump_tagged_pages(*current_mapping,
						PAGECACHE_TAG_WRITEBACK);
			}
		}

	} while ((!nr_pages) && *current_mapping);

#ifdef CONFIG_VDFS4_DEBUG
	if (nr_pages)
		vdfs4_check_moved_iblocks(sbi, pvec->pages, nr_pages);
#endif

	return (int)nr_pages;
}




static void meta_end_IO(struct bio *bio, int err)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	struct bio_vec *bvec = bio->bi_io_vec + bio->bi_vcnt - 1;
	struct vdfs4_sb_info *sbi =
			bvec->bv_page->mapping->host->i_sb->s_fs_info;

	if (bio->bi_rw & WRITE) {
		VDFS4_BUG_ON(atomic_read(&sbi->meta_bio_count) <= 0, sbi);
		if (atomic_dec_and_test(&sbi->meta_bio_count))
			wake_up_all(&sbi->meta_bio_wait);
	}

	do {
		struct page *page = bvec->bv_page;

		if (--bvec >= bio->bi_io_vec)
			prefetchw(&bvec->bv_page->flags);

		if (!uptodate) {
			SetPageError(page);
			if (page->mapping)
				set_bit(AS_EIO, &page->mapping->flags);
		}

		if (bio->bi_rw & WRITE) {
			end_page_writeback(page);
		} else {
			if (uptodate)
				SetPageUptodate(page);
			unlock_page(page);
		}

	} while (bvec >= bio->bi_io_vec);

	bio_put(bio);
}

static struct bio *allocate_new_request(struct vdfs4_sb_info *sbi, sector_t
		start_block, unsigned size)
{
	struct bio *bio;
	sector_t start_sector = start_block << (sbi->block_size_shift -
			SECTOR_SIZE_SHIFT);
	struct block_device *bdev = sbi->sb->s_bdev;
	unsigned int bio_size = (size > BIO_MAX_PAGES) ? BIO_MAX_PAGES : size;

	bio = __allocate_new_bio(bdev, start_sector, bio_size);

	if (!IS_ERR_OR_NULL(bio))
		bio->bi_end_io = meta_end_IO;
	else
		bio = NULL;

	return bio;
}

static int vdfs4_sign_mapping_pages(struct vdfs4_sb_info *sbi,
		struct pagevec *pvec, unsigned long ino)
{
	int ret = 0;
	struct vdfs4_layout_sb *vdfs4_sb = sbi->raw_superblock;
	__u64 version = ((__u64)le32_to_cpu(vdfs4_sb->exsb.mount_counter) << 32)
		| sbi->snapshot_info->sync_count;
	unsigned int magic_len = 0;
	struct vdfs4_base_table_record *table;

	down_read(&sbi->snapshot_info->tables_lock);
	table = vdfs4_get_table(sbi, ino);
	if (is_tree(ino)) {
		__le64 table_index = 0;
		struct vdfs4_btree *tree;
		unsigned int i;

		switch (ino) {
		case VDFS4_CAT_TREE_INO:
			tree = sbi->catalog_tree;
			break;
		case VDFS4_EXTENTS_TREE_INO:
			tree = sbi->extents_tree;
			break;
		case VDFS4_XATTR_TREE_INO:
			tree = sbi->xattr_tree;
			break;
		default:
			ret = -EFAULT;
			goto ERR_TABLES_LOCK;
		}

		for (i = 0; i < pvec->nr; i += tree->pages_per_node) {
			struct page **pages = pvec->pages + i;
			unsigned int j;

			if ((pvec->nr - i) < tree->pages_per_node) {
				VDFS4_ERR("incomplete bnode: %ld %ld %ld",
						ino, pages[0]->index,
						pvec->nr - i);
				ret = -EFAULT;
				goto ERR_TABLES_LOCK;
			}

			for (j = 1; j < tree->pages_per_node; j++) {
				if (pages[j]->index != pages[0]->index + j) {
					VDFS4_ERR("noncontiguous bnode pages: "
							"%ld %ld != %ld + %d",
							ino, pages[j]->index,
							pages[0]->index, j);
					ret = -EFAULT;
					goto ERR_TABLES_LOCK;
				}
			}

			ret = vdfs4_check_and_sign_dirty_bnodes(pages,
					tree, version);
			if (ret)
				break;
			table_index = pvec->pages[i]->index
					>> (sbi->log_blocks_in_leb +
					sbi->block_size_shift - PAGE_SHIFT);
			table[table_index].mount_count =
					vdfs4_sb->exsb.mount_counter;
			table[table_index].sync_count =
					sbi->snapshot_info->sync_count;
		}
	} else {
		unsigned int i;
		char *magic = NULL;

		switch (ino) {
		case VDFS4_FREE_INODE_BITMAP_INO:
			magic = INODE_BITMAP_MAGIC;
			magic_len = INODE_BITMAP_MAGIC_LEN;
			break;
		case VDFS4_SPACE_BITMAP_INO:
			magic = FSM_BMP_MAGIC;
			magic_len = FSM_BMP_MAGIC_LEN;
			break;
		default:
			ret = -EFAULT;
			goto ERR_TABLES_LOCK;
		}
		for (i = 0; i < pvec->nr; i++) {

			ret = vdfs4_check_and_sign_pages(pvec->pages[i], magic,
				magic_len, version);
			if (ret)
				break;
			table[pvec->pages[i]->index].mount_count =
				vdfs4_sb->exsb.mount_counter;
			table[pvec->pages[i]->index].sync_count =
					sbi->snapshot_info->sync_count;
		}
	}
ERR_TABLES_LOCK:
	up_read(&sbi->snapshot_info->tables_lock);
	return ret;
}

/**
 * @brief			Write meta data (struct page **)
 *				The function supports metadata fragmentation
 * @param [in]	sbi		The VDFS4 superblock information.
 * @param [in]	pages		Pointer to locked pages.
 * @param [in]	sector_addr	Start isector address.
 * @param [in]	page_count	Number of pages to be written.
 *				    and write snapshot head page in sync mode
 * @return			Returns 0 on success, errno on failure.
 */
static int vdfs4_meta_write(struct vdfs4_sb_info *sbi)
{
	struct address_space *current_mapping = NULL;
	pgoff_t next_index = 0;
	sector_t next_block = 0, block;
	struct bio *bio = NULL;
	struct blk_plug plug;
	struct pagevec pvec;
	struct page *page;
	int ret, ret2;
	unsigned int i = 0;

	pagevec_init(&pvec, 0);
	blk_start_plug(&plug);

	while (1) {
		if (i == pvec.nr) {
			pagevec_release(&pvec);
			ret = get_pages_from_mapping(sbi,
					&current_mapping, &pvec, &next_index);
			if (ret <= 0)
				break;
			i = 0;
		}

		page = pvec.pages[i];

		ret = get_block_meta_wrapper(current_mapping->host,
				page->index, &block, 0, 0);
		VDFS4_BUG_ON(ret, sbi);

		lock_page(page);
		VDFS4_BUG_ON(!PageDirty(page), sbi);
		VDFS4_BUG_ON(PageWriteback(page), sbi);
		VDFS4_BUG_ON(page->mapping != current_mapping, sbi);
		clear_page_dirty_for_io(page);
		set_page_writeback(page);
		unlock_page(page);

		while (!bio || next_block != block ||
		       !bio_add_page(bio, page, PAGE_CACHE_SIZE, 0)) {
			if (bio) {
				atomic_inc(&sbi->meta_bio_count);
				submit_bio(WRITE_FUA | REQ_META | REQ_PRIO, bio);
			}
			bio = allocate_new_request(sbi, block, pvec.nr - i);
			next_block = block;
		}

		i++;
		next_block += (sector_t)(1lu << sbi->log_blocks_in_page);
	}

	if (bio) {
		atomic_inc(&sbi->meta_bio_count);
		submit_bio(WRITE_FUA | REQ_META | REQ_PRIO, bio);
	}

	blk_finish_plug(&plug);

	current_mapping = NULL;
	while ((current_mapping = vdfs4_next_mapping(sbi, current_mapping))) {
		ret2 = filemap_fdatawait_range(current_mapping, 0, LLONG_MAX);
		if (ret2) {
			vdfs4_fatal_error(sbi,
				"cannot write matadata inode %lu: %d",
				current_mapping->host->i_ino, ret2);
			ret = ret2;
		}

		spin_lock_irq(&current_mapping->tree_lock);
		if (mapping_tagged(current_mapping, PAGECACHE_TAG_DIRTY)) {
			VDFS4_ERR("inode #%ld has dirty tag set",
					current_mapping->host->i_ino);
			__dump_tagged_pages(current_mapping,
					    PAGECACHE_TAG_DIRTY);
			ret = -EFAULT;
		}
		if (mapping_tagged(current_mapping, PAGECACHE_TAG_WRITEBACK)) {
			VDFS4_ERR("inode #%ld has writeback tag set",
					current_mapping->host->i_ino);
			__dump_tagged_pages(current_mapping,
					    PAGECACHE_TAG_WRITEBACK);
			ret = -EFAULT;
		}
		spin_unlock_irq(&current_mapping->tree_lock);
	}

	if (atomic_read(&sbi->meta_bio_count)) {
		/* it must be never happened */
		VDFS4_ERR("not all bio complited");
		wait_event_timeout(sbi->meta_bio_wait,
				!atomic_read(&sbi->meta_bio_count), HZ * 5);
	}

	return ret;
}

/**
 * @brief			Read meta data (struct page **)
 *				The function supports metadata fragmentation
 *				non-Uptodate pages must be locked
 * @param [in]	sbi		The VDFS4 superblock information.
 * @param [in]	pages		Pointer to locked pages.
 * @param [in]	sector_addr	Start isector address.
 * @param [in]	page_count	Number of pages to be written.
 *				    and write snapshot head page in sync mode
 * @return			Returns 0 on success, errno on failure.
 */
int vdfs4__read(struct inode *inode, int type, struct page **pages,
		unsigned int pages_count, sector_t start_block)
{
	struct vdfs4_sb_info *sbi = VDFS4_SB(inode->i_sb);
	struct bio *bio = NULL;
	struct blk_plug plug;
	int size;
	int ret = 0;
	sector_t last_block = 0, block;
	struct block_device *bdev = inode->i_sb->s_bdev;
	sector_t blocks_num = bdev->bd_inode->i_size >> PAGE_CACHE_SHIFT;

	unsigned int blocks_per_page = (unsigned)(1 << (PAGE_CACHE_SHIFT -
			sbi->block_size_shift));
	unsigned int count;
	int bio_flags = (type == VDFS4_META_READ) ?
			READ | REQ_META | REQ_PRIO : READ;

	blk_start_plug(&plug);

	for (count = 0; count < pages_count; count++) {
		struct page *page = pages[count];

		VDFS4_BUG_ON(!PageLocked(page), sbi);

		if (PageUptodate(page)) {
			unlock_page(page);
			continue;
		}

		ret = get_block_meta_wrapper(inode, page->index, &block, type,
				start_block);
		if (ret || (block == 0)) {
			ret = (block == 0) ? -EINVAL : ret;
			for (; count < pages_count; count++)
				unlock_page(pages[count]);
			goto exit;
		}

		if (last_block + blocks_per_page != block) {
			unsigned max_pages_num = min_t(unsigned,
					(pages_count - count), (blocks_num - block));
			if (bio)
				submit_bio(bio_flags, bio);
again:
			bio = allocate_new_request(sbi, block,
					max_pages_num);
			if (!bio) {
				ret = -EIO;
				for (; count < pages_count; count++)
					unlock_page(pages[count]);
				goto exit;
			}
		}

		size = bio_add_page(bio, page, PAGE_CACHE_SIZE, 0);
		if (size < (int)PAGE_CACHE_SIZE) {
			submit_bio(bio_flags, bio);
			bio = NULL;
			goto again;
		}
		last_block = block;
	};

exit:
	if (bio)
		submit_bio(bio_flags, bio);

	blk_finish_plug(&plug);

	for (count = 0; count < pages_count; count++) {
		if (!PageUptodate(pages[count]))
			wait_on_page_locked(pages[count]);
		if (TestClearPageError(pages[count]))
			ret = -EIO;
	}

	return ret;
}

int vdfs4_sync_metadata(struct vdfs4_sb_info *sbi)
{
	int ret = 0;
	struct super_block *sb = sbi->sb;
	struct vdfs4_layout_sb *l_sb = sbi->raw_superblock;
	struct vdfs4_extended_super_block *exsb = &l_sb->exsb;
	struct vdfs4_snapshot_info *snapshot = sbi->snapshot_info;

	if (sbi->snapshot_info->dirty_pages_count == 0)
		return 0;

	if (sbi->sb->s_flags & MS_RDONLY) {
		VDFS4_ERR("Can't sync on read-only filesystem");
		return 0;
	}

	/* Write statistics */
	if (sb->s_bdev->bd_part) {
		u64 kbytes_written = sbi->kbytes_written;

		kbytes_written += BD_PART_WRITTEN(sbi);
		if (exsb->kbytes_written != cpu_to_le64(kbytes_written)) {
			exsb->kbytes_written = cpu_to_le64(kbytes_written);
			set_sbi_flag(sbi, EXSB_DIRTY);
		}
	}

	if (is_sbi_flag_set(sbi, EXSB_DIRTY)) {
		ret = vdfs4_sync_exsb(sbi, 1);
		sbi->snapshot_info->use_base_table = 1;
		if (ret) {
			vdfs4_fatal_error(sbi, "cannot sync 2nd sb: %d", ret);
			return ret;
		}
	}

	ret = vdfs4_meta_write(sbi);
	if (ret)
		return ret;

	vdfs4_update_bitmaps(sbi);
	ret = vdfs4_update_translation_tables(sbi);
	if (ret) {
		vdfs4_fatal_error(sbi,
				"cannot commit translation tables: %d", ret);
		return ret;
	}

	if (is_sbi_flag_set(sbi, EXSB_DIRTY)) {
		ret = vdfs4_sync_exsb(sbi, 0);
		clear_sbi_flag(sbi, EXSB_DIRTY);
		if (ret)
			vdfs4_fatal_error(sbi, "cannot sync 1st sb: %d", ret);
	}

	vdfs4_commit_free_space(sbi);

	/* increase sync count */
	snapshot->sync_count++;
	return ret;
}

int vdfs4_read_comp_pages(struct inode *inode, pgoff_t index,
			      int pages_count, struct page **pages,
			      enum vdfs4_read_type type)
{
	struct address_space *mapping = NULL;
	int count, ret = 0;
	struct page *page = NULL;
	sector_t page_idx;

	if (type != VDFS4_FBASED_READ_C && type != VDFS4_FBASED_READ_M) {
		VDFS4_ERR("function can't be used for data type %d", type);
		return -EINVAL;
	}
	mapping = inode->i_sb->s_bdev->bd_inode->i_mapping;


	for (count = 0; count < pages_count; count++) {
		ret = vdfs4_get_block_file_based(inode, index + (pgoff_t)count,
				&page_idx);
		if (ret)
			goto exit_alloc_page;
		page = find_or_create_page(mapping, (pgoff_t)page_idx,
				GFP_NOFS | __GFP_HIGHMEM);
		if (!page) {
			ret = -ENOMEM;
			goto exit_alloc_page;
		}

		if (!PageChecked(page))
			ClearPageUptodate(page);
		pages[count] = page;
	}

	ret = vdfs4__read(inode, type, pages, (unsigned)pages_count, 0);
	if (ret)
		goto exit_read_data;

	for (--count; count >= 0; count--) {
		lock_page(pages[count]);
		if (PageUptodate(pages[count]))
			SetPageChecked(pages[count]);
		unlock_page(pages[count]);
	}
	return ret;
exit_alloc_page:
	VDFS4_ERR("Error in allocate page");
	for (; count > 0; count--) {
		unlock_page(pages[count - 1]);
		page_cache_release(pages[count - 1]);
	}
	return ret;
exit_read_data:
	VDFS4_ERR("Error in exit_read data");
	release_pages(pages, pages_count, 0);
	return ret;

}

static int __get_chunk_extent(struct vdfs4_inode_info *inode_i,
		pgoff_t chunk_idx, struct vdfs4_comp_extent_info *cext)
{
	struct vdfs4_comp_extent *raw_extent;
	struct page *page;
	void *data;
	pgoff_t page_idx;
	int pos;
	pgoff_t last_block;
	loff_t start;
	loff_t extent_offset;
	int ret = 0;

	extent_offset = inode_i->fbc->comp_table_start_offset +
		chunk_idx * sizeof(struct vdfs4_comp_extent);

	page_idx = (pgoff_t)extent_offset >> PAGE_CACHE_SHIFT;
	pos = extent_offset & (PAGE_CACHE_SIZE - 1);

	ret = vdfs4_read_comp_pages(&inode_i->vfs_inode, page_idx,
		1, &page, VDFS4_FBASED_READ_M);
	if (ret)
		return ret;

	data = kmap_atomic(page);
	raw_extent = (void *)((char *)data + pos);

	if (!test_bit(VDFS4_PROFILED_FILE, &inode_i->flags) &&
		memcmp(raw_extent->magic, VDFS4_COMPR_EXT_MAGIC,
				sizeof(raw_extent->magic))) {
		struct vdfs4_sb_info *sbi = VDFS4_SB(inode_i->vfs_inode.i_sb);

		VDFS4_ERR("Wrong magic in compressed extent: #%ld, "
				" chunk idx:%lu, ext offset:%lld, addr:0x%x "
				" (0x%02X 0x%02X, %s)",
			   inode_i->vfs_inode.i_ino, chunk_idx,
			   (long long)extent_offset,
			   (unsigned int)(raw_extent->magic),
			   raw_extent->magic[0], raw_extent->magic[1],
			   VDFS4_COMPR_EXT_MAGIC);
#ifdef VDFS4_DEBUG_DUMP
		mutex_lock(&sbi->dump_meta);
		VDFS4_MDUMP("", data, PAGE_SIZE);
		mutex_unlock(&sbi->dump_meta);
#endif
		vdfs4_print_volume_verification(sbi);
		ret = -EINVAL;
		goto out_unmap;
	}

	start = (pgoff_t)le64_to_cpu(raw_extent->start);
	cext->flags = le16_to_cpu(raw_extent->flags);
	cext->start_block = (pgoff_t)start >> (pgoff_t)PAGE_CACHE_SHIFT;
	cext->offset = start & (PAGE_CACHE_SIZE - 1);
	cext->len_bytes = (int)le32_to_cpu(raw_extent->len_bytes);
	last_block = (pgoff_t)(start + cext->len_bytes + PAGE_CACHE_SIZE - 1)
			>> PAGE_CACHE_SHIFT;
	cext->blocks_n = (int)(last_block - cext->start_block);
#ifdef CONFIG_VDFS4_SQUEEZE
	cext->profiled_prio =  le16_to_cpu(raw_extent->profiled_prio);
#endif
out_unmap:
	if (!ret && (cext->len_bytes < 0 || cext->offset < 0)) {
		struct vdfs4_sb_info *sbi = VDFS4_SB(inode_i->vfs_inode.i_sb);

		VDFS4_ERR("Invalid compressed extent: #%ld, chunk idx:%lu, "
			  "ext offset:%lld, cext len:%d, cext offset:%d",
			   inode_i->vfs_inode.i_ino, chunk_idx,
			   (long long)extent_offset, cext->len_bytes, cext->offset);
#ifdef VDFS4_DEBUG_DUMP
		mutex_lock(&sbi->dump_meta);
		VDFS4_MDUMP("", data, PAGE_SIZE);
		mutex_unlock(&sbi->dump_meta);
#endif
		vdfs4_print_volume_verification(sbi);
		ret = -EINVAL;
	}
	kunmap_atomic(data);
	if (ret) {
		lock_page(page);
		ClearPageChecked(page);
		unlock_page(page);
	}
	mark_page_accessed(page);
	page_cache_release(page);
	return ret;
}

#ifdef CONFIG_VDFS4_HW_DECOMPRESS_SUPPORT
/* This translation from hw flags is really ugly. But we do not want to depend
 * from unpredictable modification (e.g. too big values) */
static inline enum hw_iovec_comp_type convert_hw_comptype(enum compr_type type)
{
	enum hw_iovec_comp_type hw_type = 0;

	switch (type) {
	case VDFS4_COMPR_NONE:
		/* This case is weird. Must not happen */
		VDFS4_BUG(NULL);
		break;
	case VDFS4_COMPR_ZLIB:
		hw_type = HW_IOVEC_COMP_ZLIB;
		break;
	case VDFS4_COMPR_GZIP:
		hw_type = HW_IOVEC_COMP_GZIP;
		break;
	case VDFS4_COMPR_LZO:
		hw_type = HW_IOVEC_COMP_LZO;
		break;
	case VDFS4_COMPR_XZ:
		/* Not defined */
		break;
	case VDFS4_COMPR_LZMA:
		/* Not defined */
		break;
	default:
		VDFS4_BUG(NULL);
		break;
	}

	return hw_type;
}

static inline enum hw_iovec_hash_type convert_hw_hashtype(enum  hash_type type)
{
	switch (type) {
	case VDFS4_HASH_UNDEF:
		return HW_IOVEC_HASH_NONE;
	case VDFS4_HASH_SHA1:
		return HW_IOVEC_HASH_SHA1;
	case VDFS4_HASH_SHA256:
		return HW_IOVEC_HASH_SHA256;
	case VDFS4_HASH_MD5:
		return HW_IOVEC_HASH_MD5;
	default:
		return 0;
	}
}

static inline int is_hw_compr_supported(struct vdfs4_inode_info *inode_i,
		const struct hw_capability *hw_cap)

{
	enum compr_type compr_type = inode_i->fbc->compr_type;

	return hw_cap->comp_type & convert_hw_comptype(compr_type);
}

void *vdfs_get_hwdec_fn(struct vdfs4_inode_info *inode_i)
{
	const struct hw_capability hw_cap = get_hw_capability();

	if (inode_i->vfs_inode.i_sb->s_bdev->bd_disk->fops->hw_decompress_vec
		&& is_hw_compr_supported(inode_i, &hw_cap))
		return vdfs4_auth_decompress_hw2;

	return NULL;
}

static int hw2_unpack_chunk(struct inode *inode,
		struct vdfs4_comp_extent_info *cext, struct page **out_pages,
		int out_pages_num, struct req_hw *rq_hw)
{
	pgoff_t first_idx = cext->start_block;
	size_t offset = cext->offset;
	size_t chunk_len = cext->len_bytes;
	struct vdfs4_sb_info *sbi = VDFS4_SB(inode->i_sb);
	struct block_device *bdev = inode->i_sb->s_bdev;
	const struct block_device_operations *ops = bdev->bd_disk->fops;

	int ret;
	pgoff_t start_offset;
	int chunk_blocks_num;

	pgoff_t pstart, blocks_n;
	struct vdfs4_extent_info pext;
	sector_t chunk_start_sector;
	struct hw_iovec iovec;

	ret = vdfs4_get_iblock_extent(inode, first_idx, &pext, NULL);
	if (ret)
		return ret;

	start_offset = first_idx - pext.iblock;
	pstart = pext.first_block + start_offset;
	if (start_offset >= pext.block_count)
		return -EAGAIN;

	blocks_n = pext.block_count - start_offset;

	/* Check if chunk is fragmented */
	chunk_blocks_num = (chunk_len + PAGE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	if (blocks_n < chunk_blocks_num)
		return -EAGAIN;

	chunk_start_sector = (sector_t)pstart <<
		(sbi->block_size_shift - SECTOR_SIZE_SHIFT);

#ifdef CONFIG_VDFS4_SQUEEZE_PROFILING
	vdfs4_save_profiling_log(sbi, inode->i_ino,
			cext->start_block, cext->blocks_n);
#endif

	iovec = (struct hw_iovec){
		.phys_off = ((unsigned long long)chunk_start_sector << 9) +
			    offset,
		.len = chunk_len,
	};

	ret = ops->hw_decompress_vec(bdev, &iovec, 1, out_pages,
				      out_pages_num, rq_hw);
	return ret;
}

static int __find_get_pages(struct inode *inode, pgoff_t index,
		struct page **pages, int pages_count)
{
	int i;

	for (i = 0; i < (int)pages_count; i++) {
		pages[i] = find_or_create_page(inode->i_mapping,
				index + (pgoff_t)i, GFP_NOFS);
		if (!pages[i]) {
			while (--i >= 0) {
				unlock_page(pages[i]);
				page_cache_release(pages[i]);
			}
			return -ENOMEM;
		}
	}
	return 0;
}

static int vdfs4_hw2_prep_req(struct inode *inode,
		struct vdfs4_comp_extent_info *ext,
		int comp_extent_idx,
		struct req_hw *req)
{
	int ret = 0;
	struct vdfs4_inode_info *inode_i = VDFS4_I(inode);
	const struct hw_capability hw_cap = get_hw_capability();
	int compr = !(ext->flags & VDFS4_CHUNK_FLAG_UNCOMPR);
	int auth = is_vdfs4_inode_flag_set(inode, VDFS4_AUTH_FILE) &&
			is_sbi_flag_set(VDFS4_SB(inode->i_sb), VOLUME_AUTH);

	/* fallback to sw path if we must just read data */
	if (!compr && !auth)
		return -EINVAL;

	if (!compr)
		req->compr_type =
				(hw_cap.comp_type & HW_IOVEC_COMP_UNCOMPRESSED) ?
				HW_IOVEC_COMP_UNCOMPRESSED : 0;
	else
		req->compr_type =
				convert_hw_comptype(VDFS4_I(inode)->fbc->compr_type);

	if (!req->compr_type)
		return -EINVAL;

	if (auth) {
		req->hash_type = convert_hw_hashtype(inode_i->fbc->hash_type);
		if (!req->hash_type)
			VDFS4_BUG(VDFS4_SB(inode->i_sb));
		if (!(req->hash_type & hw_cap.hash_type))
			/*
				is this really needed? It looks like do_decompression()
				can process every hash type
			*/
			return -EINVAL;

		req->hashdata = kzalloc(inode_i->fbc->hash_len, GFP_NOFS);
		if (!req->hashdata)
			return -ENOMEM;
	} else
		req->hash_type = HW_IOVEC_HASH_NONE;

	return ret;
}

static inline void vdfs4_hw2_free_req(struct req_hw *req)
{
	kfree(req->hashdata);
}

int vdfs4_auth_decompress_hw2(struct inode *inode, struct page *page)
{
	int ret = 0, i;
	struct vdfs4_comp_extent_info cext;
	struct vdfs4_inode_info *inode_i = VDFS4_I(inode);
	int comp_extent_idx = (int)(page->index >> (inode_i->fbc->log_chunk_size
				- PAGE_SHIFT));
	struct page **dst_pages = NULL;
	int pages_count = vdfs4_chunk_page_count(inode, comp_extent_idx);
	pgoff_t index = page->index & ~((1 << (inode_i->fbc->log_chunk_size -
					PAGE_SHIFT)) - 1);
	struct req_hw req_hw = {0};
	int auth = is_vdfs4_inode_flag_set(inode, VDFS4_AUTH_FILE) &&
			is_sbi_flag_set(VDFS4_SB(inode->i_sb), VOLUME_AUTH);
	VT_PREPARE_PARAM(vt_data);

	if (PageUptodate(page))
		/* somebody read it for us */
		return 0;

	VT_START(vt_data);
	ret = __get_chunk_extent(inode_i, comp_extent_idx, &cext);
	if (ret)
		goto exit;

	ret = vdfs4_hw2_prep_req(inode, &cext, comp_extent_idx, &req_hw);
	if (ret)
		goto exit;

	dst_pages = kzalloc(pages_count * sizeof(struct page *), GFP_NOFS);
	if (!dst_pages) {
		ret = -ENOMEM;
		goto exit;
	}

	ret = __find_get_pages(inode, index, dst_pages, pages_count);
	if (ret) {
		kfree(dst_pages);
		ret = -ENOMEM;
		goto exit;
	}

	ret = hw2_unpack_chunk(inode, &cext, dst_pages, pages_count, &req_hw);

	if (ret < 0)
		goto exit_unlock;
	else
		ret = 0;

	if (auth)
		/*This is AUTH FILE. check hash value, compare to disk value */
		ret = vdfs4_check_hash_chunk_no_calc(inode_i, comp_extent_idx,
				req_hw.hashdata);

	if (!ret)
		for (i = 0; i < pages_count; ++i) {
			SetPageUptodate(dst_pages[i]);
			mark_page_accessed(dst_pages[i]);
		}
exit_unlock:
	for (i = 0; i < pages_count; ++i) {
		unlock_page(dst_pages[i]);
		page_cache_release(dst_pages[i]);
	}
	kfree(dst_pages);
	vdfs4_hw2_free_req(&req_hw);
exit:
	VT_DECOMP_FINISH(vt_data, vdfs_trace_decomp_hw, inode,
			 (cext.start_block << PAGE_CACHE_SHIFT) + cext.offset,
			 cext.len_bytes, auth,
			 !!ret,(cext.flags&VDFS4_CHUNK_FLAG_UNCOMPR));
	return ret;
}
#endif /* end of CONFIG_VDFS4_HW_DECOMPRESS_SUPPORT */

#define COMPR_TABLE_EXTENTS_PER_PAGE (PAGE_CACHE_SIZE \
		/ sizeof(struct vdfs4_comp_extent))

/* just read a chunk from disk
 * the function returns uptodated pages*/
int vdfs4_read_chunk(struct page *page, struct page **chunk_pages,
	struct vdfs4_comp_extent_info *cext)
{
	struct inode *inode = page->mapping->host;
	struct vdfs4_inode_info *inode_i = VDFS4_I(inode);
	int comp_extent_idx = (int)(page->index >>
			(inode_i->fbc->log_chunk_size - PAGE_SHIFT));
	pgoff_t index = page->index & ~((1lu << (inode_i->fbc->log_chunk_size -
					(unsigned long)PAGE_SHIFT)) - 1lu);
	sector_t page_idx = 0;
	int ret = 0, count, type = VDFS4_FBASED_READ_C;
	/* block device inode i_mapping is used to store compressed pages */
	struct address_space *mapping =
		inode->i_sb->s_bdev->bd_inode->i_mapping;
	sector_t start_block = 0;

	ret = __get_chunk_extent(inode_i, comp_extent_idx, cext);
	if (ret)
		return ret;

	if (cext->flags & VDFS4_CHUNK_FLAG_UNCOMPR) {
		/* read un-compressed data directly into the inode->i_mapping */
		mapping = inode->i_mapping;
		type = VDFS4_FBASED_READ_UNC;
		start_block = cext->start_block;
	}

#ifdef CONFIG_VDFS4_SQUEEZE_PROFILING
	vdfs4_save_profiling_log(VDFS4_SB(inode->i_sb), inode->i_ino,
			cext->start_block, cext->blocks_n);
#endif

	for (count = 0; count < cext->blocks_n; count++) {
		if (cext->flags & VDFS4_CHUNK_FLAG_UNCOMPR)
			page_idx = (sector_t)index + (sector_t)count;
		else {
			ret = vdfs4_get_block_file_based(inode,
					cext->start_block + (pgoff_t)count,
					&page_idx);
			if (ret)
				goto exit;
		}

		chunk_pages[count] = find_or_create_page(mapping,
				(pgoff_t)page_idx, GFP_NOFS | __GFP_HIGHMEM);
		if (!chunk_pages[count]) {
			ret = -ENOMEM;
			goto exit;
		}
		if (!PageChecked(chunk_pages[count]))
			ClearPageUptodate(chunk_pages[count]);
	}

	ret = vdfs4__read(inode, type, chunk_pages, cext->blocks_n,
			start_block);
exit:
	for (count = 0; count < cext->blocks_n; count++) {
		if (chunk_pages[count]) {
			lock_page(chunk_pages[count]);
			if (ret) {
				ClearPageUptodate(chunk_pages[count]);
				ClearPageChecked(chunk_pages[count]);
				page_cache_release(chunk_pages[count]);
			} else {
				SetPageChecked(chunk_pages[count]);
			}
			unlock_page(chunk_pages[count]);
		}
	}

	return ret;
}

int vdfs4_auth_decompress_sw(struct inode *inode, struct page **chunk_pages,
		pgoff_t index, struct vdfs4_comp_extent_info *cext,
		struct page *page)
{
	struct page **unpacked_pages = NULL;
	struct vdfs4_inode_info *inode_i = VDFS4_I(inode);
	void *src = NULL, *dst = NULL;
	int ret = 0;
	unsigned int i;
	int comp_extent_idx = (int)(index >> (inode_i->fbc->log_chunk_size -
			PAGE_SHIFT));
	unsigned int pages_count = vdfs4_chunk_page_count(inode, comp_extent_idx);

	if (!inode_i->fbc->hash_fn && (cext->flags & VDFS4_CHUNK_FLAG_UNCOMPR))
		/* nothing to do: non-auth, non-compressed chunk */
		return 0;

	src = vdfs4_vm_map_ram(chunk_pages, (unsigned)cext->blocks_n, -1,
			PAGE_KERNEL);
	if (!src)
		return -ENOMEM;

	/* if we have the hash_fn then we must do authentication */
	if (inode_i->fbc->hash_fn) {
		ret = vdfs4_check_hash_chunk(inode_i,
			(char *)src + cext->offset, (size_t)cext->len_bytes,
			comp_extent_idx);
		if (ret)
			goto exit;
	}

	if (cext->flags & VDFS4_CHUNK_FLAG_UNCOMPR)
		goto exit_uncompressed;

	unpacked_pages = kzalloc(pages_count * sizeof(struct page *), GFP_NOFS);
	if (!unpacked_pages) {
		ret = -ENOMEM;
		goto exit;
	}

	for (i = 0; i < pages_count; i++) {
		unpacked_pages[i] = find_or_create_page(inode->i_mapping,
				index + (pgoff_t)i, GFP_NOFS);
		if (!unpacked_pages[i]) {
			while (i-- > 0) {
				unlock_page(unpacked_pages[i]);
				page_cache_release(unpacked_pages[i]);
			}

			ret = -ENOMEM;
			goto exit_alloc_pages;
		}
	}
	/* Somebody already read it for us */
	if (PageUptodate(page)) {
		for (i = 0; i < pages_count; i++) {
			unlock_page(unpacked_pages[i]);
			page_cache_release(unpacked_pages[i]);
		}
		ret = 0;
		goto exit_alloc_pages;
	}

	dst = vdfs4_vm_map_ram(unpacked_pages, pages_count, -1, PAGE_KERNEL);
	if (!dst) {
		ret = -ENOMEM;
		VDFS4_ERR("cannot allocate memory for file-based decom");
		goto exit_free_pages;
	}

	ret = inode_i->fbc->decomp_fn(src,
			dst, (size_t)cext->offset,
			(size_t)cext->len_bytes,
			(size_t)(pages_count << PAGE_SHIFT));
#ifdef VDFS4_DEBUG_DUMP
	if (ret)
		/* dump file based decompression error */
		vdfs4_dump_fbc_error(inode_i, src, cext);
#endif
exit_free_pages:
	for (i = 0; i < pages_count; i++) {
		if (!ret) {
			SetPageUptodate(unpacked_pages[i]);
			mark_page_accessed(unpacked_pages[i]);
		}
		unlock_page(unpacked_pages[i]);
		page_cache_release(unpacked_pages[i]);
	}
exit_alloc_pages:
	kfree(unpacked_pages);
exit:
	if (dst)
		vm_unmap_ram(dst, pages_count);
exit_uncompressed:
	if (src)
		vm_unmap_ram(src, cext->blocks_n);

	return ret;
}

/* type : 0 - meta , 1 - packtree, 2 - filebased decompression */
int vdfs4_read_or_create_pages(struct inode *inode, pgoff_t index,
			      unsigned int pages_count, struct page **pages,
			      enum vdfs4_read_type type, int start_block,
			      int force_insert)
{
	struct vdfs4_sb_info *sbi = VDFS4_SB(inode->i_sb);
	struct address_space *mapping = NULL;
	int count, ret = 0;
	struct page *page = NULL;
	char is_new = 0;
	int validate_err;
	int reread_count = 0;

	if (type == VDFS4_META_READ && (inode->i_ino <= VDFS4_LSFILE)) {
		ret = vdfs4_check_page_offset(sbi, inode, index, &is_new,
				force_insert);
		if (ret)
			return ret;
	}

	mapping = inode->i_mapping;

	for (count = 0; count < (int)pages_count; count++) {
		page = find_or_create_page(mapping, index + (unsigned)count,
				GFP_NOFS | __GFP_HIGHMEM);
		if (!page) {
			ret = -ENOMEM;
			goto exit_alloc_page;
		}
		pages[count] = page;

		if (is_new) {
			ret = vdfs4_init_bitmap_page(sbi, inode->i_ino, page);
			if (ret)
				goto exit_alloc_locked_page;
			SetPageUptodate(page);
			SetPageChecked(page);
		}
	}

do_reread:
	validate_err = 0;
	ret = vdfs4__read(inode, type, pages, pages_count, start_block);
	if (ret)
		goto exit_vdfs4_meta_read;

	if (inode->i_ino > VDFS4_LSFILE)
		return ret;

	for (count = 0; count < (int)pages_count; count++) {
		page = pages[count];
		if (!PageChecked(page) && (!is_tree(inode->i_ino))) {
			lock_page(page);
			if (PageChecked(page)) {
				unlock_page(page);
				continue;
			}

			ret = vdfs4_validate_page(page);
			if (ret) {
				validate_err = 1;
				ClearPageUptodate(page);
			} else
				SetPageChecked(page);
			unlock_page(page);
		}
	}

	ret = (validate_err) ? -EINVAL : 0;

	if (ret && (reread_count < VDFS4_META_REREAD)) {
		reread_count++;
		VDFS4_ERR("do re-read bitmap %d", reread_count);
		for (count = 0; count < (int)pages_count; count++)
			lock_page(pages[count]);
		goto do_reread;
	}

	if (ret && (is_sbi_flag_set(sbi, IS_MOUNT_FINISHED)))
			vdfs4_fatal_error(sbi, "bitmap validate FAIL");

	if (ret)
		goto exit_validate_page;

	return ret;
exit_alloc_page:
	VDFS4_ERR("Error in allocate page");
	for (; count > 0; count--) {
		unlock_page(pages[count - 1]);
		page_cache_release(pages[count - 1]);
	}
	return ret;
exit_alloc_locked_page:
	VDFS4_ERR("Error in init bitmap page");
	for (; count >= 0; count--) {
		unlock_page(pages[count]);
		page_cache_release(pages[count]);
	}
	return ret;
exit_validate_page:
	VDFS4_ERR("Error in exit_validate_page");
exit_vdfs4_meta_read:
	release_pages(pages, (int)pages_count, 0);
	return ret;
}

struct page *vdfs4_read_or_create_page(struct inode *inode, pgoff_t index,
		enum vdfs4_read_type type)
{
	struct page *pages[1];
	int err = 0;

	err = vdfs4_read_or_create_pages(inode, index, 1, pages, type,
			0, 0);
	if (err)
		return ERR_PTR(err);

	return pages[0];
}

struct bio *vdfs4_mpage_bio_submit(int rw, struct bio *bio)
{
	bio->bi_end_io = end_io_write;
	submit_bio(rw, bio);
	return NULL;
}

int vdfs4_mpage_writepage(struct page *page,
		struct writeback_control *wbc, void *data)
{
	struct vdfs4_mpage_data *mpd = data;
	struct bio *bio = mpd->bio;
	struct address_space *mapping = page->mapping;
	struct inode *inode = page->mapping->host;
	struct vdfs4_sb_info *sbi = VDFS4_SB(inode->i_sb);
	struct block_device *bdev = sbi->sb->s_bdev;
	sector_t offset_alloc_hint = 0;
	unsigned blocksize;
	sector_t block_in_file;
	struct vdfs4_extent_info extent;
	const unsigned blkbits = inode->i_blkbits;
	int err = 0;
	sector_t boundary_block = 0;
	unsigned long end_index;
	struct vdfs4_inode_info *inode_info = VDFS4_I(inode);
	struct buffer_head *bh;
	loff_t i_size = i_size_read(inode);

	memset(&extent, 0x0, sizeof(extent));
	block_in_file = (sector_t)page->index << (PAGE_CACHE_SHIFT - blkbits);
	blocksize = (unsigned int)(1 << inode->i_blkbits);
	if (page_has_buffers(page)) {
		bh = page_buffers(page);
		VDFS4_BUG_ON(buffer_locked(bh), sbi);
		mutex_lock(&inode_info->truncate_mutex);
		if (buffer_mapped(bh)) {
			if (buffer_delay(bh)) {
				/* get extent which contains a iblock*/
				err = vdfs4_get_iblock_extent(&inode_info->vfs_inode,
					block_in_file, &extent,
					&offset_alloc_hint);
				/* buffer was allocated during writeback
				 * operation */
				if ((extent.first_block == 0) || err) {
					err = vdfs4_get_block_da(inode,
							block_in_file, bh, 1);
					if (err) {
						mutex_unlock(&inode_info->
								truncate_mutex);
						unlock_page(page);
						goto out;
					}
				} else {
					bh->b_blocknr = extent.first_block +
						(block_in_file - extent.iblock);
					clear_buffer_delay(bh);
				}
				unmap_underlying_metadata(bh->b_bdev,
					bh->b_blocknr);
			}
		} else {
			/*
			* unmapped dirty buffers are created by
			* __set_page_dirty_buffers -> mmapped data
			*/
			if (buffer_dirty(bh)) {
				if (vdfs4_get_int_block(inode, block_in_file, bh, 1, 0)) {
					mutex_unlock(&inode_info->truncate_mutex);
					goto confused;
				}
				if (buffer_new(bh))
					unmap_underlying_metadata(bh->b_bdev,
							bh->b_blocknr);
			}
		}
		mutex_unlock(&inode_info->truncate_mutex);

		if (!buffer_dirty(bh) || !buffer_uptodate(bh))
			goto confused;

	} else {
		/*
		* The page has no buffers: map it to disk
		*/
		VDFS4_BUG_ON(!PageUptodate(page), sbi);

		create_empty_buffers(page, blocksize, 0);
		bh = page_buffers(page);

		bh->b_state = 0;
		bh->b_size = (size_t)(1lu << blkbits);
		if (vdfs4_get_block(inode, block_in_file, bh, 1))
			goto confused;
		if (buffer_new(bh))
			unmap_underlying_metadata(bh->b_bdev,
					bh->b_blocknr);

	}

	boundary_block = bh->b_blocknr;
	end_index = (unsigned long int)(i_size >> PAGE_CACHE_SHIFT);
	if (page->index >= end_index) {
		/*
		 * The page straddles i_size.  It must be zeroed out on each
		 * and every writepage invocation because it may be mmapped.
		 * "A file is mapped in multiples of the page size.  For a file
		 * that is not a multiple of the page size, the remaining memory
		 * is zeroed when mapped, and writes to that region are not
		 * written out to the file."
		 */
		unsigned offset = i_size & (PAGE_CACHE_SIZE - 1);

		if (page->index > end_index || !offset)
			goto confused;
		zero_user_segment(page, offset, PAGE_CACHE_SIZE);
	}

	/*
	 * If it's the end of contiguous chunk, submit the BIO.
	 */
	if (bio && mpd->last_block_in_bio != boundary_block - 1)
		bio = vdfs4_mpage_bio_submit(WRITE, bio);


alloc_new:
	bdev = bh->b_bdev;
	boundary_block = bh->b_blocknr;
	if (boundary_block == 0)
		VDFS4_BUG(sbi);
	if (IS_ERR_OR_NULL(bio)) {
		sector_t s_count = (sector_t)(bdev->bd_inode->i_size >>
							SECTOR_SIZE_SHIFT);
		sector_t first_sector = (boundary_block << (blkbits - 9));
		unsigned nr_vecs = (unsigned)bio_get_nr_vecs(bdev);
		unsigned s_nr_vecs = nr_vecs * SECTOR_PER_PAGE;

		if (first_sector + s_nr_vecs > s_count)
			nr_vecs = (s_count - first_sector) / SECTOR_PER_PAGE;

		if (nr_vecs > 0)
			bio = __allocate_new_bio(bdev, first_sector, nr_vecs);

		if (IS_ERR_OR_NULL(bio))
			goto confused;
	}

	/*
	 * TODO: replace PAGE_SIZE with real user data size?
	 */
	if (bio_add_page(bio, page, PAGE_SIZE, 0) < (int)PAGE_SIZE) {
		bio = vdfs4_mpage_bio_submit(WRITE, bio);
		goto alloc_new;
	}

	/*
	 * OK, we have our BIO, so we can now mark the buffers clean.  Make
	 * sure to only clean buffers which we know we'll be writing.
	 */
	if (page_has_buffers(page)) {
		struct buffer_head *head = page_buffers(page);

		clear_buffer_dirty(head);
	}

	VDFS4_BUG_ON(PageWriteback(page), sbi);
	set_page_writeback(page);
	unlock_page(page);
	mpd->last_block_in_bio = boundary_block;
	goto out;

confused:
	if (IS_ERR_OR_NULL(bio))
		bio = NULL;
	else
		bio = vdfs4_mpage_bio_submit(WRITE, bio);
	if (buffer_mapped(bh))
		if (bh->b_blocknr == 0)
			VDFS4_BUG(sbi);

	/*
	 * vdfs4_writepage cannot perform delayed allocations
	 */
	err = block_write_full_page(page, vdfs4_get_block, wbc);

	/*
	 * The caller has a ref on the inode, so *mapping is stable
	 */
out:
	mapping_set_error(mapping, err);
	mpd->bio = bio;
	return err;
}

