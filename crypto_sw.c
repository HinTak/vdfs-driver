/**
 * VDFS4 -- Vertically Deliberate improved performance File System
 *
 * Copyright 2015 by Samsung Electronics, Inc.
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

#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/vmalloc.h>
#include <linux/scatterlist.h>
#include <linux/blkdev.h>

#include "vdfs4.h"
#include "crypto.h"
#include "crypto_sw.h"

int vdfs4_crypto_alloc_buffer(struct page ***pages,
		int no_pages, void **virt)
{
	struct page **new_pages = NULL;
	int i;
	void* addr = NULL;

	new_pages = kmalloc(no_pages * sizeof(*new_pages), GFP_NOFS);
	if(!new_pages)
		return -ENOMEM;
	for(i=0; i<no_pages; ++i) {
		new_pages[i] = alloc_page(GFP_NOFS);
		if(!new_pages[i])
			goto err_alloc_pages;
	}
	addr = vdfs4_vm_map_ram(new_pages, (unsigned)no_pages, -1,
			PAGE_KERNEL);
	if(!addr)
		goto err_alloc_pages;

	*virt = addr;
	*pages = new_pages;
	return 0;

err_alloc_pages:
	while (--i >= 0)
		__free_pages(new_pages[i], 0);
	kfree(new_pages);
	return -ENOMEM;
}

inline void vdfs4_crypto_free_buffer(struct page **pages,
		int no_pages, void* virt)
{
	int i;
	vm_unmap_ram(virt, no_pages);
	for(i=0; i<no_pages; ++i)
		__free_pages(pages[i], 0);
	kfree(pages);
}

/* This function is workaround for crypto-api/linux bug(?).
 * When vdfs is mounted as rootfs and some encrypted file
 * is about to be read then crypto_alloc_blkcipher() is called
 * for that file by vdfs4_crypto_alloc_blkcipher().
 * Next request_module("ctr(aes)") is called from alloc_blkcipher() which is
 * trying to access encrypted kmod user binary on rootfs which causes
 * 'deadlock' (crypto_alloc_blkcipher() must be done also for kmod).
 * vdfs_crypto_alloc_workaround() is called before rootfs mount
 * finishes thus causing request_module() to fail instead of deadlocking
 * and allowing crypto_alloc_blkcipher() to finish happily.
 */
void vdfs4_crypto_alloc_workaround(void)
{
	struct crypto_blkcipher* tfm = crypto_alloc_blkcipher("ctr(aes)", 0, 0);
	if(IS_ERR(tfm))
		VDFS4_ERR("Failed to alloc fake ctr(aes) blkcipher err=%ld\n",
				PTR_ERR(tfm));
	else
		crypto_free_blkcipher(tfm);
}

static struct scatterlist* vdfs4_crypto_alloc_sg(struct page **src,
		int pages_num, int offset, int len_bytes)
{
	struct scatterlist *sg;
	unsigned int i, bytes_left = len_bytes;
	int len;

	sg = kmalloc(sizeof(struct scatterlist) * (size_t)pages_num, GFP_NOFS);
	if(sg == NULL){
		VDFS4_ERR("No memory\n");
		return NULL;
	}

	sg_init_table(sg, pages_num);

	len = min_t(int, bytes_left, PAGE_SIZE - offset);
	sg_set_page(&sg[0], *src++,  len, offset);
	bytes_left -= len;

	for(i=1; i<pages_num; i++){
		len = min_t(int, PAGE_SIZE, bytes_left);
		sg_set_page(&sg[i], *src++, len, 0 );
		bytes_left -= len;
	}

	return sg;
}

static int vdfs4_crypto_alloc_blkcipher(struct blkcipher_desc* desc, unsigned char *ivec)
{
	int err;

	desc->flags = 0;
	desc->info = NULL;
	desc->tfm = crypto_alloc_blkcipher("ctr(aes)", 0, 0);
	if(IS_ERR(desc->tfm)) {
		err = PTR_ERR(desc->tfm);
		desc->tfm = NULL;
		return err;
	}

	err = crypto_blkcipher_setkey(desc->tfm, aes_debug_key,
			VDFS4_AES_KEY_LENGTH);
	if(err)
		goto exit_err;

	crypto_blkcipher_set_iv(desc->tfm, ivec, AES_IVEC_SIZE);

	return err;
exit_err:
	crypto_free_blkcipher(desc->tfm);
	return err;
}

static inline void vdfs4_crypto_destroy_blkcipher(struct blkcipher_desc* desc)
{
	crypto_free_blkcipher(desc->tfm);
}

static int vdfs4_crypto_sw_decrypt_pages(struct page **src, int src_pages_num,
		int src_offset, int len_bytes, struct page **dst,
		int dst_pages_num, int dst_offset,
		unsigned char* ivec)
{
	int ret = 0;
	struct scatterlist *src_sg, *dst_sg;
	struct blkcipher_desc desc;

	VDFS4_BUG_ON(src_offset % 8 || dst_offset % 8, NULL);

	ret = vdfs4_crypto_alloc_blkcipher(&desc, ivec);
	if(ret) {
		VDFS4_ERR("failed to alloc blkcipher");
		return ret;
	}

	src_sg = vdfs4_crypto_alloc_sg(src, src_pages_num,
			src_offset, len_bytes);
	if(src_sg == NULL){
		ret = -ENOMEM;
		goto err_alloc_src;
	}

	if(src != dst){
		dst_sg = vdfs4_crypto_alloc_sg(dst, dst_pages_num,
				dst_offset, len_bytes);
		if( dst_sg == NULL ){
			ret = -ENOMEM;
			goto err_alloc_dst;
		}
	}
	else
		dst_sg = src_sg;

	ret = crypto_blkcipher_decrypt(&desc,
			dst_sg, src_sg, len_bytes);
	if(ret < 0)
		VDFS4_ERR("crypto_blkcipher_encrypt: err=%d\n", ret);

	if(src != dst)
		kfree(dst_sg);
err_alloc_dst:
	kfree(src_sg);
err_alloc_src:
	vdfs4_crypto_destroy_blkcipher(&desc);
	return ret;
}

int vdfs4_crypto_decrypt_comp_ext(struct page **src, int src_pages_num,
		int src_offset, int len_bytes, struct page **dst,
		int dst_pages_num, int dst_offset, struct inode* inode,
		int comp_extent_idx)
{
	unsigned char ivec[AES_IVEC_SIZE];
	int ret;

	ret = vdfs4_crypto_setiv(inode, comp_extent_idx, ivec);
	if(ret)
		return ret;

	return vdfs4_crypto_sw_decrypt_pages(src, src_pages_num, src_offset,
			len_bytes, dst, dst_pages_num, dst_offset, ivec);
}
