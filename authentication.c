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
#include <linux/swap.h>
#include <linux/vmalloc.h>
#include <crypto/crypto_wrapper.h>

#ifdef CONFIG_VDFS4_DATA_AUTHENTICATION
static void print_path_to_object(struct vdfs4_sb_info *sbi, ino_t start_ino)
{
	struct inode *inode;
	char *buffer, *new_buffer = NULL;
	int buffer_len = 1;
	const char *device = sbi->sb->s_id;

	buffer = kzalloc(1, GFP_NOFS);
	if (!buffer)
		return;
	inode = vdfs4_iget(sbi, start_ino);

	if (!IS_ERR(inode))
		do {
			size_t name_len;
			struct vdfs4_inode_info *inode_i = VDFS4_I(inode);
			ino_t next_ino = 0;

			if (!inode_i->name) {
				iput(inode);
				break;
		}

		name_len = strlen(inode_i->name);
		new_buffer = kzalloc(name_len + 1 + buffer_len, GFP_NOFS);
		if (!new_buffer) {
			iput(inode);
			VDFS4_ERR("cannot allocate memory to print a path");
			break;
		}
		memcpy(new_buffer, inode_i->name, name_len);
		new_buffer[name_len] = 0x2f;
		memcpy(new_buffer + name_len + 1, buffer, buffer_len);
		buffer_len += name_len + 1;
		kfree(buffer);
		buffer = new_buffer;
		new_buffer = NULL;
		next_ino = (ino_t)inode_i->parent_id;
		iput(inode);
		/* if next_ino == 1, next dir is root */
		if (next_ino == 1)
			break;
		inode = vdfs4_iget(sbi, next_ino);
	} while (!IS_ERR(inode));

	VDFS4_ERR("VDFS4(%s) path : %s", device, buffer);

	kfree(buffer);
}

int vdfs4_verify_rsa_signature(struct vdfs4_inode_info *inode_i,
		void *buf, size_t buf_len, void *signature)
{
	int ret = 0;
	rsakey_t *pkey = (VDFS4_SB(inode_i->vfs_inode.i_sb))->rsa_key;
	void *hash = kzalloc(inode_i->fbc->hash_len, GFP_NOFS);
	if (!hash)
		return -ENOMEM;


	ret = inode_i->fbc->hash_fn(buf, buf_len, hash);
	if (ret)
		goto exit;

	ret = rsa_check_signature(pkey, signature, VDFS4_CRYPTED_HASH_LEN,
			hash, inode_i->fbc->hash_len, RSA_PADDING_PKCS1_TYPE1);

exit:
	kfree(hash);
	return ret;
}

int vdfs4_verify_superblock_rsa_signature(enum hash_type hash_type,
		void *buf, size_t buf_len,
		void *signature, rsakey_t *pkey)
{
	int ret = 0;
	uint32_t hash_len = 0;
	void *hash = NULL;

	switch (hash_type) {

	case (VDFS4_HASH_SHA1) :
		hash_len = VDFS4_SHA1_HASH_LEN;
		hash = kzalloc(hash_len, GFP_NOFS);
		if (!hash)
			return -ENOMEM;
		ret = calculate_sw_hash_sha1(buf, buf_len, hash);
		break;
	case (VDFS4_HASH_SHA256) :
		hash_len = VDFS4_SHA256_HASH_LEN;
		hash = kzalloc(hash_len, GFP_NOFS);
		if (!hash)
			return -ENOMEM;
		ret = calculate_sw_hash_sha256(buf, buf_len, hash);
		break;
	case (VDFS4_HASH_MD5) :
		hash_len = VDFS4_MD5_HASH_LEN;
		hash = kzalloc(hash_len, GFP_NOFS);
		if (!hash)
			return -ENOMEM;
		ret = calculate_sw_hash_md5(buf, buf_len, hash);
		break;
	default:
		ret = -EINVAL;
		break;
	};

	if (ret)
		goto exit;
	ret = rsa_check_signature(pkey, signature, VDFS4_CRYPTED_HASH_LEN,
		hash, hash_len, RSA_PADDING_PKCS1_TYPE1);
exit:
	kfree(hash);
	return ret;

}

static int vdfs4_get_and_cmp_hash(struct vdfs4_inode_info *inode_i, size_t chunk_idx,
		size_t comp_chunks_count, void *hash_calc, size_t hash_len)
{
	void *data;
	pgoff_t page_idx;
	int pos;
	loff_t hash_offset;
	int ret = 0;
	struct page *pages[2] = {0};
	void *hash_orig = kzalloc(hash_len, GFP_NOFS);
	if(!hash_orig)
		return -ENOMEM;

	hash_offset = inode_i->fbc->comp_table_start_offset +
		(unsigned int)comp_chunks_count *
		sizeof(struct vdfs4_comp_extent) +
		inode_i->fbc->hash_len * chunk_idx;
	page_idx = (pgoff_t)(hash_offset >> PAGE_CACHE_SHIFT);
	pos = hash_offset & (PAGE_CACHE_SIZE - 1);
	if (PAGE_CACHE_SIZE - (hash_offset - ((hash_offset >> PAGE_CACHE_SHIFT)
			<< PAGE_CACHE_SHIFT)) < inode_i->fbc->hash_len) {
		ret = vdfs4_read_comp_pages(&inode_i->vfs_inode, page_idx,
			2, pages, VDFS4_FBASED_READ_M);
		if (ret)
			goto err_read;

		data = vdfs4_vmap(pages, 2, VM_MAP, PAGE_KERNEL);
		if (data) {
			memcpy(hash_orig, (char *)data + pos,
					inode_i->fbc->hash_len);
			vunmap(data);
		} else {
			ret = -ENOMEM;
			goto err;
		}
	} else {
		ret = vdfs4_read_comp_pages(&inode_i->vfs_inode, page_idx,
			1, pages, VDFS4_FBASED_READ_M);
		if (ret)
			goto err_read;
		data = kmap_atomic(pages[0]);
		memcpy(hash_orig, (char *)data + pos, inode_i->fbc->hash_len);
		kunmap_atomic(data);
	}

	if(memcmp(hash_orig, hash_calc, hash_len)) {
		struct vdfs4_sb_info *sbi = inode_i->vfs_inode.i_sb->s_fs_info;
		VDFS4_ERR("File based decompression - hash mismatch"
				" for inode - %lu, file name - %s, chunk - %d",
				inode_i->vfs_inode.i_ino, INODEI_NAME(inode_i), chunk_idx);
		VDFS4_MDUMP("Original hash:",
				hash_orig, hash_len);
		VDFS4_MDUMP("Calculated hash:",
				hash_calc, hash_len);
		if (inode_i->parent_id != 1)
			print_path_to_object(sbi, inode_i->parent_id);
		ret = -EINVAL;
	}
err:
	for (page_idx = 0; page_idx < 2; page_idx++) {
		if(pages[page_idx]) {
			if(ret) {
				lock_page(pages[page_idx]);
				ClearPageChecked(pages[page_idx]);
				unlock_page(pages[page_idx]);
			}
			mark_page_accessed(pages[page_idx]);
			page_cache_release(pages[page_idx]);
		}
	}
err_read:
	kfree(hash_orig);
	return ret;
}

int vdfs4_check_hash_chunk(struct vdfs4_inode_info *inode_i,
		void *buffer, size_t length, size_t extent_idx)
{
	void *hash_calc = kzalloc(inode_i->fbc->hash_len, GFP_NOFS);
	int ret;

	if (!hash_calc)
		return -ENOMEM;

	ret = inode_i->fbc->hash_fn(buffer, length, hash_calc);
	if (ret)
		goto exit;

	ret = vdfs4_get_and_cmp_hash(inode_i, extent_idx, inode_i->fbc->comp_extents_n,
			hash_calc, inode_i->fbc->hash_len);
exit:
	kfree(hash_calc);
	return ret;
}

int vdfs4_check_hash_chunk_no_calc(struct vdfs4_inode_info *inode_i,
		size_t extent_idx, void *hash_calc)
{
	return vdfs4_get_and_cmp_hash(inode_i, extent_idx, inode_i->fbc->comp_extents_n,
			hash_calc, inode_i->fbc->hash_len);
}

int vdfs4_check_hash_meta(struct vdfs4_inode_info *inode_i,
		struct vdfs4_comp_file_descr *descr)
{
	void *hash_calc = kzalloc(inode_i->fbc->hash_len, GFP_NOFS);
	int ret;
	if (!hash_calc)
		return -ENOMEM;

	ret = inode_i->fbc->hash_fn((unsigned char *)descr,
			(size_t)((char *)&descr->crc -
			(char *)&descr->magic), hash_calc);
	if (ret)
		goto exit;

	ret = vdfs4_get_and_cmp_hash(inode_i, (int)le16_to_cpu(descr->extents_num),
			(int)le16_to_cpu(descr->extents_num),
			hash_calc, inode_i->fbc->hash_len);
exit:
	kfree(hash_calc);
	return ret;
}

int vdfs4_verify_file_signature(struct vdfs4_inode_info *inode_i, void *data)
{
	int ret = 0;
	loff_t start_offset = inode_i->fbc->comp_table_start_offset;
	unsigned int extents_num = (unsigned int)inode_i->fbc->comp_extents_n;

	ret = vdfs4_verify_rsa_signature(inode_i, (char *)data + (start_offset
			& (PAGE_SIZE - 1))
			+ extents_num * sizeof(struct vdfs4_comp_extent),
			(extents_num + 1) * inode_i->fbc->hash_len,
			(char *)data +
			(start_offset & (PAGE_SIZE - 1)) + extents_num *
			(sizeof(struct vdfs4_comp_extent)) +
			(extents_num + 1) * inode_i->fbc->hash_len);

	if (ret) {
		VDFS4_ERR("File based decompression RSA signature mismatch."
				"Inode number - %lu, file name - %s",
				inode_i->vfs_inode.i_ino, inode_i->name);
		ret = -EINVAL;
	}
	return ret;
}


#else

int vdfs4_verify_file_signature(struct vdfs4_inode_info *inode_i, void *data)
{
	return 0;
};
int vdfs4_check_hash_meta(struct vdfs4_inode_info *inode_i,
		struct vdfs4_comp_file_descr *descr)
{
	return 0;
};
int vdfs4_check_hash_chunk(struct vdfs4_inode_info *inode_i,
		void *buffer, size_t length, size_t extent_idx) {return 0;};

int vdfs4_check_hash_chunk_no_calc(struct vdfs4_inode_info *inode_i,
		size_t extent_idx, void *hash_calc) {return 0;};
#endif
