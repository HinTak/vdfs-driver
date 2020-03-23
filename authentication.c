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


#ifdef CONFIG_VDFS4_DATA_AUTHENTICATION

void vdfs4_destroy_rsa_key(vdfs4_rsa_key *pkey)
{
	if (pkey) {
		if (pkey->rsa_n)
			mpi_free(pkey->rsa_n);
		if (pkey->rsa_e)
			mpi_free(pkey->rsa_e);
		kfree(pkey);
	}
}
vdfs4_rsa_key *vdfs4_create_rsa_key(const char *pub_rsa_n, const char *pub_rsa_e)
{
	vdfs4_rsa_key *pkey = kzalloc(sizeof(vdfs4_rsa_key), GFP_KERNEL);
	if (!pkey)
		return NULL;
	pkey->rsa_n = mpi_read_raw_data(pub_rsa_n, VDFS4_CRYPTED_HASH_LEN);
	pkey->rsa_e = mpi_read_raw_data(pub_rsa_e, 3);
	if (!pkey->rsa_n || !pkey->rsa_e) {
		vdfs4_destroy_rsa_key(pkey);
		return NULL;
	}
	return pkey;
}

static int vdfs4_check_signature(const vdfs4_rsa_key *pkey,
		const uint8_t *signature, uint32_t sign_len,
		const uint8_t *hash, uint32_t hash_len)
{
	int ret = -EINVAL;
	MPI m_sign = NULL, m_em = NULL;

	uint8_t *em = NULL;
	uint32_t em_len = 0;

	m_sign = mpi_alloc(0);
	m_em = mpi_alloc(0);
	if (!m_sign || !m_em) {
		ret = -ENOMEM;
		goto err;
	}
	m_sign = mpi_read_raw_data(signature, sign_len);
	if (mpi_powm(m_em, m_sign, pkey->rsa_e, pkey->rsa_n)) {
		VDFS4_ERR( "failed to perform modular exponentiation");
		goto err;
	}
	em = mpi_get_buffer(m_em, &em_len, NULL);
	if (!em) {
		VDFS4_ERR("failed to get MPI buffer");
		goto err;
	}

	if (!memcmp(hash, em, hash_len))
		ret = 0;
	kfree(em);
err:
	mpi_free(m_sign);
	mpi_free(m_em);
	return ret;
}

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
		new_buffer = kzalloc(name_len + 1, GFP_NOFS);
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

static int vdfs4_calculate_hash(unsigned char *buf, size_t buf_len,
		unsigned char *hash, const char *hash_type)
{
	int ret = 0;
	unsigned int size;
	struct crypto_shash *sha;
	struct sdesc *sdescsha;
	sha = crypto_alloc_shash(hash_type, 0, 0);
	if (IS_ERR(sha))
		return PTR_ERR(sha);

	size = sizeof(struct shash_desc) + crypto_shash_descsize(sha);
	sdescsha = kmalloc(size, GFP_NOFS);
	if (!sdescsha) {
		crypto_free_shash(sha);
		return -ENOMEM;
	}

	sdescsha->shash.tfm = sha;
	sdescsha->shash.flags = 0x0;
	ret = crypto_shash_init(&sdescsha->shash);
	if (ret)
		goto exit;
	ret = crypto_shash_update(&sdescsha->shash, buf, buf_len);
	if (ret)
		goto exit;
	ret = crypto_shash_final(&sdescsha->shash, hash);
exit:
	crypto_free_shash(sha);
	kfree(sdescsha);
	return ret;
}

int vdfs4_calculate_hash_md5(unsigned char *buf, size_t buf_len,
		char *hash)
{
	const char md5[] = "md5";
	return vdfs4_calculate_hash(buf, buf_len, hash, md5);
}


int vdfs4_calculate_hash_sha256(unsigned char *buf, size_t buf_len,
		char *hash)
{
	const char sha256[] = "sha256";
#ifndef CONFIG_CRYPTO_SHA256
	VDFS4_ERR("Can't calculate hash by sha256. CONFIG_CRYPTO_SHA256 is not set");
	return -EINVAL;
#endif
	return vdfs4_calculate_hash(buf, buf_len, hash, sha256);
}

int vdfs4_calculate_hash_sha1(unsigned char *buf, size_t buf_len,
		char *hash)
{
#ifdef	CONFIG_CRYPTO_SHA1_ARM_NEON
	const char sha1[] = "sha1-neon";
#else
	const char sha1[] = "sha1";
#endif
#ifndef CONFIG_CRYPTO_SHA1
	VDFS4_ERR("Can't calculate hash by sha1. CONFIG_CRYPTO_1 is not set");
	return -EINVAL;
#endif
	return vdfs4_calculate_hash(buf, buf_len, hash, sha1);
}

int vdfs4_verify_rsa_signature(struct vdfs4_inode_info *inode_i,
		void *buf, size_t buf_len, void *signature)
{
	int ret = 0;
	vdfs4_rsa_key *pkey = (VDFS4_SB(inode_i->vfs_inode.i_sb))->rsa_key;
	void *hash = kzalloc(inode_i->fbc->hash_len, GFP_NOFS);
	if (!hash)
		return -ENOMEM;


	ret = inode_i->fbc->hash_fn(buf, buf_len, hash);
	if (ret)
		goto exit;

	ret = vdfs4_check_signature(pkey, signature, VDFS4_CRYPTED_HASH_LEN,
			hash, inode_i->fbc->hash_len);

exit:
	kfree(hash);
	return ret;
}

int vdfs4_verify_superblock_rsa_signature(enum hash_type hash_type,
		void *buf, size_t buf_len,
		void *signature, vdfs4_rsa_key *pkey)
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
		ret = vdfs4_calculate_hash_sha1(buf, buf_len, hash);
		break;
	case (VDFS4_HASH_SHA256) :
		hash_len = VDFS4_SHA256_HASH_LEN;
		hash = kzalloc(hash_len, GFP_NOFS);
		if (!hash)
			return -ENOMEM;
		ret = vdfs4_calculate_hash_sha256(buf, buf_len, hash);
		break;
	case (VDFS4_HASH_MD5) :
		hash_len = VDFS4_MD5_HASH_LEN;
		hash = kzalloc(hash_len, GFP_NOFS);
		if (!hash)
			return -ENOMEM;
		ret = vdfs4_calculate_hash_md5(buf, buf_len, hash);
		break;
	default:
		ret = -EINVAL;
		break;
	};

	if (ret)
		goto exit;
	ret = vdfs4_check_signature(pkey, signature, VDFS4_CRYPTED_HASH_LEN,
		hash, hash_len);
exit:
	kfree(hash);
	return ret;

}

static int vdfs4_get_hash(struct vdfs4_inode_info *inode_i, size_t chunk_idx,
		size_t comp_chunks_count, void *hash)
{
	void *data;
	pgoff_t page_idx;
	int pos;
	loff_t hash_offset;
	int ret = 0;

	hash_offset = inode_i->fbc->comp_table_start_offset +
		(unsigned int)comp_chunks_count *
		sizeof(struct vdfs4_comp_extent) +
		inode_i->fbc->hash_len * chunk_idx;
	page_idx = (pgoff_t)(hash_offset >> PAGE_CACHE_SHIFT);
	pos = hash_offset & (PAGE_CACHE_SIZE - 1);
	if (PAGE_CACHE_SIZE - (hash_offset - ((hash_offset >> PAGE_CACHE_SHIFT)
			<< PAGE_CACHE_SHIFT)) < inode_i->fbc->hash_len) {
		struct page *pages[2];
		ret = vdfs4_read_comp_pages(&inode_i->vfs_inode, page_idx,
			2, pages, VDFS4_FBASED_READ_M);
		if (ret)
			return ret;

		data = vdfs4_vmap(pages, 2, VM_MAP, PAGE_KERNEL);
		if (data) {
			memcpy(hash, (char *)data + pos,
					inode_i->fbc->hash_len);
			vunmap(data);
		} else
			ret = -ENOMEM;

		for (page_idx = 0; page_idx < 2; page_idx++) {
			mark_page_accessed(pages[page_idx]);
			page_cache_release(pages[page_idx]);
		}
	} else {
		struct page *page;
		ret = vdfs4_read_comp_pages(&inode_i->vfs_inode, page_idx,
			1, &page, VDFS4_FBASED_READ_M);
		if (ret)
			return ret;
		data = kmap_atomic(page);
		memcpy(hash, (char *)data + pos, inode_i->fbc->hash_len);
		kunmap_atomic(data);
		mark_page_accessed(page);
		page_cache_release(page);
	}
	return ret;
}

int vdfs4_check_hash_chunk(struct vdfs4_inode_info *inode_i,
		void *buffer, size_t length, size_t extent_idx)
{
	void *hash_orig = kzalloc(inode_i->fbc->hash_len, GFP_NOFS);
	void *hash_calc = kzalloc(inode_i->fbc->hash_len, GFP_NOFS);
	int ret;

	if (!hash_orig || !hash_calc) {
		ret = -ENOMEM;
		goto exit;
	}

	ret = inode_i->fbc->hash_fn(buffer, length, hash_calc);
	if (ret)
		goto exit;

	ret = vdfs4_get_hash(inode_i, extent_idx, inode_i->fbc->comp_extents_n,
			hash_orig);
	if (ret)
		goto exit;

	if (memcmp(hash_orig, hash_calc, inode_i->fbc->hash_len)) {
		struct vdfs4_sb_info *sbi = inode_i->vfs_inode.i_sb->s_fs_info;
		VDFS4_ERR("File based decompression - hash mismatch"
				" for inode - %lu, file name - %s, chunk - %d",
				inode_i->vfs_inode.i_ino, inode_i->name,
				extent_idx);
		if (inode_i->parent_id != 1)
			print_path_to_object(sbi, inode_i->parent_id);
		ret = -EINVAL;
	}
exit:
	kfree(hash_orig);
	kfree(hash_calc);
	return ret;
}

int vdfs4_check_hash_chunk_no_calc(struct vdfs4_inode_info *inode_i,
		size_t extent_idx, void *hash_calc)
{
	void *hash_orig = kzalloc(inode_i->fbc->hash_len, GFP_NOFS);
	int ret;

	if (!hash_orig) {
		ret = -ENOMEM;
		goto exit;
	}

	ret = vdfs4_get_hash(inode_i, extent_idx, inode_i->fbc->comp_extents_n,
			hash_orig);
	if (ret)
		goto exit;

	if (memcmp(hash_orig, hash_calc, inode_i->fbc->hash_len)) {
		struct vdfs4_sb_info *sbi = inode_i->vfs_inode.i_sb->s_fs_info;
		VDFS4_ERR("File based decompression - hash mismatch"
				" for inode - %lu, file name - %s, chunk - %d",
				inode_i->vfs_inode.i_ino, inode_i->name,
				extent_idx);
		if (inode_i->parent_id != 1)
			print_path_to_object(sbi, inode_i->parent_id);
		ret = -EINVAL;
	}
exit:
	kfree(hash_orig);
	return ret;
}

int vdfs4_check_hash_meta(struct vdfs4_inode_info *inode_i,
		struct vdfs4_comp_file_descr *descr)
{
	void *hash_orig = kzalloc(inode_i->fbc->hash_len, GFP_NOFS);
	void *hash_calc = kzalloc(inode_i->fbc->hash_len, GFP_NOFS);
	int ret;

	if (!hash_orig || !hash_calc) {
		ret = -ENOMEM;
		goto exit;
	}

	ret = inode_i->fbc->hash_fn((unsigned char *)descr,
			(size_t)((char *)&descr->crc -
			(char *)&descr->magic), hash_calc);
	if (ret)
		goto exit;

	ret = vdfs4_get_hash(inode_i, (int)le16_to_cpu(descr->extents_num),
			(int)le16_to_cpu(descr->extents_num), hash_orig);
	if (ret)
		goto exit;

	if (memcmp(hash_orig, hash_calc, inode_i->fbc->hash_len)) {
		VDFS4_ERR("File based decompression - hash metadata"
				"mismatch for inode - %lu, file_name - %s",
				inode_i->vfs_inode.i_ino, inode_i->name);
		print_path_to_object(inode_i->vfs_inode.i_sb->s_fs_info,
				inode_i->parent_id);
		ret = -EINVAL;
	}

exit:
	kfree(hash_orig);
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
