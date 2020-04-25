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

#ifndef VDFS4_CRYPTO_H_
#define VDFS4_CRYPTO_H_

#include "vdfs4_layout.h"
#include "vdfs4.h"
#ifdef CONFIG_VDFS4_AES_DEBUG_KEY
#include "crypto_debug_key.h"
#endif
#ifdef CONFIG_VDFS4_SW_DECRYPTION
#include "crypto_sw.h"
#endif

#define AES_BLOCK_SIZE	16
#define AES_IVEC_SIZE	16

static inline int vdfs4_crypto_setiv(struct inode* inode, int comp_extent_idx,
		unsigned char *ivec)
{
#ifdef CONFIG_VDFS4_DECRYPTION_SUPPORT
	struct vdfs4_inode_info* inode_i = VDFS4_I(inode);
	u64 aes_counter;
	if(!inode_i->fbc || !ivec)
		return -EINVAL;

	aes_counter = (comp_extent_idx << inode_i->fbc->log_chunk_size) /
			AES_BLOCK_SIZE;

	memcpy(ivec, inode_i->fbc->aes_nonce, VDFS4_AES_NONCE_SIZE);
	memcpy(ivec + VDFS4_AES_NONCE_SIZE, &aes_counter,
			AES_IVEC_SIZE - VDFS4_AES_NONCE_SIZE );

	return 0;
#else
	return -EINVAL;
#endif
}

#ifdef CONFIG_VDFS4_HW_DECRYPTION
static inline int vdfs4_crypto_hw2_prep_req(struct req_hw* req,
		struct inode * inode,
		int comp_extent_idx)
{
	req->enc_type = HW_IOVEC_ENCRYPT_AES128_CTR;
#ifdef CONFIG_VDFS4_AES_DEBUG_KEY_FOR_HW
	req->enc_key = (u8*)aes_debug_key;
#else
	req->enc_key = NULL;
#endif
	return vdfs4_crypto_setiv(inode, comp_extent_idx, req->enc_ivec);
}
#endif

static inline int vdfs4_crypto_only_hw2_possible(void)
{
#ifndef CONFIG_VDFS4_SW_DECRYPTION
	return 1;
#else
	return 0;
#endif
}

#endif /* VDFS4_CRYPTO_H_ */
