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

#ifndef VDFS4_CRYPTO_SW_H_
#define VDFS4_CRYPTO_SW_H_

int vdfs4_crypto_decrypt_comp_ext(struct page **src, int src_pages_num,
		int src_offset, int len_bytes, struct page **dst,
		int dst_pages_num, int dst_offset, struct inode* inode,
		int comp_extent_idx);

int vdfs4_crypto_alloc_buffer(struct page ***pages,
		int no_pages, void **virt);

void vdfs4_crypto_free_buffer(struct page **pages,
		int no_pages, void* virt);

void vdfs4_crypto_alloc_workaround(void);

#endif /* VDFS4_CRYPTO_SW_H_ */
