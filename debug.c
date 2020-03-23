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
#else
/* inline void vdfs4_debug_print_sb(struct vdfs4_sb_info *sbi) {} */
#endif

