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

#ifndef _VDFS4_DEBUG_H_
#define _VDFS4_DEBUG_H_

#ifdef CONFIG_KPI_SYSTEM_SUPPORT
extern void set_kpi_hw_error(char* prefix, char* msg);
#else
#define set_kpi_hw_error(x,y)
#endif

#include <linux/crc32.h>
#include <linux/console.h>

extern void console_forbid_async_printk(void);
extern void console_permit_async_printk(void);

#define VDFS4_PRE_DUMP()\
	do {\
		console_forbid_async_printk();\
		console_flush_messages();\
		_sep_printk_start();\
	} while (0)

#define VDFS4_POST_DUMP()\
	do {\
		_sep_printk_end();\
		console_permit_async_printk();\
	} while (0)
/**
 * @brief		Memory dump.
 * @param [in]	type	Sets debug type (see VDFS4_DBG_*).
 * @param [in]	buf	Pointer to memory.
 * @param [in]	len	Byte count in the dump.
 * @return	void
 */
#define VDFS4_MDUMP(log_str, buf, len)\
	do {\
		VDFS4_ERR(log_str);\
		VDFS4_PRE_DUMP();\
		print_hex_dump(KERN_ERR, "",\
				DUMP_PREFIX_NONE, 16, 1, buf, len,\
				true);\
		VDFS4_POST_DUMP();\
	} while (0)

/**
 * @brief		Print error message to kernel ring buffer.
 * @param [in]	fmt	Printf format string.
 * @return	void
 */
#define VDFS4_ERR(fmt, ...)\
	do {\
		printk(KERN_ERR "vdfs4-ERROR:%d:%s: " fmt "\n", __LINE__,\
			__func__, ##__VA_ARGS__);\
		set_kpi_hw_error("vdfs4-ERROR:", fmt);\
	} while (0)

#define VDFS4_MOUNT_INFO(fmt, ...)\
do {\
	printk(KERN_INFO "vdfs4-INFO: " fmt, ##__VA_ARGS__);\
} while (0)

/** Enables VDFS4_DEBUG_SB() in super.c */
#define VDFS4_DBG_SB	(1 << 0)

/** Enables VDFS4_DEBUG_INO() in inode.c */
#define VDFS4_DBG_INO	(1 << 1)

/** Enables VDFS4_DEBUG_INO() in fsm.c, fsm_btree.c */
#define VDFS4_DBG_FSM	(1 << 2)

/** Enables VDFS4_DEBUG_SNAPSHOT() in snapshot.c */
#define VDFS4_DBG_SNAPSHOT	(1 << 3)

/** Enables VDFS4_DEBUG_MUTEX() driver-wide */
#define VDFS4_DBG_MUTEX	(1 << 4)

/** Enables VDFS4_DEBUG_TRN() driver-wide. Auxiliary, you can remove this, if
 * there is no more free vdfs4_debug_mask bits */
#define VDFS4_DBG_TRANSACTION (1 << 5)

#define VDFS4_DBG_BTREE (1 << 6)

/* Non-permanent debug */
#define VDFS4_DBG_TMP (1 << 7)


#if defined(CONFIG_VDFS4_DEBUG)
/**
 * @brief		Print debug information.
 * @param [in]	type	Sets debug type (see VDFS4_DBG_*).
 * @param [in]	fmt	Printf format string.
 * @return	void
 */
#define VDFS4_DEBUG(type, fmt, ...)\
	do {\
		if ((type) & vdfs4_debug_mask)\
			printk(KERN_WARNING "vdfs4-DEBUG:%s:%d:%s: " fmt "\n", __FILE__,\
				__LINE__, __func__, ##__VA_ARGS__);\
	} while (0)
#else
#define VDFS4_DEBUG(type, fmt, ...) do {} while (0)
#endif

/**
 * @brief		Print debug information in super.c.
 * @param [in]	fmt	Printf format string.
 * @return	void
 */
#define VDFS4_DEBUG_SB(fmt, ...) VDFS4_DEBUG(VDFS4_DBG_SB, fmt,\
						##__VA_ARGS__)

/**
 * @brief		Print debug information in inode.c.
 * @param [in]	fmt	Printf format string.
 * @return	void
 */
#define VDFS4_DEBUG_INO(fmt, ...) VDFS4_DEBUG(VDFS4_DBG_INO, fmt,\
						##__VA_ARGS__)

/**
 * @brief		Print debug information in fsm.c, fsm_btree.c.
 * @param [in]	fmt	Printf format string.
 * @return	void
 */
#define VDFS4_DEBUG_FSM(fmt, ...) VDFS4_DEBUG(VDFS4_DBG_FSM, fmt,\
						##__VA_ARGS__)

/**
 * @brief		Print debug information in snapshot.c.
 * @param [in]	fmt	Printf format string.
 * @return	void
 */
#define VDFS4_DEBUG_SNAPSHOT(fmt, ...) VDFS4_DEBUG(VDFS4_DBG_SNAPSHOT, fmt,\
						##__VA_ARGS__)

/**
 * @brief		TODO Print debug information in ...
 * @param [in]	fmt	Printf format string.
 * @return	void
 */
#define VDFS4_DEBUG_MUTEX(fmt, ...) VDFS4_DEBUG(VDFS4_DBG_MUTEX, fmt,\
						##__VA_ARGS__)

/**
 * @brief		Print debug information with pid.
 * @param [in]	fmt	Printf format string.
 * @return	void
 */
#define VDFS4_DEBUG_TRN(fmt, ...) VDFS4_DEBUG(VDFS4_DBG_TRANSACTION,\
				"pid=%d " fmt,\
				((struct task_struct *) current)->pid,\
				##__VA_ARGS__)

/**
 * @brief		Print non-permanent debug information.
 * @param [in]	fmt	Printf format string.
 * @return	void
 */
#define VDFS4_DEBUG_TMP(fmt, ...) VDFS4_DEBUG(VDFS4_DBG_TMP,\
				"pid=%d " fmt,\
				((struct task_struct *) current)->pid,\
				##__VA_ARGS__)

#define VDFS4_DEBUG_BTREE(fmt, ...) VDFS4_DEBUG(VDFS4_DBG_BTREE, fmt, \
				##__VA_ARGS__)

extern unsigned int vdfs4_debug_mask;

enum vdfs4_debug_err_k {
	vdfs4_debug_err_none=0x00,
	vdfs4_debug_err_bug,
	vdfs4_debug_err_bug_on,
	vdfs4_debug_err_basetable_load,
	vdfs4_debug_err_bnode_sanity,
	vdfs4_debug_err_bnode_delete,
	vdfs4_debug_err_bnode_merge,
	vdfs4_debug_err_bnode_alloc,
	vdfs4_debug_err_bnode_put,
	vdfs4_debug_err_bnode_destroy,
	vdfs4_debug_err_bnode_dirty,
	vdfs4_debug_err_bnode_read,
	vdfs4_debug_err_bnode_offset,
	vdfs4_debug_err_bitmap_validate,
	vdfs4_debug_err_bitmap_free,
	vdfs4_debug_err_inode_unlink,
	vdfs4_debug_err_inode_write,
	vdfs4_debug_err_inode_evict,
	vdfs4_debug_err_orphan,
};

enum vdfs4_debug_img_verify_k {
	vdfs4_debug_img_verify_no_data,
	vdfs4_debug_img_verify_incompletion,
	vdfs4_debug_img_verify_fail,
	vdfs4_debug_img_verify_ok,
	vdfs4_debug_img_verify_mkfs_on_disk,
};

#define VDFS_IMG_VERIFY_MAGIC (0x0DEFACED)
#define VDFS_IMG_VERIFY_OFFSET (0x1000)	//Last page of area.
#define VDFS_DBG_AREA_OFFSET (0x2000)	//It is fixed
#define VDFS_DBG_AREA_MAGIC "Vdbg"
#define VDFS_DBG_AREA_VER (1)
#define VDFS_DBG_VERIFY_START (0x3aa33aa3)
#define VDFS_DBG_VERIFY_OK (0x5a5a5a5a)
#define VDFS_DBG_VERIFY_FAIL (0xdead4ead)
#define VDFS_DBG_VERIFY_MKFS (0x0a0a0a0a)
#define VDFS_DBG_ERR_MAX_CNT (10)
struct vdfs_err_info
{
	uint16_t idx;
	uint16_t vdfs_err_type_k;
	uint32_t proof[2];
	uint32_t reserved;
	uint8_t note[32];
} __attribute__((packed));

struct vdfs_dbg_info
{
	uint32_t verify_result;
	uint32_t err_count;
}__attribute__((packed));

struct vdfs_dbg_area_map
{
	uint8_t magic[4];
	uint32_t dbgmap_ver;
	uint32_t reserved[6];
	union {
		struct vdfs_dbg_info dbg_info;
		uint32_t for_fixed_size[120];
	} dbg;
	union {
		struct vdfs_err_info err_list[VDFS_DBG_ERR_MAX_CNT];
		uint32_t for_fixed_size[128];
	} err;
} __attribute__((packed));

#if defined(CONFIG_VDFS4_DEBUG)
void vdfs4_debug_print_sb(struct vdfs4_sb_info *sbi);
#else
static inline void vdfs4_debug_print_sb(
		struct vdfs4_sb_info *sbi  __attribute__ ((unused))) {}
#endif

int vdfs4_debug_get_err_count(struct vdfs4_sb_info *sbi, uint32_t *err_count);
int vdfs4_debug_put_err(struct vdfs4_sb_info *sbi,
		uint16_t err_type, uint32_t proof_1, uint32_t proof_2,
		const uint8_t *note);
#if defined(CONFIG_VDFS4_DEBUG)
void vdfs4_debug_print_volume_verification(
		struct vdfs4_sb_info *sbi);
#else
static inline void vdfs4_debug_print_volume_verification(
		struct vdfs4_sb_info *sbi __attribute__ ((unused))) {}
#endif
#endif /* _VDFS4_DEBUG_H_ */
