#ifndef _VDFS_TRACE_H
#define _VDFS_TRACE_H
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/fs.h>

#define VT_NAME_LEN (16)

/* VT_FAULT_TYPE */
#define FAULT_NON_RA		0
#define FAULT_SYNC_RA		1
#define FAULT_ASYNC_RA		2

/* VT_AOPS_TYPE */
#define AOPS_SYNC_NONE		0
#define AOPS_SYNC		1

enum vdfs_trace_data_type {
	vdfs_trace_data_fops,
	vdfs_trace_data_req,
	vdfs_trace_data_fault,
	vdfs_trace_data_decomp,
	vdfs_trace_data_iops,
	vdfs_trace_data_aops,
	vdfs_trace_data_writeback,
	vdfs_trace_data_fstype,
	vdfs_trace_data_sb,
	vdfs_trace_data_rpmb,
	vdfs_trace_data_pivot,
};

enum vdfs_trace_ops_type {
	/* file_operations type */
	vdfs_trace_fops_dir_iterate,
	vdfs_trace_fops_dir_fsync,
	vdfs_trace_fops_write_iter,
	vdfs_trace_fops_read_iter,
	vdfs_trace_fops_splice_read,
	vdfs_trace_fops_open,
	vdfs_trace_fops_fsync,
	/* req operations */
	vdfs_trace_req_read,
	vdfs_trace_req_read_meta,
	vdfs_trace_req_write,
	vdfs_trace_req_write_meta,
	vdfs_trace_req_discard,
	vdfs_trace_req_flush,
	vdfs_trace_req_etc,
	/* fault operation */
	vdfs_trace_fault,
	/* decompress */
	vdfs_trace_decomp_hw,
	vdfs_trace_decomp_sw,
	/* inode operations */
	vdfs_trace_iops_lookup,
	vdfs_trace_iops_follow_link,
	vdfs_trace_iops_permission,
	vdfs_trace_iops_get_acl,
	vdfs_trace_iops_readlink,
	vdfs_trace_iops_put_link,
	vdfs_trace_iops_create,
	vdfs_trace_iops_link,
	vdfs_trace_iops_unlink,
	vdfs_trace_iops_symlink,
	vdfs_trace_iops_mkdir,
	vdfs_trace_iops_rmdir,
	vdfs_trace_iops_mknod,
	vdfs_trace_iops_rename,
	vdfs_trace_iops_rename2,
	vdfs_trace_iops_setattr,
	vdfs_trace_iops_getattr,
	vdfs_trace_iops_setxattr,
	vdfs_trace_iops_getxattr,
	vdfs_trace_iops_listxattr,
	vdfs_trace_iops_removexattr,
	/* address operations */
	vdfs_trace_aops_readpage,
	vdfs_trace_aops_readpages,
	vdfs_trace_aops_writepage,
	vdfs_trace_aops_writepages,
	vdfs_trace_aops_write_begin,
	vdfs_trace_aops_write_end,
	vdfs_trace_aops_bmap,
	vdfs_trace_aops_direct_io,
	vdfs_trace_aops_tuned_chunk,
	/* writeback */
	vdfs_trace_wb_writeback,
	/* filesystem type */
	vdfs_trace_fstype_mount,
	/* super operations */
	vdfs_trace_sb_put_super,
	vdfs_trace_sb_sync_fs,
	vdfs_trace_sb_remount_fs,
	vdfs_trace_sb_evict_inode,
	/* rpmb operation
	 * - write : write cmd(addr&data[reliable]) ->
	 *			write cmd(request result) ->
	 *			read cmd(read result))
	 * - read  : write cmd(addr) -> read cmd(read data))
	 */
	vdfs_trace_rpmb_write,
	vdfs_trace_rpmb_read,
	/* pivot */
	vdfs_trace_pivot_suspend,
	vdfs_trace_pivot_resume,
};

/* used for universal type access */
struct vdfs_trace_sub_data {
	int partno;
	unsigned long i_ino;
	char filename[VT_NAME_LEN];
	loff_t offset;
	loff_t count;
	unsigned long long type;
};

struct vdfs_trace_fops_data {
	/* partition number (super_block->bd_part->partno) */
	int partno;
	unsigned long i_ino;
	/* filename (filp->f_path.dentry->d_iname) */
	char filename[VT_NAME_LEN];
	loff_t pos;			/* file position, 8byte */
	loff_t count;		/* io requirement size, 8byte */
};

struct vdfs_trace_iops_data {
	int partno;
	unsigned long i_ino;
	char filename[VT_NAME_LEN];
};

struct vdfs_trace_req_data {
	int partno;
	unsigned long i_ino;		/* dummy for padding */
	char filename[VT_NAME_LEN];	/* dummy for padding */
	loff_t sector;
	loff_t size;			/* byte */
	unsigned long long cmd_flags;
};

struct vdfs_trace_fault_data {
	int partno;
	unsigned long i_ino;
	/* filename (f_path.dentry->d_iname) */
	char filename[VT_NAME_LEN];
	loff_t offset;
	loff_t pages;
	unsigned int type;
};

struct vdfs_trace_hw_decomp_data {
	int partno;
	unsigned long i_ino;
	char filename[VT_NAME_LEN];
	loff_t offset;
	loff_t chunk_len;
	unsigned int use_hash;
};

struct vdfs_trace_aops_data {
	int partno;
	unsigned long i_ino;
	char filename[VT_NAME_LEN];
	loff_t pos;
	loff_t len;
	unsigned int is_sync;
};

struct vdfs_trace_fstype_data {
	int partno;			/* dummy for padding */
	unsigned long i_ino;
	char device_name[VT_NAME_LEN];
	loff_t sector;			/* dummy for padding */
	loff_t size;			/* dummy for padding */
};

struct vdfs_trace_sb_data {
	int partno;
	unsigned long i_ino;
	char filename[VT_NAME_LEN];
	loff_t pos;
	loff_t len;
};

struct vdfs_trace_rpmb_data {
	int partno;			/* dummy for padding */
	unsigned long i_ino;		/* dummy for padding */
	char filename[VT_NAME_LEN];	/* dummy for padding */
	loff_t address;
	loff_t blocks;
};

struct vdfs_trace_data {
	unsigned int idx;
	enum vdfs_trace_data_type data_type:16;
	enum vdfs_trace_ops_type ops_type:16;
	union {
		struct vdfs_trace_sub_data target;
		struct vdfs_trace_fops_data fops;
		struct vdfs_trace_req_data req;
		struct vdfs_trace_fault_data fault;
		struct vdfs_trace_hw_decomp_data hw_decomp;
		struct vdfs_trace_iops_data iops;
		struct vdfs_trace_aops_data aops;
		struct vdfs_trace_fstype_data fstype;
		struct vdfs_trace_sb_data sbops;
		struct vdfs_trace_rpmb_data rpmb;
	} data;
	/* common information */
	int pid;			/* thread id (current->pid) */
	int ppid;			/* thread id (current->ppid) */
	char process[VT_NAME_LEN];	/* process name */

	ktime_t start;		/* start time */
	ktime_t end;		/* finish time */
	unsigned int flags;		/* trace information */
	/* for management list */
	struct list_head list;
};
typedef struct vdfs_trace_data  vdfs_trace_data_t;

#ifdef CONFIG_VDFS4_TRACE
/*
 * Common
 */
/* Function */
vdfs_trace_data_t *vdfs_trace_start(void);
void vdfs_trace_finish(vdfs_trace_data_t *trace);
void vdfs_trace_clear_buffer(void);
/* Macro */
#define VT_PREPARE_PARAM(name) vdfs_trace_data_t *name = NULL
#define VT_START(name)	{ (name) = vdfs_trace_start(); }
#define VT_FINISH(name) vdfs_trace_finish(name)

/*
 * file operations
 */
/* Function */
vdfs_trace_data_t *vdfs_trace_fops_start(enum vdfs_trace_ops_type ops_type,
					 struct hd_struct *bd_part,
					 struct inode *inode, struct file *file,
					 loff_t pos, size_t count);
void vdfs_trace_fops_finish(vdfs_trace_data_t *trace,
			    enum vdfs_trace_ops_type ops_type,
			    struct hd_struct *bd_part,
			    struct inode *inode, struct file *file,
			    loff_t pos, size_t count);
/* Macro */
#define VT_FOPS_START(name, op, hd_part, inode, file)			\
	{ (name) = vdfs_trace_fops_start(				\
			(op), (hd_part), (inode), (file), 0, 0); }
#define VT_FOPS_RW_START(name, op, hd_part, inode, file, pos, count)	\
	{ (name) = vdfs_trace_fops_start(				\
			(op), (hd_part), (inode), (file), (pos), (count)); }
#define VT_FOPS_RW_FINISH(name, op, hd_part, inode, file, pos, count)	\
	{ vdfs_trace_fops_finish((name),				\
			(op), (hd_part), (inode), (file), (pos), (count)); }

/*
 * fault
 */
/* Function */
vdfs_trace_data_t *vdfs_trace_fault_start(struct vm_area_struct *vma,
					unsigned long offset,
					unsigned int pages,
					unsigned int type);
/* Macro */
#define VT_FAULT_START(name, vma, offset, pages, type)			\
	{ (name) = vdfs_trace_fault_start((vma), (offset), (pages), (type)); }

/*
 * inode operations
 */
/* Function */
vdfs_trace_data_t *vdfs_trace_iops_start(enum vdfs_trace_ops_type ops_type,
					 struct dentry *dentry);
/* Macro */
#define VT_IOPS_START(name, op, dentry)					\
	{ (name) = vdfs_trace_iops_start((op), (dentry)); }

/*
 * address operations
 */
/* Function */
vdfs_trace_data_t *vdfs_trace_aops_start(enum vdfs_trace_ops_type ops_type,
					 struct inode *inode, struct file *file,
					 loff_t pos, loff_t len,
					 unsigned int is_sync);
/* Macro */
#define VT_AOPS_START(name, ops, inode, file, pos, len, is_sync)	\
	{ (name) = vdfs_trace_aops_start(				\
		(ops), (inode), (file), (pos), (len), (is_sync)); }

/*
 * decompress
 */
/* Function */
void vdfs_trace_decomp_finish(vdfs_trace_data_t *trace,
			      enum vdfs_trace_ops_type type,
			      struct inode *inode,
			      size_t offset, size_t chunk_len,
			      unsigned char use_hash,
			      int is_canceled, int is_uncompr);
/* Macro */
#define VT_DECOMP_FINISH(name, type, inode, offset, chunk_len,		\
			 use_hash, is_canceled, is_uncompr)		\
	{ vdfs_trace_decomp_finish((name), (type), (inode), (offset),	\
				   (chunk_len), (use_hash),		\
				   (is_canceled), (is_uncompr));	\
	}

/*
 * (mmc)request
 */
/* Function */
void vdfs_trace_insert_req(struct request *req);
void vdfs_trace_complete_req(struct request *req, unsigned int nr_bytes);
void vdfs_trace_update_req(struct request *req);

/*
 * writeback
 */
/* Function */
vdfs_trace_data_t *vdfs_trace_writeback_start(void);
/* Macro */
#define VT_WRITE_BACK_START(name)					\
	{ (name) = vdfs_trace_writeback_start(); }

/*
 * filesystem type
 */
/* Function */
vdfs_trace_data_t *vdfs_trace_fstype_start(enum vdfs_trace_ops_type ops,
					   char *device_name);
/* Macro */
#define VT_FSTYPE_START(name, ops, device_name)				\
	{ (name) = vdfs_trace_fstype_start((ops), (device_name)); }

/*
 * superblock operations
 */
/* Function */
vdfs_trace_data_t *vdfs_trace_sb_start(enum vdfs_trace_ops_type ops,
			struct super_block *sb, struct inode *inode,
			loff_t pos, loff_t len);
/* Macro */
#define VT_SBOPS_START(name, ops, sb, inode, pos, len)			\
	{ (name) = vdfs_trace_sb_start(ops, sb, inode, pos, len); }

/*
 * rpmb operations
 */
/* Function */
vdfs_trace_data_t *vdfs_trace_rpmb_start(unsigned int blocks,
					 unsigned char *buf);
/* Macro */
#define VT_RPMB_START(name, blocks, buf)				\
	{ (name) = vdfs_trace_rpmb_start(blocks, buf); }

/*
 * Pivot
 */
void vdfs_trace_insert_pivot(enum vdfs_trace_ops_type pivot);

#else
/* Common */
#define VT_PREPARE_PARAM(name)
#define VT_START(name)
#define VT_FINISH(name)
static inline void vdfs_trace_clear_buffer(void) {};

/* file operations */
#define VT_FOPS_START(name, op, hd_part, inode, filp)
#define VT_FOPS_RW_START(name, op, hd_part, inode, filp, pos, count)
#define VT_FOPS_RW_FINISH(name, op, hd_part, inode, file, pos, count)

/* fault */
#define VT_FAULT_START(name, vma, offset, pages, type)

/* inode operations */
#define VT_IOPS_START(name, op, dentry)

/* address operations */
#define VT_AOPS_START(name, ops, inode, file, pos, len, is_sync)

/* decompress */
#define VT_DECOMP_FINISH(name, type, inode, offset, chunk_len,		\
			 use_hash, is_canceled, is_uncompr)

/* (mmc)request */
static inline void vdfs_trace_insert_req(struct request *req) {};
static inline void vdfs_trace_complete_req(struct request *req,
					   unsigned int nr_bytes) {};
static inline void vdfs_trace_update_req(struct request *req) {};

/*writeback */
#define VT_WRITE_BACK_START(name)

/* filesystem type */
#define VT_FSTYPE_START(name, ops, device_name)

/* superblock operations */
#define VT_SBOPS_START(name, ops, sb, inode, pos, len)

/* rpmb operations */
#define VT_RPMB_START(name, blocks, buf)

/* Pivot */
static inline void vdfs_trace_insert_pivot(enum vdfs_trace_ops_type pivot) {};

#endif /* CONFIG_VDFS4_TRACE */
#endif /* _VDFS_TRACE_H */
