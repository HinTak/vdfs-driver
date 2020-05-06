/*
 * vdfs_trace.c
 *
 * Copyright (C) 2017 Samsung Electronics
 * Created by Huijin Park(huijin.park@samsung.com)
 *
 * 2017-05-22 : Implement tracer for vfs file_operations.
 * NOTE:
 */
#include <linux/sched.h>
#include <linux/mount.h>
#include <linux/list.h>
#include <linux/list_sort.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/uio.h>
#include <linux/blk_types.h>
#include <linux/proc_fs.h>
#include <linux/bio.h>
#include <linux/ctype.h>

#include "vdfs4.h"
#include <linux/vdfs_trace.h>	/* FlashFS : vdfs-trace */

/* #define IO_BANDWITH */

/* output option */
#define OUTPUT_NAME_LEN (VT_NAME_LEN-1)	/* last byte is Null */
#define OUTPUT_OPS_TYPE (5)
#define OUTPUT_OPS_FUNC (11)

/* Trace Option */
#if defined(CONFIG_VDFS4_DEBUG)
# define TRACE_LIMIT 10000  /* max trace data count */
#elif defined(CONFIG_VDFS4_PERF)
# define TRACE_LIMIT 10000  /* max trace data count */
#else
# error "Release Kernel should exclude vdfs_trace..!!"
#endif


/* Trace Control Options */
#define TRACE_OFF	(0)		/* trace enable */
#define TRACE_ON	(1)		/* trace disable */
#define SUPPRESS_OFF	(0)		/* trace suppress off */
#define SUPPRESS_ON	(1)		/* trace suppress on */

struct vdfs_trace_ctrl {
	unsigned char onoff;
	unsigned char suppress;
};
static struct vdfs_trace_ctrl trace_ctrl = {
#if defined(CONFIG_VDFS4_DEBUG)
	.onoff		= TRACE_ON,
	.suppress	= SUPPRESS_ON,
#elif defined(CONFIG_VDFS4_PERF)
	.onoff		= TRACE_OFF,
	.suppress	= SUPPRESS_ON,
#else
#error "Release Kernel should exclude vdfs_trace..!!"
#endif
};

/* For list control about 'vdfs_trace_data_t' */
#define VT_ENTRY(p, name) \
		list_entry((p), vdfs_trace_data_t, name)
#define VT_FIRST_ENTRY(p, name) \
		list_first_entry((p), vdfs_trace_data_t, name)
#define VT_LAST_ENTRY(p, name) \
		list_last_entry((p), vdfs_trace_data_t, name)

/* For trace data flag control */
#define VT_IS_FLAG(x, y) ((x) & ((0x1)<<(y)))
#define VT_SET_FLAG(x, y) { (x) |= ((0x1)<<(y)); }
#define VT_CLEAR_FLAG(x, y) { (x) &= (~((0x1)<<(y))); }
enum vt_trace_flags_type {
	/* 00 */ vt_flag_sublist,	/* 0:resp item, 1:sublist item */
	/* 01 */ vt_flag_sublist_last,	/* 1: the last data of sublist */
	/* 02 */ vt_flag_canceled,	/* 1: canceled record */
};

/* Static Variables */
static vdfs_trace_data_t _trace_data[TRACE_LIMIT];
static unsigned int traced_data_cnt;
static LIST_HEAD(_free_list);
static LIST_HEAD(_traced_list);
static LIST_HEAD(_tracing_start_list);
static LIST_HEAD(_tracing_finish_list);
static DEFINE_SPINLOCK(vdfs_trace_lock);
static DEFINE_SPINLOCK(tracing_lock);
static DECLARE_WAIT_QUEUE_HEAD(vdfs_trace_wait);

static vdfs_trace_data_t *alloc_trace_data(void);
static int arrange_traced_data(vdfs_trace_data_t *data);
static void start_trace_data(vdfs_trace_data_t *data);
static void finish_trace_data(vdfs_trace_data_t *data);

static vdfs_trace_data_t *alloc_trace_data(void)
{
	unsigned long flag;
	static unsigned int used_cnt;
	vdfs_trace_data_t *rtn = NULL;

	if (trace_ctrl.onoff == TRACE_OFF)
		return NULL;
	spin_lock_irqsave(&vdfs_trace_lock, flag);
	if (used_cnt < TRACE_LIMIT) {
		/* alloc from _trace_data. */
		rtn = &(_trace_data[used_cnt++]);
	} else {
		/*
			if free buffer is empty, move buffer from traced
			to free buffer
		*/
		if (list_empty(&_free_list) && !list_empty(&_traced_list)) {
			vdfs_trace_data_t *trace;

			trace = VT_FIRST_ENTRY(&_traced_list, list);
			do {
				list_move(&trace->list, &_free_list);
				if (list_empty(&_traced_list))
					break;
				trace = VT_FIRST_ENTRY(&_traced_list, list);
			} while (VT_IS_FLAG(trace->flags, vt_flag_sublist));
		}
		/* alloc from _free_list */
		if (!list_empty(&_free_list)) {
			rtn = list_first_entry_or_null(&_free_list,
					vdfs_trace_data_t, list);
			if (rtn)
				list_del(&rtn->list);	/* delete from free list */
		} else
			rtn = NULL;
	}
	spin_unlock_irqrestore(&vdfs_trace_lock, flag);
	if (rtn)
		memset(rtn, 0x0, sizeof(vdfs_trace_data_t));

	return rtn;
}

static void free_trace_data(vdfs_trace_data_t *trace)
{
	unsigned long flag;

	/* push into free list */
	spin_lock_irqsave(&vdfs_trace_lock, flag);
	list_add_tail(&trace->list, &_free_list);
	spin_unlock_irqrestore(&vdfs_trace_lock, flag);
}

static void start_trace_data(vdfs_trace_data_t *trace)
{
	unsigned long flag;

	trace->pid = task_pid_nr(current);
	trace->ppid = task_ppid_nr(current);

	memcpy(trace->process, current->comm, sizeof(trace->process)-1);
	spin_lock_irqsave(&tracing_lock, flag);
	if (current->vt_rep_idx == 0) {
		trace->idx = traced_data_cnt;
		/*
			If mmc request is resp data,
			do not save idx into task struct.
		*/
		if (trace->data_type != vdfs_trace_data_req &&
			trace->ops_type != vdfs_trace_decomp_hw) {
			current->vt_rep_idx = traced_data_cnt;
		}
		traced_data_cnt++;
	} else {
		VT_SET_FLAG(trace->flags, vt_flag_sublist);
		trace->idx = current->vt_rep_idx;
	}
	list_add_tail(&trace->list, &_tracing_start_list);
	spin_unlock_irqrestore(&tracing_lock, flag);
	trace->start.tv64 = sched_clock();
}

static void finish_trace_data(vdfs_trace_data_t *trace)
{
	unsigned long flag;
	struct list_head *p;
	int is_tracing = 0;

	if (!trace)
		return;
	trace->end.tv64 = sched_clock();
	if (!VT_IS_FLAG(trace->flags, vt_flag_sublist))
		current->vt_rep_idx = 0;	/* reset index for resp trace data */

	spin_lock_irqsave(&tracing_lock, flag);
	list_del(&trace->list);
	list_add_tail(&trace->list, &_tracing_finish_list);

	/* check finish io or not */
	list_for_each(p, &_tracing_start_list) {
		vdfs_trace_data_t *entry = VT_ENTRY(p, list);

		if (trace->pid == entry->pid && trace->idx == entry->idx) {
			is_tracing = 1;
			break;
		}
	}
	spin_unlock_irqrestore(&tracing_lock, flag);
	if (!is_tracing)
		arrange_traced_data(trace);
}

static int traced_data_cmp(void *priv, struct list_head *a,
			   struct list_head *b)
{
	if (a != NULL && b != NULL) {
		vdfs_trace_data_t *_a, *_b;

		_a = VT_ENTRY(a, list);
		_b = VT_ENTRY(b, list);
		if (_a->start.tv64 < _b->start.tv64)
			return 0;
		else
			return 1;
	}
	return 1;
}

static inline int is_mmc_trace_data(vdfs_trace_data_t *entry)
{
	if (entry->ops_type == vdfs_trace_decomp_hw
		|| entry->data_type == vdfs_trace_data_req
		|| entry->data_type == vdfs_trace_data_rpmb)
		return 1;
	else
		return 0;
}

static inline int is_write_trace_data(vdfs_trace_data_t *entry)
{
	if (entry->ops_type == vdfs_trace_fops_write_iter
	    || entry->ops_type == vdfs_trace_aops_writepage
	    || entry->ops_type == vdfs_trace_aops_writepages)
		return 1;
	else
		return 0;
}

static int arrange_traced_data(vdfs_trace_data_t *data)
{
	unsigned char is_tracing = 0;
	unsigned long flag;
	vdfs_trace_data_t *last_entry;
	LIST_HEAD(buffer);
	struct list_head *pos, *n;

	/* extract tracing data from tracing_finish_list */
	spin_lock_irqsave(&tracing_lock, flag);
	list_for_each_safe(pos, n, &_tracing_finish_list) {
		vdfs_trace_data_t *entry = VT_ENTRY(pos, list);

		if (entry->pid == data->pid && entry->idx == data->idx) {
			list_del(&entry->list);
			list_add(&entry->list, &buffer);
			if (trace_ctrl.suppress == SUPPRESS_OFF
			    || entry->data_type == vdfs_trace_data_pivot
			    || is_mmc_trace_data(entry)
			    || is_write_trace_data(entry))
				is_tracing = 1;
		}
	}
	spin_unlock_irqrestore(&tracing_lock, flag);

	/* sort extracted tracing data (order by start time) */
	list_sort(NULL, &buffer, traced_data_cmp);
	last_entry = VT_LAST_ENTRY(&buffer, list);
	if (VT_IS_FLAG(last_entry->flags, vt_flag_sublist))
		VT_SET_FLAG(last_entry->flags, vt_flag_sublist_last);

	/* push tracing data into traced list */
	spin_lock_irqsave(&vdfs_trace_lock, flag);
	if (!is_tracing)
		list_splice_tail(&buffer, &_free_list);
	else
		list_splice_tail(&buffer, &_traced_list);
	spin_unlock_irqrestore(&vdfs_trace_lock, flag);
	wake_up_interruptible(&vdfs_trace_wait);
	return 0;
}

/*
 * Common Function
 */
inline vdfs_trace_data_t *vdfs_trace_start(void)
{
	vdfs_trace_data_t *trace = alloc_trace_data();

	if (trace)
		start_trace_data(trace);
	return trace;
}

inline void vdfs_trace_finish(vdfs_trace_data_t *trace)
{
	if (trace)
		finish_trace_data(trace);
}

static inline void fill_trace_data(vdfs_trace_data_t *trace,
			enum vdfs_trace_data_type data_type,
			enum vdfs_trace_ops_type ops_type,
			int partno,
			unsigned long i_ino,
			char *filename,
			loff_t offset,
			loff_t count,
			unsigned long long type)
{
	struct vdfs_trace_sub_data *target = &(trace->data.target);

	trace->data_type = data_type;
	trace->ops_type  = ops_type;
	target->partno = partno;
	target->i_ino  = i_ino;
	if (filename)
		memcpy(target->filename, filename, sizeof(target->filename) - 1);
	target->offset = offset;
	target->count   = count;
	target->type    = type;
}

static void fill_fops_trace_data(vdfs_trace_data_t *trace,
			enum vdfs_trace_ops_type ops_type,
			struct hd_struct *bd_part,
			struct inode *inode, struct file *file,
			loff_t pos, size_t count)
{
	if (inode && VDFS4_I(inode)->name)
		fill_trace_data(trace, vdfs_trace_data_fops, ops_type,
				bd_part->partno, inode->i_ino,
				VDFS4_I(inode)->name, pos, count, 0);
	else if (inode && file && file->f_path.dentry)
		fill_trace_data(trace, vdfs_trace_data_fops, ops_type,
				bd_part->partno, inode->i_ino,
				file->f_path.dentry->d_iname, pos, count, 0);
	else
		fill_trace_data(trace, vdfs_trace_data_fops, ops_type,
				bd_part->partno, 0,
				'\0', pos, count, 0);
}

/**
 * vdfs_trace_fops_start - start file operations trace
 * @ops_type:  file operation type
 * @bd_part :  target partition(for partition number)
 * @inode   :  file information(for filename)
 * @file    :  sub file information(for filename)
 * @pos     :  operation position
 * @count   :  operation length
 *
 */
vdfs_trace_data_t *vdfs_trace_fops_start(
			enum vdfs_trace_ops_type ops_type,
			struct hd_struct *bd_part,
			struct inode *inode, struct file *file,
			loff_t pos, size_t count)
{
	vdfs_trace_data_t *trace = alloc_trace_data();
	if (!trace)
		return NULL;
	fill_fops_trace_data(trace, ops_type, bd_part, inode, file, pos, count);
	start_trace_data(trace);
	return trace;
}

/**
 * vdfs_trace_fops_finish - finish file operations trace
 * @trace   : trace data
 * @ops_type:  file operation type
 * @bd_part :  target partition(for partition number)
 * @inode   :  file information(for filename)
 * @file    :  sub file information(for filename)
 * @pos     :  operation position
 * @count   :  operation length
 *
 */
void vdfs_trace_fops_finish(vdfs_trace_data_t *trace,
			enum vdfs_trace_ops_type ops_type,
			struct hd_struct *bd_part,
			struct inode *inode, struct file *file,
			loff_t pos, size_t count)
{
	if (!trace)
		return;
	fill_fops_trace_data(trace, ops_type, bd_part, inode, file, pos, count);
	finish_trace_data(trace);
}

/*
 * mmc request
 */
#define REQ_MAGIC (0x76647472)/* vdtr */
static inline int _is_mmc_dev(struct block_device *bi_bdev)
{
	const char *mmc_dev_name = "mmcblk";

	return !(memcmp(mmc_dev_name,
		bi_bdev->bd_disk->disk_name, 6));
}

enum vdfs_trace_ops_type _get_mmc_req_ops_type(u64 cmd_flags)
{
	/* refer 'enum rq_flag_bits' */
	if (cmd_flags & REQ_DISCARD)
		return vdfs_trace_req_discard;
	else if ((cmd_flags & (REQ_WRITE|REQ_META)) == (REQ_WRITE|REQ_META))
		return vdfs_trace_req_write_meta;
	else if (cmd_flags & REQ_WRITE)
		return vdfs_trace_req_write;
	else if (cmd_flags & REQ_FLUSH)
		return vdfs_trace_req_flush;
	else if (cmd_flags & REQ_META)
		return vdfs_trace_req_read_meta;
	else if (!(cmd_flags & REQ_WRITE))
		return vdfs_trace_req_read;
	else
		return vdfs_trace_req_etc;
}

/**
 * vdfs_trace_insert_rq - start mmc request trace
 * @req:	request of mmc
 *
 */
void vdfs_trace_insert_req(struct request *req)
{
	vdfs_trace_data_t *trace;

	req->vdfs_trace_magic = 0x0;
	req->vdfs_trace_data = NULL;

	if (!req->rq_disk || !req->part)
		return;
	if (memcmp(req->rq_disk->disk_name, "mmc", 3))
		return;

	trace = alloc_trace_data();

	if (trace) {
		fill_trace_data(trace, vdfs_trace_data_req,
				_get_mmc_req_ops_type(req->cmd_flags),
				req->part->partno, 0, "",
				req->__sector, 0, req->cmd_flags);

		start_trace_data(trace);
		req->vdfs_trace_magic = REQ_MAGIC;
		req->vdfs_trace_data = trace;
	}
}

/**
 * vdfs_trace_update_req - update req start time
 * @req : 	request of mmc
 */
void vdfs_trace_update_req(struct request *req)
{
	vdfs_trace_data_t *trace;

	if (!req)
		return;
	if (!req->vdfs_trace_data)
		return;
	if (req->vdfs_trace_magic != REQ_MAGIC)
		return;
	trace = (vdfs_trace_data_t *)req->vdfs_trace_data;
	trace->start.tv64 = sched_clock();
}

/**
 * vdfs_trace_complete_req - finish mmc request trace
 * @req:	request of mmc
 * @nr_bytes	written size(bytes_xfered)
 */
void vdfs_trace_complete_req(struct request *req, unsigned int nr_bytes)
{
	vdfs_trace_data_t *trace;

	trace = (vdfs_trace_data_t *)req->vdfs_trace_data;
	if (!trace)
		return;
	if (req->vdfs_trace_magic != REQ_MAGIC)
		return;

	trace->data.req.size = nr_bytes;
	finish_trace_data(trace);

	/* clear */
	req->vdfs_trace_magic = 0x0;
	req->vdfs_trace_data = NULL;
}

/**
 * vdfs_trace_fault_start - start fault trace
 * @vma:	vm area(for file information)
 * @offset:	fault address
 * @pages:	read ahead size from page fault
 * @type:	if 0, async read-ahead
 *		if 1, sync  read-ahead
 *		if 2, non   read-ahead operation.
 *
 */
vdfs_trace_data_t *vdfs_trace_fault_start(struct vm_area_struct *vma,
		unsigned long offset, unsigned int pages, unsigned int type)
{
	vdfs_trace_data_t *trace;
	struct block_device *s_bdev;
	struct dentry *dentry;
	struct inode *inode;

	if (!vma->vm_file
		|| !vma->vm_file->f_path.mnt->mnt_sb
		|| !vma->vm_file->f_path.mnt->mnt_sb->s_bdev)
		return NULL;
	s_bdev = vma->vm_file->f_path.mnt->mnt_sb->s_bdev;
	dentry = vma->vm_file->f_path.dentry;
	if (!_is_mmc_dev(s_bdev))
		return NULL;

	trace = alloc_trace_data();

	if (trace) {
		struct inode *inode = dentry->d_inode;
		if (inode && is_vdfs4(inode->i_sb) && VDFS4_I(inode)->name)
			fill_trace_data(trace, vdfs_trace_data_fault,
					vdfs_trace_fault,
					s_bdev->bd_part->partno,
					inode->i_ino, VDFS4_I(inode)->name,
					offset, pages, type);
		else
			fill_trace_data(trace, vdfs_trace_data_fault,
					vdfs_trace_fault,
					s_bdev->bd_part->partno, 0, dentry->d_iname,
					offset, pages, type);

		start_trace_data(trace);
	}
	return trace;
}

/**
 * vdfs_trace_decomp_finish - finish hw decompress trace
 * @type:		type of decompress requirement(hw or sw)
 * @inode:		inode pointer
 * @offset:		offset in file data
 * @chunk_len:	read size
 * @use_hash:	if 1, it calculated hash and compared with hash table.
 * @is_cancled:	if 1, cancel trace data.
 * @is_uncompr: if 1, the chunk is not compressed data
 */
void vdfs_trace_decomp_finish(vdfs_trace_data_t *trace,
			      enum vdfs_trace_ops_type type,
			      struct inode *inode,
			      size_t offset, size_t chunk_len,
			      unsigned char use_hash,
			      int is_cancled, int is_uncompr)
{
	if (!trace)
		return;
	if (is_cancled||is_uncompr) {
		VT_SET_FLAG(trace->flags, vt_flag_canceled);
	} else {
		if (VDFS4_I(inode)->name)
			fill_trace_data(trace, vdfs_trace_data_decomp,
					type,
					inode->i_sb->s_bdev->bd_part->partno,
					inode->i_ino, VDFS4_I(inode)->name,
					offset, chunk_len, use_hash);
		else
			fill_trace_data(trace, vdfs_trace_data_decomp,
					type,
					inode->i_sb->s_bdev->bd_part->partno,
					0, "",
					offset, chunk_len, use_hash);
	}
	finish_trace_data(trace);
}

/**
 * vdfs_trace_iops_start - start inode operation trace
 * @ops_type:	operation type
 * @dentry:  dentry for partition number and filename
 *
 */
vdfs_trace_data_t *vdfs_trace_iops_start(enum vdfs_trace_ops_type ops_type,
					 struct dentry *dentry)
{
	vdfs_trace_data_t *trace = alloc_trace_data();

	if (trace) {
		if (dentry && dentry->d_inode) {
			struct inode *inode = dentry->d_inode;

			fill_trace_data(trace, vdfs_trace_data_iops, ops_type,
					dentry->d_sb->s_bdev->bd_part->partno,
					inode->i_ino, VDFS4_I(inode)->name,
					0, 0, 0);
		} else if (dentry)
			fill_trace_data(trace, vdfs_trace_data_iops, ops_type,
					dentry->d_sb->s_bdev->bd_part->partno,
					0, dentry->d_iname,
					0, 0, 0);

		else
			fill_trace_data(trace, vdfs_trace_data_iops, ops_type,
					0, 0, "", 0, 0, 0);

		start_trace_data(trace);
	}
	return trace;
}

/**
 * vdfs_trace_aops_start - start address operation trace
 * @ops_type:	operation type
 * @inode:  inode for partition number
 * @file:  file for filename
 * @pos:  operation position
 * @len:  operation length
 *
 */
vdfs_trace_data_t *vdfs_trace_aops_start(
			enum vdfs_trace_ops_type ops_type,
			struct inode *inode, struct file *file,
			loff_t pos, loff_t len, unsigned int is_sync)
{
	loff_t data_pos, data_len;
	struct vdfs4_inode_info *i_info = VDFS4_I(inode);
	vdfs_trace_data_t *trace = alloc_trace_data();

	if (trace) {
		switch(ops_type) {
		case vdfs_trace_aops_writepages:
		case vdfs_trace_aops_writepage:
			data_pos = 0;
			data_len = i_info->write_size;
			i_info->write_size = 0;		/* reset */
			if (data_len == 0) {
				/* ignore nomeaning trace data */
				free_trace_data(trace);
				return NULL;
			}
			break;
		case vdfs_trace_aops_write_begin:
			i_info->write_size += len;	/* accrue write size */
		default:
			data_pos = pos;
			data_len = len;
			break;
		}

		if (inode && VDFS4_I(inode)->name)
			fill_trace_data(trace, vdfs_trace_data_aops,
					ops_type,
					inode->i_sb->s_bdev->bd_part->partno,
					inode->i_ino, VDFS4_I(inode)->name,
					data_pos, data_len, is_sync);
		else
			fill_trace_data(trace, vdfs_trace_data_aops,
					ops_type,
					0, 0, "",
					data_pos, data_len, is_sync);

		start_trace_data(trace);
	}
	return trace;
}

/**
 * vdfs_trace_writeback_start - start writeback trace
 *
 */
vdfs_trace_data_t *vdfs_trace_writeback_start(void)
{
	vdfs_trace_data_t *trace;

	trace = alloc_trace_data();
	if (trace) {
		trace->data_type = vdfs_trace_data_writeback;
		trace->ops_type = vdfs_trace_wb_writeback;
		start_trace_data(trace);
	}
	return trace;
}

vdfs_trace_data_t *vdfs_trace_fstype_start(enum vdfs_trace_ops_type ops,
					   char *device_name)
{
	vdfs_trace_data_t *trace = alloc_trace_data();

	if (trace) {
		fill_trace_data(trace, vdfs_trace_data_fstype,
				ops, 0, 0, device_name, 0, 0, 0);
		start_trace_data(trace);
	}
	return trace;
}

vdfs_trace_data_t *vdfs_trace_sb_start(enum vdfs_trace_ops_type ops,
				struct super_block *sb, struct inode *inode,
				loff_t pos, loff_t len)
{
	vdfs_trace_data_t *trace = alloc_trace_data();

	if (trace) {
		if (inode && VDFS4_I(inode)->name)
			fill_trace_data(trace, vdfs_trace_data_sb,
					ops, sb->s_bdev->bd_part->partno,
					inode->i_ino, VDFS4_I(inode)->name,
					pos, len, 0);
		else
			fill_trace_data(trace, vdfs_trace_data_sb,
					ops, sb->s_bdev->bd_part->partno,
					0, "",
					pos, len, 0);

		start_trace_data(trace);
	}
	return trace;
}

vdfs_trace_data_t *vdfs_trace_rpmb_start(unsigned int blocks,
					 unsigned char *buf)
{
	static short read_address;
	static unsigned char reading;
	unsigned short *req = (uint16_t *)(buf + 510);
	vdfs_trace_data_t *trace = NULL;

	if (reading) {
		trace = alloc_trace_data();

		if (trace == NULL)
			return NULL;

		fill_trace_data(trace, vdfs_trace_data_rpmb,
				vdfs_trace_rpmb_read, 0, 0, "",
				read_address, blocks, 0);
		reading = 0;
		start_trace_data(trace);
	} else if (buf && be16_to_cpu(*req) == 0x3) { /* MMC_RPMB_WRITE_DATA */
		trace = alloc_trace_data();
		if (trace == NULL)
			return NULL;

		fill_trace_data(trace, vdfs_trace_data_rpmb,
				vdfs_trace_rpmb_write, 0, 0, "",
				be16_to_cpu(*((uint16_t *)(buf+504))), blocks, 0);

		start_trace_data(trace);
	} else if (buf && be16_to_cpu(*req) == 0x4) { /* MMC_RPMB_READ_DATA */
		read_address = be16_to_cpu(*((uint16_t *)(buf+504)));
		reading = 1;
	}
	return trace;
}

void vdfs_trace_insert_pivot(enum vdfs_trace_ops_type pivot)
{
	vdfs_trace_data_t *trace = alloc_trace_data();
	if (trace) {
		trace->data_type = vdfs_trace_data_pivot;
		trace->ops_type = pivot;
		start_trace_data(trace);
		finish_trace_data(trace);
	}
}

static const char *_data_type_to_str(enum vdfs_trace_data_type data_type)
{
	switch (data_type) {
	case vdfs_trace_data_fops:
		return "f_ops";
	case vdfs_trace_data_req:
		return "req";
	case vdfs_trace_data_fault:
		return "fault";
	case vdfs_trace_data_decomp:
		return "decmp";
	case vdfs_trace_data_iops:
		return "i_ops";
	case vdfs_trace_data_aops:
		return "a_ops";
	case vdfs_trace_data_writeback:
		return "wback";
	case vdfs_trace_data_fstype:
		return "fstyp";
	case vdfs_trace_data_sb:
		return "super";
	case vdfs_trace_data_rpmb:
		return "RPMB";
	case vdfs_trace_data_pivot:
		return "pivot";
	default:
		return "NONE";
	}
}

static const char *_ops_type_to_str(enum vdfs_trace_ops_type ops_type)
{
	switch (ops_type) {
	/* file operations */
	case vdfs_trace_fops_dir_iterate:
		return "iterate";
	case vdfs_trace_fops_dir_fsync:
		return "dir_sync";
	case vdfs_trace_fops_write_iter:
		return "write_iter";
	case vdfs_trace_fops_read_iter:
		return "read_iter";
	case vdfs_trace_fops_splice_read:
		return "splice_read";
	case vdfs_trace_fops_open:
		return "open";
	case vdfs_trace_fops_fsync:
		return "file_fsync";
	/* req operations */
	case vdfs_trace_req_read:
		return "read";
	case vdfs_trace_req_read_meta:
		return "meta_read";
	case vdfs_trace_req_write:
		return "write";
	case vdfs_trace_req_write_meta:
		return "meta_write";
	case vdfs_trace_req_discard:
		return "discard";
	case vdfs_trace_req_flush:
		return "flush";
	case vdfs_trace_req_etc:
		return "etc";
	/* fault operation */
	case vdfs_trace_fault:
		return "fault";
	/* hw_decompress */
	case vdfs_trace_decomp_hw:
		return "hw_decomp";
	case vdfs_trace_decomp_sw:
		return "sw_decomp";
	/* inode operations */
	case vdfs_trace_iops_lookup:
		return "lookup";
	case vdfs_trace_iops_get_acl:
		return "get_acl";
	case vdfs_trace_iops_create:
		return "create";
	case vdfs_trace_iops_link:
		return "link";
	case vdfs_trace_iops_unlink:
		return "unlink";
	case vdfs_trace_iops_symlink:
		return "symlink";
	case vdfs_trace_iops_mkdir:
		return "mkdir";
	case vdfs_trace_iops_rmdir:
		return "rmdir";
	case vdfs_trace_iops_mknod:
		return "mknod";
	case vdfs_trace_iops_rename:
		return "rename";
	case vdfs_trace_iops_setattr:
		return "setattr";
	case vdfs_trace_iops_setxattr:
		return "setxattr";
	case vdfs_trace_iops_getxattr:
		return "getxattr";
	case vdfs_trace_iops_listxattr:
		return "listxattr";
	case vdfs_trace_iops_removexattr:
		return "rmxattr";
#if 0
	/* no allocated function for vdfs */
	case vdfs_trace_iops_permission:
		return "permit";
	case vdfs_trace_iops_rename2:
		return "rename2";
	case vdfs_trace_iops_getattr:
		return "getattr";
	/* use kernel general function (not vdfs own)*/
	case vdfs_trace_iops_follow_link:
		return "fol_link";
	case vdfs_trace_iops_readlink:
		return "readlink";
	case vdfs_trace_iops_put_link:
		return "putlink";
#endif
	/* address operations */
	case vdfs_trace_aops_readpage:
		return "readpage";
	case vdfs_trace_aops_readpages:
		return "readpages";
	case vdfs_trace_aops_writepage:
		return "write_page";
	case vdfs_trace_aops_writepages:
		return "write_pages";
	case vdfs_trace_aops_write_begin:
		return "write_begin";
	case vdfs_trace_aops_write_end:
		return "write_end";
	case vdfs_trace_aops_bmap:
		return "bmap";
	case vdfs_trace_aops_direct_io:
		return "direct_io";
	case vdfs_trace_aops_tuned_chunk:
		return "tuned_chunk";
	/* write back */
	case vdfs_trace_wb_writeback:
		return "writeback";
	/* filesystem type */
	case vdfs_trace_fstype_mount:
		return "mount";
	/* super operations */
	case vdfs_trace_sb_put_super:
		return "put_super";
	case vdfs_trace_sb_sync_fs:
		return "sync_fs";
	case vdfs_trace_sb_remount_fs:
		return "remount_fs";
	case vdfs_trace_sb_evict_inode:
		return "evict_inode";
	/* rpmb operations */
	case vdfs_trace_rpmb_write:
		return "write";
	case vdfs_trace_rpmb_read:
		return "read";
	/* pivot */
	case vdfs_trace_pivot_suspend:
		return "suspend";
	case vdfs_trace_pivot_resume:
		return "resume";
	default:
		return "invalid";
	}
}

static const char _ops_func_to_char(enum vdfs_trace_ops_type ops_type,
				 int sublist)
{
	switch (ops_type) {
	case vdfs_trace_fault:
		return 'F';
	case vdfs_trace_req_read:
	case vdfs_trace_req_read_meta:
		if (!sublist)
			return 'L';
		/* fall through */
	case vdfs_trace_fops_dir_iterate:
	case vdfs_trace_fops_read_iter:
	case vdfs_trace_fops_splice_read:
	case vdfs_trace_decomp_hw:
	case vdfs_trace_decomp_sw:
	case vdfs_trace_iops_lookup:
	case vdfs_trace_iops_get_acl:
	case vdfs_trace_iops_getxattr:
	case vdfs_trace_iops_listxattr:
	case vdfs_trace_aops_tuned_chunk:
	case vdfs_trace_aops_readpage:
	case vdfs_trace_aops_readpages:
	case vdfs_trace_aops_bmap:
	case vdfs_trace_rpmb_read:
		return 'R';
	case vdfs_trace_fops_write_iter:
	case vdfs_trace_req_write:
	case vdfs_trace_req_write_meta:
	case vdfs_trace_iops_create:
	case vdfs_trace_iops_link:
	case vdfs_trace_iops_unlink:
	case vdfs_trace_iops_symlink:
	case vdfs_trace_iops_mkdir:
	case vdfs_trace_iops_rmdir:
	case vdfs_trace_iops_mknod:
	case vdfs_trace_iops_rename:
	case vdfs_trace_iops_setattr:
	case vdfs_trace_iops_setxattr:
	case vdfs_trace_iops_removexattr:
	case vdfs_trace_aops_writepage:
	case vdfs_trace_aops_writepages:
	case vdfs_trace_aops_write_begin:
	case vdfs_trace_aops_write_end:
	case vdfs_trace_wb_writeback:
	case vdfs_trace_sb_evict_inode:
	case vdfs_trace_rpmb_write:
		return 'W';
	case vdfs_trace_fops_dir_fsync:
	case vdfs_trace_fops_fsync:
	case vdfs_trace_req_flush:
	case vdfs_trace_sb_sync_fs:
		return 'S';
	case vdfs_trace_fops_open:
	case vdfs_trace_req_discard:
	case vdfs_trace_req_etc:
	case vdfs_trace_aops_direct_io:
	case vdfs_trace_fstype_mount:
	case vdfs_trace_sb_remount_fs:
	case vdfs_trace_sb_put_super:
		return 'E';
	default:
		return 'I';
	}
}

static int _trace_data_to_str(char *buffer,
			      int size,
			      vdfs_trace_data_t *trace)
{
	unsigned int us;
	int len = 0;
	int partno = 0;
	char *file_name = NULL;
	loff_t offset, count;
	unsigned int countK = 0, countB = 0;
	char type = 'F';	/* B(block), F(file),C(compressed : file base) */
	int sublist = true;

	us = ktime_to_us(trace->start);
	if (VT_IS_FLAG(trace->flags, vt_flag_sublist_last)) {
		len = snprintf(buffer, size - 1, "       `-");
	} else if (VT_IS_FLAG(trace->flags, vt_flag_sublist)) {
		len = snprintf(buffer, size - 1, "       |-");
	} else {
		len = snprintf(buffer, size - 1, "[%7u]", trace->idx);
		sublist = false;
	}

	/* [starttime(s):duration(us)][ops_type:ops_func] */
	len += snprintf(buffer + len, size - len - 1,
			"[%5lld.%06ld:%7lldus][%*s(%4d/%4d)][%*s: %-*s][%c]",
			ktime_divns(trace->start, NSEC_PER_SEC),
			us % USEC_PER_SEC,
			ktime_us_delta(trace->end, trace->start),
			OUTPUT_NAME_LEN, trace->process, trace->pid, trace->ppid,
			OUTPUT_OPS_TYPE, _data_type_to_str(trace->data_type),
			OUTPUT_OPS_FUNC, _ops_type_to_str(trace->ops_type),
			_ops_func_to_char(trace->ops_type, sublist));

	/* [ops_func + ] */
	switch (trace->data_type) {
	case vdfs_trace_data_fault:
	case vdfs_trace_data_aops:
		if (trace->data.fault.type == 0)
			len += snprintf(buffer + len, size - len - 1, "[N]");
		else if (trace->data.fault.type == 1)
			len += snprintf(buffer + len, size - len - 1, "[S]");
		else if (trace->data.fault.type == 2)
			len += snprintf(buffer + len, size - len - 1, "[A]");
		break;
	case vdfs_trace_data_decomp:
		len += snprintf(buffer + len, size - len - 1,
				"[%c]",
				((trace->data.hw_decomp.use_hash == 1) ?
				'H' : 'N'));
		break;
	default:	/* fops, req, iops, fstype, rpmb, writeback, pivot */
		len += snprintf(buffer + len, size - len - 1, "[-]");
		break;
	}

	/* [partno:filename:i_ino] */
	switch (trace->data_type) {
	case vdfs_trace_data_fops:
	case vdfs_trace_data_fault:
	case vdfs_trace_data_iops:
	case vdfs_trace_data_aops:
	case vdfs_trace_data_sb:
	case vdfs_trace_data_decomp:
	case vdfs_trace_data_req:
	case vdfs_trace_data_writeback:
		if (trace->data.target.filename[0] == '\0') {
			len += snprintf(buffer + len, size - len - 1,
				"[%2d:%-*s:%5s]",
				trace->data.target.partno,
				OUTPUT_NAME_LEN,
				!sublist ? _ops_type_to_str(trace->ops_type) :
				"       -    ",
				!sublist ? "99999" :
				"  -  ");
			break;
		}
		len += snprintf(buffer + len, size - len - 1,
				"[%2d:%-*s:%5ld]",
				trace->data.target.partno,
				OUTPUT_NAME_LEN, trace->data.target.filename,
				trace->data.target.i_ino);
		break;
	case vdfs_trace_data_rpmb:
		len += snprintf(buffer + len, size - len - 1,
				"[96:RPMB           :  -  ]");
		break;
	case vdfs_trace_data_fstype:
		len += snprintf(buffer + len, size - len - 1,
				"[%2d:%-*s:  -  ]", 0,
				OUTPUT_NAME_LEN,
				trace->data.fstype.device_name);
		break;
	default:
		break;
	}

	offset = trace->data.target.offset;
	count  = trace->data.target.count;

	/* [F/B/C:start:size] */
	switch (trace->data_type) {
	case vdfs_trace_data_decomp:
		type   = 'C';
	case vdfs_trace_data_fops:
		countK = count >> 10;
		countB = count % 1024;
		break;
	case vdfs_trace_data_req:
		offset = offset << 9;
		countK = count  >> 10;
		countB = count  % 1024;
		type   = 'B';
#if 0
		len += snprintf(buffer + len, size - len - 1,
			"[f:0x%08llx]", trace->data.req.cmd_flags);
#endif
		break;
	case vdfs_trace_data_fault:
		offset = offset << 12;
		countK = count  << 2;
		break;
	case vdfs_trace_data_rpmb:
		type   = 'B';
		offset = offset << 8;
		countK = (count << 8) >> 10;
		countB = (count << 8) % 1024;
		break;
	case vdfs_trace_data_aops:
		switch (trace->ops_type) {
		case vdfs_trace_aops_writepages:
			if (trace->data.aops.len == LLONG_MAX) {
#if 0
				len += snprintf(buffer + len, size - len - 1,
						"[Write all dirty page]");
#endif
				goto no_print;
			}
		case vdfs_trace_aops_writepage:
			offset = 0;	/* no meaning in aops_writepage(s) */
			countK = count >> 10;
			countB = count % 1024;
			break;
		case vdfs_trace_aops_readpage:
		case vdfs_trace_aops_readpages:
			offset = offset << 12;
			countK = count  << 2;
			break;
		case vdfs_trace_aops_write_begin:
		case vdfs_trace_aops_write_end:
		case vdfs_trace_aops_direct_io:
			countK = count >> 10;
			countB = count % 1024;
			break;
		case vdfs_trace_aops_bmap:
		case vdfs_trace_aops_tuned_chunk:
		default:
			goto no_print;
		}
		break;
	case vdfs_trace_data_writeback:
	case vdfs_trace_data_sb:
	case vdfs_trace_data_iops:
	case vdfs_trace_data_fstype:
	default:
		goto no_print;
	}

	if (offset || countK || countB) {
		len += snprintf(buffer + len, size - len - 1,
				"[%c:%09llx:%5uK|%4u]", type, offset, countK, countB);
#ifdef IO_BANDWITH
		if (!VT_IS_FLAG(trace->flags, vt_flag_sublist)) {
			u32 _time = ktime_us_delta(trace->end, trace->start);
			u32 size  = (countK << 10) + countB;

			len += snprintf(buffer + len, size - len - 1, "%4uMB",
					size / _time);
		}
#endif
	}

no_print:
	len += snprintf(buffer + len, size - len - 1, "\n");
	return len;
}

void vdfs_trace_clear_buffer(void)
{
	unsigned long flag;
	spin_lock_irqsave(&vdfs_trace_lock, flag);
	list_splice_tail_init(&_traced_list, &_free_list);
	spin_unlock_irqrestore(&vdfs_trace_lock, flag);
	spin_lock_irqsave(&tracing_lock, flag);
	traced_data_cnt = 0;
	spin_unlock_irqrestore(&tracing_lock, flag);
}

#define PRIVATE_BUF_SIZE (4096)
#define MAX_LINE_LEN (256)
static ssize_t proc_vdfs_trace_open(struct inode *inode, struct file *file)
{
	file->private_data = kmalloc(PRIVATE_BUF_SIZE, GFP_KERNEL);
	if (file->private_data)
		return 0;
	else
		return -ENOMEM;
}

static int proc_vdfs_trace_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}

static ssize_t proc_vdfs_trace_write(struct file *file,
				     const char __user *buf, size_t len,
				     loff_t *ppos)
{
	ssize_t ret = 0;
	unsigned long flag;
	char *token, *name, *value;
	char buffer[MAX_LINE_LEN] = {0,}, *pbuffer = buffer;
	char *help_msg = "[usage : echo options > vdfs_trace]\n"
		" - option list -\n"
		"	on|off			: disable or enable trace \n"
		"       suppress=on|off         : control suppress option\n"
		"	clear			: clear mmc trace queue(stop read before clear)\n"
		"	state			: show current config\n";
	#define IS_SAME(value, str) ((value) && (str)  \
				&& (strlen(value) == strlen(str))  \
				&& !(strncasecmp((value), (str), sizeof((str)))))

	copy_from_user(buffer, buf, len);
	name = strim(strsep(&pbuffer, "="));
	if (pbuffer)
		value = strim(strsep(&pbuffer, "="));
	pr_debug("vdfs_trace control : %s(%s-%s)\n", pbuffer, name, value);
	if (IS_SAME(name, "on")) {
		trace_ctrl.onoff = TRACE_ON;
	} else if (IS_SAME(name, "off")) {
		trace_ctrl.onoff = TRACE_OFF;
	} else if (IS_SAME(name, "suppress") && value) {
		spin_lock_irqsave(&tracing_lock, flag);
		if (IS_SAME(value, "on"))
			trace_ctrl.suppress = SUPPRESS_ON;
		else if (IS_SAME(value, "off"))
			trace_ctrl.suppress = SUPPRESS_OFF;
		else
			ret = -EINVAL;
		spin_unlock_irqrestore(&tracing_lock, flag);
		if (ret)
			goto out;
	} else if (IS_SAME(name, "clear")) {
		vdfs_trace_clear_buffer();
	} else if (IS_SAME(name, "state")) {
		pr_err("[vdfs_trace state]\n"
			"\t - vdfs_trace onoff    : %s\n"
			"\t - vdfs_trace suppress : %s\n",
			((trace_ctrl.onoff == TRACE_ON)?"on":"off"),
			((trace_ctrl.suppress == SUPPRESS_ON)?"on":"off"));
	} else {
		ret = -EINVAL;
		pr_err("Unknown or Invalid vdfs trace option(%s:%s).\n",
		       name, value);
		goto out;
	}
	ret = len;
out:
	if (ret == -EINVAL)
		pr_err("%s\n", help_msg);

	#undef IS_SAME
	return ret;
}

static ssize_t proc_vdfs_trace_read(struct file *file, char __user *buf,
			size_t size, loff_t *ppos)
{
	ssize_t rtn = 0;
	struct list_head *p, *previous;
	vdfs_trace_data_t *current_buf = NULL;
	char *private_buf = (char *)file->private_data;
	size_t shorter_buf_len =
				(size < PRIVATE_BUF_SIZE) ? size:PRIVATE_BUF_SIZE;

reread:
	if (!(*ppos))	/* first read case */
		previous = &_traced_list;
	else
		previous = &((vdfs_trace_data_t *)((unsigned int)(*ppos)))->list;

	spin_lock_irq(&vdfs_trace_lock);
	rtn = wait_event_interruptible_lock_irq(vdfs_trace_wait,
			previous->next != &_traced_list, vdfs_trace_lock);
	if (rtn) {
		spin_unlock_irq(&vdfs_trace_lock);
		return rtn;
	}

	list_for_each(p, previous) {
		int len;

		if (p == &_traced_list) {
			current_buf = VT_LAST_ENTRY(&_traced_list, list);
			break;
		}
		current_buf = VT_ENTRY(p, list);
		if (VT_IS_FLAG(current_buf->flags, vt_flag_canceled))
			continue;
		rtn += _trace_data_to_str(private_buf+rtn,
					   PRIVATE_BUF_SIZE - rtn,
					   current_buf);
		if ((shorter_buf_len-rtn) < MAX_LINE_LEN)
			break;
	}
	spin_unlock_irq(&vdfs_trace_lock);
	copy_to_user(buf, private_buf, rtn);
	*ppos = (loff_t)((unsigned int)current_buf);
	if (!rtn)
		goto reread;
	return rtn;
}

static ssize_t proc_vdfs_trace_dbg_read(struct file *file, char __user *buf,
			size_t size, loff_t *ppos)
{
	unsigned long flag;
	int len = 0;
	char buffer[128];
	char dbg_buf[256];
	struct list_head *p;
	unsigned int tracing_start_cnt = 0;
	unsigned int tracing_finish_cnt = 0;

	if (file->private_data)
		return 0;

	spin_lock_irqsave(&tracing_lock, flag);
	printk(KERN_DEBUG "[tracing_start_list]\n");
	list_for_each(p, &_tracing_start_list) {
		vdfs_trace_data_t *trace = VT_ENTRY(p, list);

		_trace_data_to_str(dbg_buf, sizeof(dbg_buf), trace);
		printk(KERN_DEBUG "%s", dbg_buf);
		tracing_start_cnt++;
	}
	printk(KERN_DEBUG "\n\n[tracing_finish_list]\n");
	list_for_each(p, &_tracing_finish_list) {
		vdfs_trace_data_t *trace = VT_ENTRY(p, list);

		_trace_data_to_str(dbg_buf, sizeof(dbg_buf), trace);
		printk(KERN_DEBUG "%s", dbg_buf);
		tracing_finish_cnt++;
	}
	spin_unlock_irqrestore(&tracing_lock, flag);

	len += snprintf(buffer+len, sizeof(buffer)-1,
			"vdfs_trace_data_t size : %d bytes, list length : %d\n",
			sizeof(vdfs_trace_data_t), TRACE_LIMIT);
	len += snprintf(buffer+len, sizeof(buffer)-1,
			"_tracing_start_list size : %u\n", tracing_start_cnt);
	len += snprintf(buffer+len, sizeof(buffer)-1,
			"_tracing_finish_list size : %u\n", tracing_finish_cnt);

	copy_to_user(buf, buffer, len);
	file->private_data = (void *)1;

	return len;
}
static const struct file_operations proc_vdfs_trace_fops = {
	.open		= proc_vdfs_trace_open,
	.read		= proc_vdfs_trace_read,
	.write		= proc_vdfs_trace_write,
	.release	= proc_vdfs_trace_release,
};
static const struct file_operations proc_vdfs_trace_dbg_fops = {
	.read      = proc_vdfs_trace_dbg_read,
};

static int __init vdfs_trace_init(void)
{
	proc_create("vdfs_trace", S_IRUSR, NULL, &proc_vdfs_trace_fops);
	proc_create("vdfs_trace_dbg", S_IRUSR, NULL, &proc_vdfs_trace_dbg_fops);
	return 0;
}
module_init(vdfs_trace_init)
