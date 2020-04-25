#undef TRACE_SYSTEM
#define TRACE_SYSTEM vdfs4

#if !defined(_TRACE_VDFS4_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_VDFS4_H

#include <linux/writeback.h>
#include <linux/tracepoint.h>

TRACE_EVENT(vdfs4_evict_inode_exit,
	TP_PROTO(struct inode *inode, int ret_place),

	TP_ARGS(inode, ret_place),

	TP_STRUCT__entry(
		__field(	dev_t,	dev			)
		__field(	ino_t,	ino			)
		__field(	__u16,	mode		)
		__field(	int,	ret_place	)
	),

	TP_fast_assign(
		__entry->dev	= inode->i_sb->s_dev;
		__entry->ino	= inode->i_ino;
		__entry->mode	= inode->i_mode;
		__entry->ret_place	= ret_place;
	),

	TP_printk("dev %d,%d ino %lu mode 0%o ret_place %d",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  (unsigned long) __entry->ino, __entry->mode, __entry->ret_place)
);


TRACE_EVENT(vdfs4_evict_inode_enter,
	TP_PROTO(struct inode *inode),

	TP_ARGS(inode),

	TP_STRUCT__entry(
		__field(	dev_t,	dev			)
		__field(	ino_t,	ino			)
		__field(	__u16,	mode		)
	),

	TP_fast_assign(
		__entry->dev	= inode->i_sb->s_dev;
		__entry->ino	= inode->i_ino;
		__entry->mode	= inode->i_mode;
	),

	TP_printk("dev %d,%d ino %lu mode 0%o",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  (unsigned long) __entry->ino, __entry->mode)
);


TRACE_EVENT(vdfs4_sync_fs_enter,
	TP_PROTO(struct super_block *sb, int wait),

	TP_ARGS(sb, wait),

	TP_STRUCT__entry(
		__field(	dev_t,	dev			)
		__field(	int,	wait		)
	),

	TP_fast_assign(
		__entry->dev	= sb->s_dev;
		__entry->wait	= wait;
	),

	TP_printk("dev %d,%d wait %d", MAJOR(__entry->dev), MINOR(__entry->dev), __entry->wait)
);

TRACE_EVENT(vdfs4_sync_fs_exit,
	TP_PROTO(struct super_block *sb, int ret),

	TP_ARGS(sb, ret),

	TP_STRUCT__entry(
		__field(	dev_t,	dev			)
		__field(	int,	ret			)
	),

	TP_fast_assign(
		__entry->dev	= sb->s_dev;
		__entry->ret	= ret;
	),

	TP_printk("dev %d,%d ret %d", MAJOR(__entry->dev), MINOR(__entry->dev), __entry->ret)
);



TRACE_EVENT(vdfs4_write_inode,
	TP_PROTO(struct inode *inode, struct writeback_control *wbc),

	TP_ARGS(inode, wbc),

	TP_STRUCT__entry(
		__field(	dev_t,	dev			)
		__field(	ino_t,	ino			)
		__field(	__u16,	mode		)
	),

	TP_fast_assign(
		__entry->dev	= inode->i_sb->s_dev;
		__entry->ino	= inode->i_ino;
		__entry->mode	= inode->i_mode;
	),

	TP_printk("dev %d,%d ino %lu mode 0%o",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  (unsigned long) __entry->ino, __entry->mode)
);


TRACE_EVENT(vdfs4_destroy_inode,
	TP_PROTO(struct inode *inode),

	TP_ARGS(inode),

	TP_STRUCT__entry(
		__field(	dev_t,	dev			)
		__field(	ino_t,	ino			)
		__field(	__u16,	mode		)
	),

	TP_fast_assign(
		__entry->dev	= inode->i_sb->s_dev;
		__entry->ino	= inode->i_ino;
		__entry->mode	= inode->i_mode;
	),

	TP_printk("dev %d,%d ino %lu mode 0%o",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  (unsigned long) __entry->ino, __entry->mode)
);


TRACE_EVENT(vdfs4_alloc_inode,
	TP_PROTO(struct super_block *sb),

	TP_ARGS(sb),

	TP_STRUCT__entry(
		__field(	dev_t,	dev			)
	),

	TP_fast_assign(
		__entry->dev	= sb->s_dev;
	),

	TP_printk("dev %d,%d", MAJOR(__entry->dev), MINOR(__entry->dev))
);


TRACE_EVENT(vdfs4_file_fsync_exit,
	TP_PROTO(struct file *file, int ret),

	TP_ARGS(file, ret),

	TP_STRUCT__entry(
		__field(	dev_t,	dev			)
		__field(	ino_t,	ino			)
		__field(	__u16,	mode		)
		__field(	int,	ret	)
	),

	TP_fast_assign(
		struct inode *inode = file->f_mapping->host;

		__entry->dev	= inode->i_sb->s_dev;
		__entry->ino	= inode->i_ino;
		__entry->mode	= inode->i_mode;
		__entry->ret	= ret;
	),

	TP_printk("dev %d,%d ino %lu mode 0%o ret %d",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  (unsigned long) __entry->ino, __entry->mode,
		  __entry->ret)
);


TRACE_EVENT(vdfs4_file_fsync_enter,
	TP_PROTO(struct file *file, loff_t start, loff_t end,
			int datasync),

	TP_ARGS(file, start, end, datasync),

	TP_STRUCT__entry(
		__field(	dev_t,	dev			)
		__field(	ino_t,	ino			)
		__field(	__u16,	mode		)
		__field(	loff_t,	start		)
		__field(	loff_t,	end			)
		__field(	int,	datasync	)
	),

	TP_fast_assign(
		struct inode *inode = file->f_mapping->host;

		__entry->dev	= inode->i_sb->s_dev;
		__entry->ino	= inode->i_ino;
		__entry->mode	= inode->i_mode;
		__entry->start	= start;
		__entry->end	= end;
		__entry->datasync	= datasync;
	),

	TP_printk("dev %d,%d ino %lu mode 0%o start %lld end %lld datasync %d",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  (unsigned long) __entry->ino, __entry->mode,
		  __entry->start, __entry->end,
		  __entry->datasync)
);


TRACE_EVENT(vdfs4_file_release,
	TP_PROTO(struct inode *inode, struct file *file),

	TP_ARGS(inode, file),

	TP_STRUCT__entry(
		__field(	dev_t,	dev			)
		__field(	ino_t,	ino			)
		__field(	__u16,	mode		)
	),

	TP_fast_assign(
		__entry->dev	= inode->i_sb->s_dev;
		__entry->ino	= inode->i_ino;
		__entry->mode	= inode->i_mode;
	),

	TP_printk("dev %d,%d ino %lu mode 0%o",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  (unsigned long) __entry->ino, __entry->mode)
);


TRACE_EVENT(vdfs4_file_open,
	TP_PROTO(struct inode *inode, struct file *filp),

	TP_ARGS(inode, filp),

	TP_STRUCT__entry(
		__field(	dev_t,	dev			)
		__field(	ino_t,	ino			)
		__field(	__u16,	mode		)
	),

	TP_fast_assign(
		__entry->dev	= inode->i_sb->s_dev;
		__entry->ino	= inode->i_ino;
		__entry->mode	= inode->i_mode;
	),

	TP_printk("dev %d,%d ino %lu mode 0%o",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  (unsigned long) __entry->ino, __entry->mode)
);


TRACE_EVENT(vdfs4_file_splice_read,
	TP_PROTO(struct file *in, loff_t *ppos,
			struct pipe_inode_info *pipe, size_t len, unsigned int flags),

	TP_ARGS(in, ppos, pipe, len, flags),

	TP_STRUCT__entry(
		__field(	dev_t,	dev			)
		__field(	ino_t,	ino			)
		__field(	__u16,	mode		)
		__field(	__u32,	len			)
		__field(	__u32,	flags		)
	),

	TP_fast_assign(
		__entry->dev	= in->f_mapping->host->i_sb->s_dev;
		__entry->ino	= in->f_mapping->host->i_ino;
		__entry->mode	= in->f_mapping->host->i_mode;
		__entry->len	= len;
		__entry->flags	= flags;
	),

	TP_printk("dev %d,%d ino %lu mode 0%o len %d flags %x",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  (unsigned long) __entry->ino,
		  __entry->mode, __entry->len, __entry->flags)
);


TRACE_EVENT(vdfs4_file_mmap,
	TP_PROTO(struct file *file, struct vm_area_struct *vma),

	TP_ARGS(file, vma),

	TP_STRUCT__entry(
		__field(	dev_t,	dev			)
		__field(	ino_t,	ino			)
		__field(	__u16,	mode			)
	),

	TP_fast_assign(
		__entry->dev	= file->f_mapping->host->i_sb->s_dev;
		__entry->ino	= file->f_mapping->host->i_ino;
		__entry->mode	= file->f_mapping->host->i_mode;
	),

	TP_printk("dev %d,%d ino %lu mode 0%o",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  (unsigned long) __entry->ino,
		  __entry->mode)
);


TRACE_EVENT(vdfs4_file_write_iter,
	TP_PROTO(struct kiocb *iocb,
			struct iov_iter *iov_iter),

	TP_ARGS(iocb, iov_iter),

	TP_STRUCT__entry(
		__field(	dev_t,	dev			)
		__field(	ino_t,	ino			)
		__field(	__u16,	mode			)
	),

	TP_fast_assign(
		__entry->dev	= iocb->ki_filp->f_mapping->host->i_sb->s_dev;
		__entry->ino	= iocb->ki_filp->f_mapping->host->i_ino;
		__entry->mode	= iocb->ki_filp->f_mapping->host->i_mode;
	),

	TP_printk("dev %d,%d ino %lu mode 0%o",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  (unsigned long) __entry->ino,
		  __entry->mode)
);

TRACE_EVENT(vdfs4_file_read_iter,
	TP_PROTO(struct kiocb *iocb,
			struct iov_iter *iov_iter),

	TP_ARGS(iocb, iov_iter),

	TP_STRUCT__entry(
		__field(	dev_t,	dev			)
		__field(	ino_t,	ino			)
		__field(	__u16,	mode			)
	),

	TP_fast_assign(
		__entry->dev	= iocb->ki_filp->f_mapping->host->i_sb->s_dev;
		__entry->ino	= iocb->ki_filp->f_mapping->host->i_ino;
		__entry->mode	= iocb->ki_filp->f_mapping->host->i_mode;
	),

	TP_printk("dev %d,%d ino %lu mode 0%o",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  (unsigned long) __entry->ino,
		  __entry->mode)
);

#endif /* _TRACE_VDFS4_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
