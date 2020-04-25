#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/delay.h>

#include "vdfs4.h"

#define LOCK_TIMEOUT (10) //10sec

static void lock_timer_cb(struct work_struct *work) {
	static atomic_t flag = ATOMIC_INIT(0);
	struct vdfs4_lock_info *info = container_of(to_delayed_work(work),
					struct vdfs4_lock_info, timer);
	/* print only once */
	if (atomic_inc_return(&flag) != 1) {
		atomic_dec(&flag);
		return;
	}

	VDFS4_ERR("BlockedLock..!!\n");
	show_state();
}

static void init_lock_trace(struct vdfs4_lock_info* info)
{
	info->lock = __SPIN_LOCK_UNLOCKED(info->lock);
	INIT_DELAYED_WORK(&info->timer, lock_timer_cb);
	atomic_set(&info->lock_count, 0);
	info->initialized = 1;
}

void vdfs4_register_lock_timer(struct vdfs4_sb_info *sbi,
			       enum vdfs4_lock_type type)
{
	bool rtn;
	struct vdfs4_lock_info *info = &(sbi->lock_info[type]);

	if (!info->initialized)
		init_lock_trace(info);

	spin_lock(&info->lock);
	atomic_inc(&info->lock_count);
	rtn = mod_delayed_work(system_wq, &info->timer, LOCK_TIMEOUT * HZ);
	spin_unlock(&info->lock);
}

void vdfs4_unregister_lock_timer(struct vdfs4_sb_info *sbi,
				 enum vdfs4_lock_type type)
{
	struct vdfs4_lock_info *info = &(sbi->lock_info[type]);

	spin_lock(&info->lock);
	if (atomic_dec_and_test(&info->lock_count))
		cancel_delayed_work_sync(&info->timer);
	spin_unlock(&info->lock);
}
