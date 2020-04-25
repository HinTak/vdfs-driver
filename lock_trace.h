#ifndef LOCK_TRACE_H_
#define LOCK_TRACE_H_

#if defined(CONFIG_VDFS4_LOCK_TRACE)
enum vdfs4_lock_type {
	VDFS4_LOCK_CAT_TREE = 0,
	VDFS4_LOCK_MAX,
};

struct vdfs4_lock_info {
	spinlock_t lock;
	struct delayed_work timer;
	atomic_t lock_count;
	char initialized;
};

void vdfs4_register_lock_timer(struct vdfs4_sb_info *sbi,
			       enum vdfs4_lock_type type);
void vdfs4_unregister_lock_timer(struct vdfs4_sb_info *sbi,
				 enum vdfs4_lock_type type);

/* Category Tree Lock */
#define vdfs4_cattree_lock(sbi, lock_type) do {				\
	mutex_##lock_type##_lock((sbi)->catalog_tree->rw_tree_lock);	\
	vdfs4_register_lock_timer((sbi), VDFS4_LOCK_CAT_TREE);		\
} while(0)

#define vdfs4_cattree_unlock(sbi, lock_type) do {			\
	vdfs4_unregister_lock_timer((sbi), VDFS4_LOCK_CAT_TREE);	\
	mutex_##lock_type##_unlock((sbi)->catalog_tree->rw_tree_lock);	\
} while(0)

#define vdfs4_cattree_w_lock(sbi) vdfs4_cattree_lock(sbi, w)
#define vdfs4_cattree_w_unlock(sbi) vdfs4_cattree_unlock(sbi, w)
#define vdfs4_cattree_r_lock(sbi) vdfs4_cattree_lock(sbi, r)
#define vdfs4_cattree_r_unlock(sbi) vdfs4_cattree_unlock(sbi, r)

#else

/* Category Tree Lock */
#define vdfs4_cattree_w_lock(sbi)			\
	mutex_w_lock((sbi)->catalog_tree->rw_tree_lock)
#define vdfs4_cattree_w_unlock(sbi)			\
	mutex_w_unlock((sbi)->catalog_tree->rw_tree_lock)
#define vdfs4_cattree_r_lock(sbi)			\
	mutex_r_lock((sbi)->catalog_tree->rw_tree_lock)
#define vdfs4_cattree_r_unlock(sbi)			\
	mutex_r_unlock((sbi)->catalog_tree->rw_tree_lock)
#endif

#endif /* LOCK_TRACE_H_ */
