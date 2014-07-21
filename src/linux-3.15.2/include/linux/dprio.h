/*
 * include/linux/dprio.h
 *
 * Deferred set priority.
 *
 * Started by (C) 2014 Sergey Oboguev <oboguev@yahoo.com>
 *
 * This code is licenced under the GPL version 2 or later.
 * For details see linux-kernel-base/COPYING.
 */

#ifndef _LINUX_DPRIO_H
#define _LINUX_DPRIO_H

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/authlist.h>

#ifdef CONFIG_DEFERRED_SETPRIO

/*
 * @mask contains bit-flags indicating which policies had been pre-approved.
 * Other fields are valid only if the corresponding bit is set in @mask.
 */
static inline void __dprio_info_assumptions(void)
{
	/* SCHED_xxx is used as a bit index in @mask */
	BUILD_BUG_ON(SCHED_NORMAL > 31);
	BUILD_BUG_ON(SCHED_FIFO > 31);
	BUILD_BUG_ON(SCHED_RR > 31);
	BUILD_BUG_ON(SCHED_BATCH > 31);
	BUILD_BUG_ON(SCHED_IDLE > 31);
}
struct dprio_info {
	unsigned mask;
	s32 normal_sched_nice;
	s32 batch_sched_nice;
	u32 fifo_sched_priority;
	u32 rr_sched_priority;
	bool capable_sys_nice;
};

/*
 * Called by dup_task_struct to reset non-inherited fields
 */
static __always_inline void set_task_in_dprio(struct task_struct *tsk,
					      bool in_dprio)
{
#ifdef CONFIG_DEBUG_DEFERRED_SETPRIO
	tsk->in_dprio = in_dprio;
#endif
}

static inline void dprio_dup_task_struct(struct task_struct *tsk)
{
	/* reset deferred setprio fields not inherited from the parent */
	tsk->dprio_ku_area_pp = NULL;
	tsk->dprio_info = NULL;
	set_task_in_dprio(tsk, false);
}

void dprio_detach(struct task_struct *tsk);
void dprio_handle_request(void);
bool dprio_check_for_request(struct task_struct *prev);
long dprio_prctl(int option, unsigned long a2, unsigned long a3,
		 unsigned long a4, unsigned long a5);

struct dprio_saved_context {
	struct dprio_ku_area __user * __user *dprio_ku_area_pp;
	struct dprio_info *dprio_info;
};

static inline void dprio_save_reset_context(struct dprio_saved_context *saved)
{
	saved->dprio_ku_area_pp = current->dprio_ku_area_pp;
	saved->dprio_info = current->dprio_info;

	if (unlikely(saved->dprio_ku_area_pp)) {
		preempt_disable();
		current->dprio_ku_area_pp = NULL;
		current->dprio_info = NULL;
		preempt_enable();
	}
}

static inline void dprio_restore_context(struct dprio_saved_context *saved)
{
	if (unlikely(saved->dprio_ku_area_pp)) {
		preempt_disable();
		current->dprio_ku_area_pp = saved->dprio_ku_area_pp;
		current->dprio_info = saved->dprio_info;
		preempt_enable();
	}
}

static inline void dprio_free_context(struct dprio_saved_context *saved)
{
	if (unlikely(saved->dprio_info))
		kfree(saved->dprio_info);
}

#ifdef CONFIG_DEFERRED_SETPRIO_ALLOW_EVERYBODY
  #define DPRIO_AUTHLIST_INITIAL_VALUE  AUTHLIST_KIND_EVERYBODY
#else
  #define DPRIO_AUTHLIST_INITIAL_VALUE  AUTHLIST_KIND_NOBODY
#endif

extern struct authlist dprio_authlist;

int dprio_check_permission(void);

#else /* ndef CONFIG_DEFERRED_SETPRIO */

static inline void set_task_in_dprio(struct task_struct *tsk, bool in_dprio) {}
static inline void dprio_dup_task_struct(struct task_struct *tsk) {}
static inline void dprio_detach(struct task_struct *tsk) {}
static inline void dprio_handle_request(void) {}

struct dprio_saved_context {
	char dummy[0];		/* suppress compiler warning */
};

static inline void dprio_save_reset_context(struct dprio_saved_context *saved) {}
static inline void dprio_restore_context(struct dprio_saved_context *saved) {}
static inline void dprio_free_context(struct dprio_saved_context *saved) {}

#endif /* CONFIG_DEFERRED_SETPRIO */

#endif /* _LINUX_DPRIO_H */

