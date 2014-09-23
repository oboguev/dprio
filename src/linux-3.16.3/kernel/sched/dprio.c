/*
 * kernel/sched/dprio.c
 *
 * Deferred set priority.
 *
 * Started by (C) 2014 Sergey Oboguev <oboguev@yahoo.com>
 *
 * This code is licenced under the GPL version 2 or later.
 * For details see linux-kernel-base/COPYING.
 */

#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/stddef.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/dprio.h>
#include <linux/dprio_api.h>
#include <linux/slab.h>
#include <linux/compiler.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/prctl.h>
#include <linux/init.h>

unsigned int dprio_privileged = DPRIO_PRIVILEGED_INITIAL_VALUE;

/*
 * Returns 0 on success.
 */
static inline int __copyin(void *dst, const void __user *src,
			   unsigned size, bool atomic)
{
	int ret;

	/* Use barrier() to sequence userspace-kernel dprio protocol */
	barrier();
	if (atomic) {
		pagefault_disable();
		ret = __copy_from_user_inatomic(dst, src, size);
		pagefault_enable();
	} else {
		ret = copy_from_user(dst, src, size);
	}
	barrier();

	return ret;
}

/*
 * Returns 0 on success.
 */
static inline int __copyout(void __user *dst, const void *src,
			    unsigned size, bool atomic)
{
	int ret;

	/* Use barrier() to sequence userspace-kernel dprio protocol */
	barrier();
	if (atomic) {
		pagefault_disable();
		ret = __copy_to_user_inatomic(dst, src, size);
		pagefault_enable();
	} else {
		ret = copy_to_user(dst, src, size);
	}
	barrier();

	return ret;
}

#define __copyin_var(x, uptr, atomic)	\
	__copyin(&(x), (uptr), sizeof(x), (atomic))

#define __copyout_var(x, uptr, atomic)	\
	__copyout((uptr), &(x), sizeof(x), (atomic))


/*
 * Mimics sched_copy_attr()
 */
#define CHUNK_SIZE 32u
static int dprio_copyin_sched_attr(struct sched_attr __user *uattr,
				   struct sched_attr *attr,
				   bool atomic)
{
	u32 size;

	if (!access_ok(VERIFY_READ, uattr, SCHED_ATTR_SIZE_VER0))
		return -EFAULT;

	/*
	 * zero the full structure, so that a short copy will be nice.
	 */
	memset(attr, 0, sizeof(*attr));

	if (__copyin_var(size, &uattr->size, atomic))
		return -EFAULT;

	if (size > PAGE_SIZE)	/* silly large */
		return -E2BIG;

	if (!size)		/* abi compat */
		size = SCHED_ATTR_SIZE_VER0;

	if (size < SCHED_ATTR_SIZE_VER0)
		return -E2BIG;

	/*
	 * If we're handed a bigger struct than we know of,
	 * ensure all the unknown bits are 0 - i.e. new
	 * user-space does not rely on any kernel feature
	 * extensions we dont know about yet.
	 */
	if (size > sizeof(*attr)) {
		unsigned char __user *addr;
		unsigned char __user *end;
		unsigned char val[CHUNK_SIZE];
		unsigned k, chunk_size;

		addr = (char __user *)uattr + sizeof(*attr);
		end  = (char __user *)uattr + size;

		for (; addr < end; addr += chunk_size) {
			chunk_size = min((unsigned) (end - addr), CHUNK_SIZE);
			if (__copyin(val, addr, chunk_size, atomic))
				return -EFAULT;
			for (k = 0;  k < chunk_size; k++) {
				if (val[k])
					return -E2BIG;
			}
		}
		size = sizeof(*attr);
	}

	if (__copyin(attr, uattr, size, atomic))
		return -EFAULT;

	attr->size = size;

	/*
	 * XXX: do we want to be lenient like existing syscalls; or do we want
	 * to be strict and return an error on out-of-bounds values?
	 * See also other uses of clamp(..., MIN_NICE, MAX_NICE) below.
	 */
	attr->sched_nice = clamp(attr->sched_nice, MIN_NICE, MAX_NICE);

	return 0;
}


/*
 * Detach the task from userland deferred setprio request area and deallocate
 * all resources for the connection. Called from:
 *
 *   - prctl(PR_SET_DEFERRED_SETPRIO) with area argument passed as NULL
 *     to terminate previous connection
 *
 *   - prctl(PR_SET_DEFERRED_SETPRIO) with new non-NULL area argument
 *     setting new connection. Previous connection is terminated before
 *     establishing a new one
 *
 *   - when the task is terminated in do_exit()
 */
void dprio_detach(struct task_struct *tsk)
{
	preempt_disable();

	tsk->dprio_ku_area_pp = NULL;

	if (unlikely(tsk->dprio_info)) {
		kfree(tsk->dprio_info);
		tsk->dprio_info = NULL;
	}

	preempt_enable();
}

/*
 * Pre-process sched_attr just read from the userspace, whether during precheck
 * or during dprio request execution, to impose uniform interpretation of
 * structure format and values.
 */
static void uniform_attr(struct sched_attr *attr)
{
	/* accommodate legacy hack */
	if ((attr->sched_policy & SCHED_RESET_ON_FORK) &&
	    attr->sched_policy != -1) {
		attr->sched_flags |= SCHED_FLAG_RESET_ON_FORK;
		attr->sched_policy &= ~SCHED_RESET_ON_FORK;
	}

	if (attr->sched_policy == SCHED_IDLE)
		attr->sched_nice = MAX_NICE;
}

/*
 * Precheck whether current process is authorized to set its scheduling
 * properties to @uattr. If yes, make record in @info and return 0.
 * If not, return error.
 */
static int precheck(struct dprio_info *info, struct sched_attr __user *uattr)
{
	struct sched_attr attr;
	u32 policy;
	unsigned mask;
	int error;

	error = dprio_copyin_sched_attr(uattr, &attr, false);
	if (error)
		return error;

	uniform_attr(&attr);

	policy = attr.sched_policy;
	mask = 1 << policy;

	switch (policy) {
	case SCHED_NORMAL:
		attr.sched_nice = clamp(attr.sched_nice, MIN_NICE, MAX_NICE);
		if ((info->mask & mask) &&
		    attr.sched_nice >= info->normal_sched_nice)
			break;
		error = sched_setattr_precheck(current, &attr);
		if (error == 0) {
			info->normal_sched_nice = attr.sched_nice;
			info->mask |= mask;
		}
		break;

	case SCHED_BATCH:
		attr.sched_nice = clamp(attr.sched_nice, MIN_NICE, MAX_NICE);
		if ((info->mask & mask) &&
		    attr.sched_nice >= info->batch_sched_nice)
			break;
		error = sched_setattr_precheck(current, &attr);
		if (error == 0) {
			info->batch_sched_nice = attr.sched_nice;
			info->mask |= mask;
		}
		break;

	case SCHED_FIFO:
		if ((info->mask & mask) &&
		    attr.sched_priority <= info->fifo_sched_priority)
			break;
		error = sched_setattr_precheck(current, &attr);
		if (error == 0) {
			info->fifo_sched_priority = attr.sched_priority;
			info->mask |= mask;
		}
		break;

	case SCHED_RR:
		if ((info->mask & mask) &&
		    attr.sched_priority <= info->rr_sched_priority)
			break;
		error = sched_setattr_precheck(current, &attr);
		if (error == 0) {
			info->rr_sched_priority = attr.sched_priority;
			info->mask |= mask;
		}
		break;

	case SCHED_IDLE:
		if (info->mask & mask)
			break;
		error = sched_setattr_precheck(current, &attr);
		if (error == 0)
			info->mask |= mask;
		break;

	case SCHED_DEADLINE:
		/*
		 * DL is not a meaningful policy for deferred set
		 * priority
		 */
	default:
		error = -EINVAL;
		break;
	}

	return error;
}

/*
 * Implements prctl(PR_SET_DEFERRED_SETPRIO).
 *
 * To set PR_SET_DEFERRED_SETPRIO:
 *
 *     a2 = address of u64 variable in the userspace that holds the pointer
 *          to dprio_ku_area or NULL
 *
 *     a3 = address of userspace array of pointers to sched_attr entries
 *          to preapprove for subsequent pre-checked use by deferred set
 *          priority requests
 *
 *     a4 = count of entries in a3 or 0
 *
 *     a5 = 0
 *
 * To reset PR_SET_DEFERRED_SETPRIO:
 *
 *     a2 = 0
 *     a3 = 0
 *     a4 = 0
 *     a5 = 0
 *
 * Thus valid calls are:
 *
 *     struct sched_attr **sched_attrs_pp;
 *     prctl(PR_SET_DEFERRED_SETPRIO, dprio_ku_area_pp,
 *           sched_attrs_pp, nattrs, 0)
 *
 *     prctl(PR_SET_DEFERRED_SETPRIO, NULL, NULL, 0, 0)
 *
 */
long dprio_prctl(int option, unsigned long a2, unsigned long a3,
		 unsigned long a4, unsigned long a5)
{
	struct dprio_ku_area __user * __user *ku_area_pp;
	struct dprio_ku_area __user *ku_area_p;
	struct dprio_info *info = NULL;
	unsigned long ne, nentries;
	struct sched_attr __user * __user *uattr_pp;
	struct sched_attr __user *uattr_p;
	bool atomic = false;
	long error = 0;

	if (option != PR_SET_DEFERRED_SETPRIO)
		return -EINVAL;

	ku_area_pp = (struct dprio_ku_area __user * __user *) a2;

	/*
	* Handle reset operation for PR_SET_DEFERRED_SETPRIO
	 */
	if (ku_area_pp == NULL) {
		if (a3 | a4 | a5)
			return -EINVAL;
		dprio_handle_request();
		dprio_detach(current);
		return 0;
	}

	/*
	 * Handle set operation for PR_SET_DEFERRED_SETPRIO
	 */
	uattr_pp = (struct sched_attr __user * __user *) a3;
	nentries = a4;
	if (a5)
		return -EINVAL;

	/* sanity check to avoid long spinning in the kernel */
	if (nentries > 4096) {
		error = -EINVAL;
		goto out;
	}

	/* Check alignment */
	if ((unsigned long) ku_area_pp % sizeof(u64))
		return  -EINVAL;

	/* check *ku_area_pp is readable and writeable */
	if (__copyin_var(ku_area_p, ku_area_pp, atomic) ||
	    __copyout_var(ku_area_p, ku_area_pp, atomic))
		return  -EFAULT;

	error = dprio_check_permission();
	if (error)
		return error;

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (info == NULL)
		return -ENOMEM;
	info->mask = 0;
	/*
	 * XXX:
	 *
	 * We may trigger a false recording of PF_SUPERPRIV here by requesting
	 * CAP_SYS_NICE capability we may not actually use later, however
	 * since we cannot modify current->flags during dprio_handle_request()
	 * when called from __schedule(), the alternatives would be either
	 * possibly missing the recording of PF_SUPERPRIV, or (better) splitting
	 * PF_SUPERPRIV from current->flags and moving it to a variable with
	 * atomic access protocol.
	 */
	info->capable_sys_nice = capable(CAP_SYS_NICE);

	/*
	 * We prevalidate maximum requested priority levels at the time of
	 * prctl set-up instead of validating priority change requests during
	 * their actual processing in __schedule and do_fork in order to:
	 *
	 *    - reduce latency during request processing in __schedule()
	 *
	 *    - avoid blocking in the secirity code when setprio processing
	 *      is performed in _schedule()
	 *
	 *    - avoid EINTR or ERESTARTSYS etc. that may be returned by
	 *      the security code during setprio request processing
	 */
	for (ne = 0;  ne < nentries;  ne++) {
		cond_resched();
		if (__copyin_var(uattr_p, uattr_pp + ne, atomic)) {
			error = -EFAULT;
			goto out;
		}
		error = precheck(info, uattr_p);
		if (error)
			goto out;
	}

	/*
	 * If there was a previous active dprio ku area, try to process
	 * any pending request in it and detach from it.
	 */
	dprio_handle_request();
	dprio_detach(current);

	preempt_disable();
	current->dprio_ku_area_pp = ku_area_pp;
	current->dprio_info = info;
	preempt_enable();

out:
	if (error && info)
		kfree(info);

	return error;
}

/*
 * Check if "deferred set priority" request from the userland is pending.
 * Returns @true if request has been detected, @false if not.
 *
 * If page pointed by dprio_ku_area_pp is not currently accessible (e.g. not
 * valid or paged out), return @false.
 */
bool dprio_check_for_request(struct task_struct *prev)
{
	struct dprio_ku_area __user *ku_area_p;
	bool atomic = true;

#ifdef CONFIG_DEBUG_DEFERRED_SETPRIO
	/*
	 * We are only called if prev->dprio_ku_area_pp != NULL,
	 * thus prev cannot be a kernel thread
	 */
	if (unlikely(prev->active_mm != prev->mm)) {
		WARN_ONCE(1, KERN_ERR "BUG: dprio: address space not mapped\n");
		return false;
	}
#endif /* CONFIG_DEBUG_DEFERRED_SETPRIO */

	if (__copyin_var(ku_area_p, prev->dprio_ku_area_pp, atomic))
		return false;

	return ku_area_p != NULL;
}

/*
 * Handle pending "deferred set priority" request from the userland.
 */
void dprio_handle_request(void)
{
	struct dprio_ku_area __user *ku;
	struct dprio_ku_area __user *ku_null;
	struct sched_attr attr;
	bool atomic;
	u32 resp, error;
	int ierror = 0;
	unsigned long rlim_rtprio;
	long rlim_nice;
	struct dprio_info *info;

	/* attached to ku area? */
	if (current->dprio_ku_area_pp == NULL)
		return;

	/* called from __schedule? */
	atomic = preempt_count() != 0;

	/* fetch ku request area address from the userspace */
	if (__copyin_var(ku, current->dprio_ku_area_pp, atomic))
		return;

	/* check if request is pending */
	if (unlikely(ku == NULL))
		return;

	/* remark to the userspace:
	   request processing has been started/attempted */
	resp = DPRIO_RESP_UNKNOWN;
	if (__copyout_var(resp, &ku->resp, atomic))
		return;

	/* reset pending request */
	ku_null = NULL;
	if (__copyout_var(ku_null, current->dprio_ku_area_pp, atomic))
		return;

	/* fetch request parameters from the userspace */
	if (dprio_copyin_sched_attr(&ku->sched_attr, &attr, atomic))
		return;

	/* impose uniform interpretation of sched_attr */
	uniform_attr(&attr);

	if (attr.sched_flags & ~SCHED_FLAG_RESET_ON_FORK) {
		ierror = -EINVAL;
		goto out;
	}

	/*
	 * check if request has been pre-authorized
	 */
	info = current->dprio_info;
	switch (attr.sched_policy) {
	case SCHED_NORMAL:
		if (!(info->mask & (1 << SCHED_NORMAL)) ||
		    attr.sched_nice < info->normal_sched_nice)
			ierror = -EPERM;
		/*
		 * check whether RLIMIT_NICE has been reduced
		 * by setrlimit or prlimit
		 */
		if (ierror == 0 && !info->capable_sys_nice) {
			rlim_nice = 20 - task_rlimit(current, RLIMIT_NICE);
			if (attr.sched_nice < rlim_nice)
				ierror = -EPERM;
		}
		break;

	case SCHED_BATCH:
		if (!(info->mask & (1 << SCHED_BATCH)) ||
		    attr.sched_nice < info->batch_sched_nice)
			ierror = -EPERM;
		/*
		 * check whether RLIMIT_NICE has been reduced
		 * by setrlimit or prlimit
		 */
		if (ierror == 0 && !info->capable_sys_nice) {
			rlim_nice = 20 - task_rlimit(current, RLIMIT_NICE);
			if (attr.sched_nice < rlim_nice)
				ierror = -EPERM;
		}
		break;

	case SCHED_FIFO:
		if (!(info->mask & (1 << SCHED_FIFO)) ||
		    attr.sched_priority > info->fifo_sched_priority)
			ierror = -EPERM;
		/*
		 * check whether RLIMIT_RTPRIO has been reduced
		 * by setrlimit or prlimit
		 */
		if (ierror == 0 && !info->capable_sys_nice) {
			rlim_rtprio = task_rlimit(current, RLIMIT_RTPRIO);
			if (rlim_rtprio == 0 || attr.sched_priority > rlim_rtprio)
				ierror = -EPERM;
		}
		break;

	case SCHED_RR:
		if (!(info->mask & (1 << SCHED_RR)) ||
		    attr.sched_priority > info->rr_sched_priority)
			ierror = -EPERM;
		/*
		 * check whether RLIMIT_RTPRIO has been reduced
		 * by setrlimit or prlimit
		 */
		if (ierror == 0 && !info->capable_sys_nice) {
			rlim_rtprio = task_rlimit(current, RLIMIT_RTPRIO);
			if (rlim_rtprio == 0 || attr.sched_priority > rlim_rtprio)
				ierror = -EPERM;
		}
		break;

	case SCHED_IDLE:
		if (!(info->mask & (1 << SCHED_IDLE)))
			ierror = -EPERM;
		break;

	default:
		ierror = -EINVAL;
		break;
	}

	/* execute the request */
	if (ierror == 0)
		ierror = sched_setattr_prechecked(current, &attr, true);

out:
	if (ierror) {
		error = (u32) -ierror;
		resp = DPRIO_RESP_ERROR;
		if (0 == __copyout_var(error, &ku->error, atomic))
			__copyout_var(resp, &ku->resp, atomic);
	} else {
		resp = DPRIO_RESP_OK;
		__copyout_var(resp, &ku->resp, atomic);
	}
}

/*
 * Verify if the current task is authorized to use prctl(PR_SET_DEFERRED_SETPRIO).
 */
int dprio_check_permission(void)
{
	if (dprio_privileged && !capable(CAP_DPRIO))
		return -EPERM;

	return 0;
}

