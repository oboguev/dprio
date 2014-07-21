/*
 * DPRIO (deferred set priority) userspace functions.
 *
 * Copyright (c) 2014 Sergey Oboguev
 *
 * User-level DPRIO library source code is dual-licensed under GPL2 and
 * "use as you want" license described below. The user of this code is
 * free to choose whether to use user-level DPRIO library under GPL2
 * or under the "use as you want" license.
 *
 * "Use as you want" license terms are:
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this source file (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software
 * is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sched.h>
#include <pthread.h>
#include <errno.h>
#include <alloca.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include "dprio.h"

/*****************************************************************************
*       		Generic definitions				     *
*****************************************************************************/

#ifndef PR_SET_DEFERRED_SETPRIO
 #define PR_SET_DEFERRED_SETPRIO	43
#endif

#ifndef __always_inline
# define __always_inline	inline __attribute__((always_inline))
#endif

typedef int bool;

#ifndef true
  #define true 1
#endif

#ifndef false
  #define false 0
#endif

/* compiler barrier */
#define barrier()  do { __asm__ __volatile__ ("" ::: "memory"); } while (0)

static inline size_t ROUNDUP(size_t n, size_t r)
{
	return ((n + r - 1) / r) * r;
}

static void bugcheck()
{
	abort();
}

/*****************************************************************************
*       		Structure definitions				     *
*****************************************************************************/

struct __dprio_threadgroup {
	int minpl;
	int maxpl;
	const struct sched_attr *plsched;
	dprio_onerror_proc_t onerror;
};

struct __dprio_perthread_set {
	void *pv;
	size_t alloc_size;
	unsigned int pagesize;
	unsigned int perpage;
	unsigned int alloc_count;
	size_t struct_size;
};

struct dprio_ku_ctlarea {
	/*
	 * @cmd holds an address, but is defined as u64 rather than pointer
	 * type, so 32-bit applications will have the same ku_area structure
	 * as 64-bit ones and can interoperate with 64-bit kernel.
	 */
	volatile u64 cmd;             	/* pointer to ctl[x] or NULL */
	/*
	 * The definition of dprio_ku_area is shared with the kernel.
	 */
	struct dprio_ku_area {
		/*
		 * Size of struct sched_attr may change in future definitions
		 * of the structure, therefore @sched_attr should come after
		 * @resp and @error in order to maintain the compatibility
		 * between the userland and the kernel built with different
		 * versions of struct sched_attr definition.
		 */
		volatile u32 resp;    	/* DPRIO_RESP_xxx */
		volatile u32 error;	/* one of errno values */
		volatile struct sched_attr sched_attr;
	} ctl[2];
};

/*
 * Userspace-kernel dprio protocol is as follows:
 *
 * Userspace:
 *
 *     Select and fill in idle dprio_ku_area:
 *         Set @resp = DPRIO_RESP_NONE.
 *         Set @sched_attr.
 *
 *     Set @cmd to point dprio_ku_area.
 *
 *     @cmd is u64 variable previously designated in the call
 *     prctl(PR_SET_DEFERRED_SETPRIO, & @cmd, ...)
 *
 * Kernel:
 *
 *     1) On task preemption attempt, read @cmd.
 *        If cannot (e.g. inaccessible incl. paged out), quit.
 *        Note: will reattempt again on next preemption cycle.
 *
 *     2) If read-in value of @cmd is 0, do nothing. Quit.
 *
 *     3) Set @resp = DPRIO_RESP_UNKNOWN.
 *        If cannot (e.g. inaccessible), quit.
 *
 *     4) Set @cmd = NULL.
 *        If cannot (e.g. inaccessible), quit.
 *        Note that in this case request handling will be reattempted on next
 *        thread preemption cycle. Thus DPRIO_RESP_UNKNOWN may be transient
 *        and be overwritten with DPRIO_RESP_OK or DPRIO_RESP_ERROR if @cmd
 *        is not reset to 0 by the kernel (or to 0 or to the address of another
 *        dprio_ku_area by the userspace).
 *
 *     5) Read @sched_attr.
 *        If cannot (e.g. inaccessible), quit.
 *
 *     6) Try to change task scheduling attributes in accordance with @sched_attr.
 *
 *     7) If successful, set @resp = DPRIO_RESP_OK and Quit.
 *
 *     8) If unsuccessful, set @error = appopriate errno-style value.
 *        If cannot (e.g. inaccessible), quit.
 *        Set @resp = DPRIO_RESP_ERROR.
 *        If cannot (e.g. inaccessible), quit.
 *
 * Explanation of possible @resp codes:
 *
 * DPRIO_RESP_NONE
 *
 *     Request has not been processed yet.
 *
 * DPRIO_RESP_OK
 *
 *     Request has been successfully processed.
 *
 * DPRIO_RESP_ERROR
 *
 *     Request has failed, @error has errno.
 *
 * DPRIO_RESP_UNKNOWN
 *
 *     Request processing has been attempted, but the outcome is unknown.
 *     Request might have been successful or failed.
 *     Current os-level thread priority becomes unknown.
 *
 *     @error field may be invalid.
 *
 *     This code is written to @resp at the start of request processing,
 *     then @resp is changed to OK or ERR at the end of request processing
 *     if dprio_ku_area and @cmd stay accessible for write.
 *
 *     This status code is never left visible to the userspace code in the
 *     current thread if dprio_ku_area and @cmd are locked in memory and remain
 *     properly accessible for read and write during request processing.
 *
 *     This status code might happen (i.e. stay visible to userspace code
 *     in the current thread) if access to dprio_ku_area or @cmd is lost
 *     during request processing, for example the page that contains the area
 *     gets swapped out or the area is otherwise not fully accessible for
 *     reading and writing.
 *
 *     If @error has value of DPRIO_RESP_UNKNOWN and @cmd is still pointing
 *     to dprio_ku_area containing @error, it is possible for the request to
 *     be reprocessed again at the next context switch and @error change to
 *     DPRIO_RESP_OK or DPRIO_RESP_ERROR. To ensure @error does not change
 *     under your feet, change @cmd to either NULL or address of another
 *     dprio_ku_area distinct from one containing this @error.
 */
enum {
	DPRIO_RESP_NONE     = 0,
	DPRIO_RESP_OK       = 1,
	DPRIO_RESP_ERROR    = 2,
	DPRIO_RESP_UNKNOWN  = 3
};

/*
 * @area	userland/kernel communication area
 *
 * @tg		thread group data
 *
 * @actual   	last actual known priority level
 * 		or -1 if not known
 *
 * @pending  	priority level of pending deferred setprio request
 * 		or -1 if not pending
 *
 * @ix		index of request area used by pending deferred setprio request
 *      	0 or 1 selects ku_area.ctl[ix]
 *      	-1 if not pending
 *
 * @errctx      user errctx for pending request
 *
 * @reset_on_fork	true if SCHED_FLAG_RESET_ON_FORK was in effect at the
 * 			time of dprio_init_thread
 */
struct __dprio_perthread {
	struct dprio_ku_ctlarea ku_area;
	struct __dprio_threadgroup *tg;
	int actual;
	int pending;
	int ix;
	unsigned long errctx;
	bool reset_on_fork;
};

/*****************************************************************************
*       		Module-local variables				     *
*****************************************************************************/

static pthread_once_t once_control = PTHREAD_ONCE_INIT;
static bool once_inited = false;
static pthread_key_t ctx_tls_key;

#ifdef DPRIO_STAT
struct dprio_stat dprio_stat __attribute__ ((aligned (8)));
#endif

/*****************************************************************************
*       		Logical priority levels                              *
*****************************************************************************/

static int validate_pl_pair(const struct sched_attr *pl1,
			    const struct sched_attr *pl2)
{
	int policy1 = pl1->sched_policy & ~SCHED_RESET_ON_FORK;
	int policy2 = pl2->sched_policy & ~SCHED_RESET_ON_FORK;

	switch (policy1) {
	case SCHED_IDLE:
	case SCHED_BATCH:
	case SCHED_NORMAL:
	case SCHED_RR:
	case SCHED_FIFO:
		break;

	default:
		return false;
	}

	switch (policy2) {
	case SCHED_IDLE:
		return policy1 == SCHED_IDLE;

	case SCHED_BATCH:
		if (policy1 == SCHED_IDLE)
			return true;
		if (policy1 != SCHED_BATCH)
			return false;
		return pl1->sched_nice >= pl2->sched_nice;

	case SCHED_NORMAL:
		if (policy1 == SCHED_IDLE)
			return true;
		if (policy1 != SCHED_BATCH && policy1 != SCHED_NORMAL)
			return false;
		return pl1->sched_nice >= pl2->sched_nice;

	case SCHED_RR:
	case SCHED_FIFO:
		if (policy1 != SCHED_RR && policy1 != SCHED_FIFO)
			return true;
		return pl1->sched_priority <= pl2->sched_priority;

	default:
		return false;
	}
}

/*
 * Validate the definitions of logical priority levels.
 *
 * Return true if they look sane.
 * Return false if they look incorrect, e.g. not in reasonably ascending order.
 */
int dprio_validate_pl(int minpl, int maxpl,
		      const struct sched_attr *plsched,
		      int* plbad)
{
	int pl, ret;

	if (minpl == maxpl) {
		ret = validate_pl_pair(plsched, plsched);
		if (!ret && plbad)
			*plbad = minpl;
		return ret;
	}

	if (!(maxpl >= minpl))
		return false;

	for (pl = minpl + 1;  pl <= maxpl;  pl++) {
		if (!validate_pl_pair(plsched + pl - 1 - minpl,
				      plsched + pl - minpl)) {
			if (plbad)
				*plbad = pl;
			return false;
		}
	}

	return true;
}

/*****************************************************************************
*       		Thread group descriptor				     *
*****************************************************************************/

static void once_init(void)
{
	if (0 == pthread_key_create(& ctx_tls_key, NULL))
		once_inited = true;
}

dprio_threadgroup_t dprio_alloc_threadgroup(
	int minpl, int maxpl,
	const struct sched_attr *plsched,
	dprio_onerror_proc_t onerror)
{
	dprio_threadgroup_t tg;

	if (!once_inited) {
		pthread_once(&once_control, once_init);
		if (!once_inited)
			return NULL;
	}

	if (maxpl < minpl)
		return NULL;

	tg = (dprio_threadgroup_t) malloc(sizeof *tg);

	if (tg) {
		tg->minpl = minpl;
		tg->maxpl = maxpl;
		tg->plsched = plsched;
		tg->onerror = onerror;
	}

	return tg;
}

void dprio_free_threadgroup(dprio_threadgroup_t tg)
{
	if (tg)
		free(tg);
}

/*****************************************************************************
*       		Perthread context set 				     *
*****************************************************************************/

dprio_perthread_set_t dprio_alloc_perthread_set(
	unsigned int count,
	unsigned int *alloc_count,   /* optional */
	size_t struct_size,
	int flags,
	int *locked)                 /* optional */
{
	dprio_perthread_set_t pset;

	size_t alloc_size;
	long pagesize;
	long perpage;
	long npages;
	void* pv;
	int align;

	/* default size to non-extended structure */
	if (struct_size < sizeof(struct __dprio_perthread))
		struct_size = sizeof(struct __dprio_perthread);

	/* make sure structures in the set will be nicely aligned */
	align = __alignof__(struct __dprio_perthread);
	if (align < sizeof(u64))
		align = sizeof(u64);
	struct_size = ROUNDUP(struct_size, align);

	/* system page size */
	pagesize = sysconf(_SC_PAGESIZE);
	if (pagesize <= 0)
		pagesize = getpagesize();
	if (pagesize <= 0)
		return NULL;

	/* structs per page */
	perpage = pagesize / struct_size;
	if (perpage < 1)
		return NULL;

	/* number of pages required and total allocation size */
	npages = count / perpage + ((count % perpage) ? 1 : 0);
	alloc_size = npages * pagesize;

	/* allocate set descriptor */
	pset = (dprio_perthread_set_t) malloc(sizeof(*pset));
	if (pset == NULL)
		return NULL;

	/* allocate pages for the structures */
	pv = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
		  MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
		  -1, 0);
	if (pv == MAP_FAILED) {
		free(pset);
		return NULL;
	}

	/* try to lock pages in memory */
	if (locked)
		*locked = false;
	if (flags & (DPRIO_ALLOC_MLOCK | DPRIO_ALLOC_TRY_MLOCK)) {
		if (0 == mlock(pv, alloc_size)) {
			if (locked)
				*locked = true;
		} else if (flags & DPRIO_ALLOC_MLOCK) {
			munmap(pv, alloc_size);
			free(pset);
			return NULL;
		}
	}

	pset->alloc_size = alloc_size;
	pset->pv = pv;
	pset->perpage = (unsigned int) perpage;
	pset->pagesize = (unsigned int) pagesize;
	pset->struct_size = struct_size;
	pset->alloc_count = (unsigned int) (npages * perpage);

	if (alloc_count)
		*alloc_count = pset->alloc_count;

	return pset;
}

void dprio_free_perthread_set(dprio_perthread_set_t pset)
{
	if (pset) {
		munmap(pset->pv, pset->alloc_size);
		free(pset);
	}
}

dprio_perthread_t dprio_get_perthread(
	dprio_perthread_set_t pset,
	unsigned int index)
{
	char *p;

	if (index >= pset->alloc_count)
		return NULL;

	p = pset->pv;
	p += pset->pagesize * (index / pset->perpage);
	p += pset->struct_size * (index % pset->perpage);

	return (dprio_perthread_t) p;
}

/*****************************************************************************
*       		  Perthread context 				     *
*****************************************************************************/

static __always_inline dprio_perthread_t getctx(void)
{
	return (dprio_perthread_t) pthread_getspecific(ctx_tls_key);
}

int dprio_init_thread(dprio_perthread_t ctx, dprio_threadgroup_t tg)
{
	const struct sched_attr** pp;
	struct sched_attr attr;
	int error;
	unsigned k, plcount = tg->maxpl - tg->minpl + 1;

	memset(&attr, 0, sizeof attr);
	attr.size = sizeof(attr);
	if (sched_getattr(0, &attr, attr.size, 0))
		return -1;

	ctx->ku_area.cmd = 0;
	ctx->tg = tg;
	ctx->actual = -1;
	ctx->pending = -1;
	ctx->ix = -1;
	ctx->reset_on_fork = !!(attr.sched_flags & SCHED_FLAG_RESET_ON_FORK);

	pp = alloca(sizeof(struct sched_attr*) * plcount);
	if (pp == NULL) {
		errno = ENOMEM;
		return -1;
	}

	for (k = 0;  k < plcount;  k++)
		pp[k] = tg->plsched + k;

	if (error = pthread_setspecific(ctx_tls_key, ctx)) {
		errno = error;
		return -1;
	}

	return prctl(PR_SET_DEFERRED_SETPRIO, &ctx->ku_area.cmd, pp, plcount, 0);
}

void dprio_uninit_thread(void)
{
	if (once_inited)
		pthread_setspecific(ctx_tls_key, NULL);
	prctl(PR_SET_DEFERRED_SETPRIO, 0, 0, 0, 0);
}

/*****************************************************************************
*       		  Actual DPRIO code 				     *
*****************************************************************************/

int dprio_get(void)
{
	dprio_perthread_t ctx = getctx();
	dprio_threadgroup_t tg = ctx->tg;
	if (ctx->pending >= 0)
		return ctx->pending;
	return ctx->actual;
}

static int setprio(int pl, dprio_perthread_t ctx)
{
	dprio_threadgroup_t tg = ctx->tg;
	struct sched_attr attr;
	int rc;

	if (! (pl >= tg->minpl && pl <= tg->maxpl)) {
		errno = EINVAL;
		return -1;
	}

	attr = tg->plsched[pl - tg->minpl];
	if (ctx->reset_on_fork)
		attr.sched_flags |= SCHED_FLAG_RESET_ON_FORK;

	do {
		rc = sched_setattr(0, &attr, 0);
	} while (rc == -1 && errno == EINTR);

#ifdef DPRIO_STAT
	__sync_fetch_and_add(&dprio_stat.actual_setprio, 1);
#endif

	return rc;
}

static void __always_inline set_cmd(struct dprio_ku_ctlarea *ku, struct dprio_ku_area *sa)
{
	barrier();
	* (volatile struct dprio_ku_area **) &ku->cmd = sa;
	barrier();
}

static inline void set_req(dprio_perthread_t ctx, int pl, unsigned long errctx)
{
	int ix;

	switch (ctx->ix) {
	case 0:
		ix = 1;
		break;
	case -1:
	case 1:
		ix = 0;
		break;

	default:
		bugcheck();
		return;
	}

	ctx->ku_area.ctl[ix].error = 0;
	ctx->ku_area.ctl[ix].resp = DPRIO_RESP_NONE;
	ctx->ku_area.ctl[ix].sched_attr = ctx->tg->plsched[pl - ctx->tg->minpl];
	ctx->pending = pl;
	ctx->ix = ix;
	ctx->errctx = errctx;
	set_cmd(&ctx->ku_area, &ctx->ku_area.ctl[ix]);
}

static inline void setnow(int pl, unsigned long errctx)
{
	if (dprio_setnow(pl, DPRIO_FORCE | DPRIO_NOSTAT))
		getctx()->tg->onerror(errno, pl, errctx, pl, errctx, false);
}

static u32 get_resp(struct dprio_ku_area *ctl)
{
	return ctl->resp;
}

static void handle_unknown(dprio_perthread_t ctx,
			   int err_pl, unsigned long err_errctx,
			   int new_pl, unsigned long new_errctx)
{
	dprio_threadgroup_t tg = ctx->tg;

	set_cmd(&ctx->ku_area, NULL);
	ctx->actual = -1;
	ctx->pending = -1;
	ctx->ix = -1;

	if (tg->onerror(EWOULDBLOCK,
			err_pl, err_errctx,
			new_pl, new_errctx, true))
		setnow(new_pl, new_errctx);
}

/*
 * Check if @pl is in the same relation to @actual,
 * as @peninging to @actual
 */
static inline bool same_relationship(int actual, int pending, int pl)
{
	if (pending == actual)
		return pl == actual;
	else if (pending > actual)
		return pl > actual;
	else /* if (pending < actual) */
		return pl < actual;
}

/*
 * Check if two different logical priority levels @p1 and @p2 have actually the
 * same sched_attr definition. This is to avoid system call overhead in case
 * application defines two or more adjacent logical priority levels to have
 * the same sched_attr value.
 *
 * TODO: It would be nicer to figure out the equality relationship
 *       at init time.
 */
static bool equal_pl(dprio_perthread_t ctx, int p1, int p2)
{
	dprio_threadgroup_t tg = ctx->tg;
	const struct sched_attr *a1, *a2;

	if (! (p1 >= tg->minpl && p1 <= tg->maxpl))
		return false;

	if (! (p2 >= tg->minpl && p2 <= tg->maxpl))
		return false;

	if (p1 == p2)
		return true;

	a1 = &tg->plsched[p1 - tg->minpl];
	a2 = &tg->plsched[p2 - tg->minpl];

	if (a1->sched_policy != a2->sched_policy)
		return false;

	switch (a1->sched_policy) {
	case SCHED_NORMAL:
	case SCHED_BATCH:
		return a1->sched_nice == a2->sched_nice;

	case SCHED_FIFO:
	case SCHED_RR:
		return a1->sched_priority == a2->sched_priority;

	case SCHED_DEADLINE:
		return 	a1->sched_runtime == a2->sched_runtime &&
			a1->sched_deadline == a2->sched_deadline &&
			a1->sched_period == a2->sched_period;

	case SCHED_IDLE:
		return true;

	default:
		return false;
	}
}

/*
 * Set real (os-level) thread priority
 *
 * If @flags contains DPRIO_FORCE, then disregard all cached state and
 * reinitialize it. This may be helpful (1) if thread priority has been changed
 * directly with system call (either by the thread itself or other thread/task)
 * bypassing dprio_xxx routines, so cached dprio state is invalid; or (2) if
 * knowledge of current priority level has been lost due to errors.
 *
 * If DPRIO_FORCE is not specified, change thread priority only if @pl is different
 * from the last actually-known set pl.
 *
 * At the exit from this function cached priority is supposed to be identical to
 * real os-level priority and there is no pending "deferred set priority" request.
 */
int dprio_setnow(int pl, unsigned int flags)
{
	dprio_perthread_t ctx = getctx();
	dprio_threadgroup_t tg = ctx->tg;
	volatile resp;
	bool force = false;
	struct dprio_ku_area *ctl;
	int prev_pending = ctx->pending;
	unsigned long prev_errctx = ctx->errctx;

#ifdef DPRIO_STAT
	if (! (flags & DPRIO_NOSTAT))
		__sync_fetch_and_add(&dprio_stat.dprio_setnow, 1);
#endif

	if (! (pl >= tg->minpl && pl <= tg->maxpl)) {
		errno = EINVAL;
		return -1;
	}

	set_cmd(&ctx->ku_area, NULL);

	if (flags & DPRIO_FORCE) {
		force = true;
	} else if (ctx->pending != -1) {
		ctl = &ctx->ku_area.ctl[ctx->ix];
		switch (resp = get_resp(ctl)) {
		case DPRIO_RESP_NONE:
			/* do nothing */
			break;

		case DPRIO_RESP_OK:
			ctx->actual = ctx->pending;
			break;

		case DPRIO_RESP_ERROR:
			ctx->pending = -1;
			if (! tg->onerror(ctl->error,
					  prev_pending, prev_errctx,
					  pl, DPRIO_NO_ERRCTX, true)) {
				/* onerror took corrective action */
				return 0;
			}
			break;

		case DPRIO_RESP_UNKNOWN:
			ctx->actual = -1;
			ctx->pending = -1;
			if (! tg->onerror(EWOULDBLOCK,
					  prev_pending, prev_errctx,
					  pl, DPRIO_NO_ERRCTX, true)) {
				/* onerror took corrective action */
				return 0;
			}
			break;

		default:
			bugcheck();
			break;
		}
	}

	ctx->pending = -1;
	ctx->ix = -1;

	if (!force) {
		if (pl == ctx->actual)
			return 0;

		if (equal_pl(ctx, pl, ctx->actual)) {
			ctx->actual = pl;
			return 0;
		}
	}

	if (setprio(pl, ctx)) {
		return -1;
	} else {
		ctx->actual = pl;
		return 0;
	}
}

/*
 * Request to set thread priority level to @pl.
 * Priority change will be performed asynchronously, when and only if needed.
 * Errors will be reported asynchronously via @onerror callback 	    .
 * The value of @errctx will be passed to the callback.     								    .
 */
void dprio_set(int pl, unsigned long errctx)
{
	dprio_perthread_t ctx = getctx();
	dprio_threadgroup_t tg = ctx->tg;
	struct dprio_ku_area *ctl, *ctlx;
	volatile int resp;
	int pass;

#ifdef DPRIO_STAT
	__sync_fetch_and_add(&dprio_stat.dprio_set, 1);
#endif

	int prev_ix = ctx->ix;
	int prev_pending = ctx->pending;
	unsigned long prev_errctx = ctx->errctx;

	if (! (pl >= tg->minpl && pl <= tg->maxpl)) {
		tg->onerror(EINVAL, pl, errctx, pl, errctx, false);
	}

	/*
	 * Actual current priority level is not known
	 */
	else if (ctx->actual < 0) {
		if (setprio(pl, ctx))
			tg->onerror(errno, pl, errctx, pl, errctx, false);
		else {
			ctx->actual = pl;
			ctx->pending = -1;
		}
	}

	/*
	 * Actual current priority level is known,
	 * and there is no pending deferred request
	 */
	else if (ctx->pending < 0) {
		if (pl == ctx->actual)
			/* do nothing */ ;
		else if (equal_pl(ctx, pl, ctx->actual))
			ctx->actual = pl;
		else if (pl > ctx->actual)
			set_req(ctx, pl, errctx);
		else if (pl < ctx->actual) {
			if (0 == setprio(pl, ctx))
				ctx->actual = pl;
			else
				tg->onerror(errno, pl, errctx, pl, errctx, false);
		}
	}

	/*
	 * In all the cases below actual current priority level is known,
	 * and there also was pending deferred setprio request (either
	 * still pending or possibly already processed).
	 *
	 * Nodes in the diagrams below are (left to right):
	 *     last known actual pl, pending pl, pl.
	 *
	 * Pending request may have already been processed or not.
	 */

	else if (pl == ctx->pending) {
		ctl = &ctx->ku_area.ctl[ctx->ix];
		pass = 0;

again_10:
		/*
		 * Use accessor function and extra assignment to reduce the
		 * probability of hitting volatile bugs in the compiler.
		 * See "Volatiles are miscompiled, and what to do about it".
		 * http://dl.acm.org/citation.cfm?id=1450093
		 */
		switch (resp = get_resp(ctl)) {
		case DPRIO_RESP_NONE:
			/* do nothing */
			break;

		case DPRIO_RESP_OK:
			ctx->actual = ctx->pending;
			ctx->pending = -1;
			break;

		case DPRIO_RESP_ERROR:
			ctx->pending = -1;
			tg->onerror(ctl->error,
				    prev_pending, prev_errctx,
				    pl, errctx, false);
			break;

		case DPRIO_RESP_UNKNOWN:
			if (pass++ == 0) {
				set_cmd(&ctx->ku_area, NULL);
				goto again_10;
			}
			handle_unknown(ctx, prev_pending, prev_errctx, pl, errctx);
			break;

		default:
			bugcheck();
			break;
		}
	}

	else if (same_relationship(ctx->actual, ctx->pending, pl) &&
		 equal_pl(ctx, pl, ctx->pending)) {
		ctx->pending = pl;
	}

	else if (ctx->pending > ctx->actual && pl > ctx->pending) {
		/*
		 *         *
		 *        /
		 *       /
		 *      *
		 *     /
		 *    /
		 *   *
		 */

		set_req(ctx, pl, errctx);

		ctl = &ctx->ku_area.ctl[prev_ix];

		switch (resp = get_resp(ctl)) {
		case DPRIO_RESP_NONE:
			/* do nothing */
			break;

		case DPRIO_RESP_OK:
			ctx->actual = prev_pending;
			break;

		case DPRIO_RESP_ERROR:
			if (tg->onerror(ctl->error,
					prev_pending, prev_errctx,
					pl, errctx, true))
				setnow(pl, errctx);
			break;

		case DPRIO_RESP_UNKNOWN:
			handle_unknown(ctx, prev_pending, prev_errctx, pl, errctx);
			break;

		default:
			bugcheck();
			break;
		}
	}

	else if (ctx->pending > ctx->actual && pl == ctx->actual) {
		/*
		 *      *
		 *     / \
		 *    /   \
		 *   /     \
		 *  *.......*
		 */

		set_cmd(&ctx->ku_area, NULL);
		ctx->pending = -1;

		ctl = &ctx->ku_area.ctl[prev_ix];

		switch (resp = get_resp(ctl)) {
		case DPRIO_RESP_NONE:
			/* do nothing */
			break;

		case DPRIO_RESP_OK:
			setnow(pl, errctx);
			break;

		case DPRIO_RESP_ERROR:
			tg->onerror(ctl->error,
				    prev_pending, prev_errctx,
				    pl, errctx, true);
			break;

		case DPRIO_RESP_UNKNOWN:
			handle_unknown(ctx, prev_pending, prev_errctx, pl, errctx);
			break;

		default:
			bugcheck();
			break;
		}
	}

	else if (ctx->pending > ctx->actual &&
		 pl > ctx->actual && pl < ctx->pending) {
		/*
		 *      *
		 *     / \
		 *    /...*
		 *   /
		 *  *
		 */

		set_req(ctx, pl, errctx);

		ctl = &ctx->ku_area.ctl[prev_ix];

		switch (resp = get_resp(ctl)) {
		case DPRIO_RESP_NONE:
			/* do nothing */
			break;

		case DPRIO_RESP_OK:
			set_cmd(&ctx->ku_area, NULL);
			ctlx = &ctx->ku_area.ctl[ctx->ix];
again_20:
			switch (resp = get_resp(ctlx)) {
			case DPRIO_RESP_NONE:
				setnow(pl, errctx);
				break;

			case DPRIO_RESP_OK:
				ctx->actual = pl;
				ctx->pending = -1;
				break;

			case DPRIO_RESP_ERROR:
				ctx->actual = prev_pending;
				ctx->pending = -1;
				tg->onerror(ctlx->error, pl, errctx, pl, errctx, false);
				break;

			case DPRIO_RESP_UNKNOWN:
				if (pass++ == 0) {
					set_cmd(&ctx->ku_area, NULL);
					goto again_20;
				}
				handle_unknown(ctx, pl, errctx, pl, errctx);
				break;

			default:
				bugcheck();
				break;
			}
			break;

		case DPRIO_RESP_ERROR:
			if (tg->onerror(ctl->error,
					prev_pending, prev_errctx,
					pl, errctx, true))
				setnow(pl, errctx);
			break;

		case DPRIO_RESP_UNKNOWN:
			handle_unknown(ctx, prev_pending, prev_errctx, pl, errctx);
			break;

		default:
			bugcheck();
			break;
		}
	}

	else if (ctx->pending > ctx->actual && pl < ctx->actual) {
		/*
		 *      *
		 *     / \
		 *    *...\
		 *         \
		 *          *
		 */

		setnow(pl, errctx);
	}

	else if (0 && ctx->pending < ctx->actual &&
		 pl > ctx->pending && pl < ctx->actual) {
		/*
		 *  *
		 *   \
		 *    \...*
		 *     \ /
		 *      *
		 */

		/*
		 * This pattern does not happen.
		 *
		 * Downslope as the previous step is not possible.
		 *
		 * If @pending were less than @actual, this would cause
		 * immediate lowering of real task priority during the previous
		 * step, with resuling actual = pl, pending = -1, so we would
		 * never be here.
		 *
		 * Same holds for other previous-downslope patterns below.
		 */
	}

	else if (0 && ctx->pending < ctx->actual && pl < ctx->pending) {
		/*
		 *  *
		 *   \
		 *    \
		 *     *
		 *      \
		 *       \
		 *        *
		 */

		/*
		 * This pattern does not happen.
		 */
	}

	else if (0 && ctx->pending < ctx->actual && pl == ctx->actual) {
		/*
		 *  *.......*
		 *   \     /
		 *    \   /
		 *     \ /
		 *      *
		 */

		/*
		 * This pattern does not happen.
		 */
	}

	else if (0 && ctx->pending < ctx->actual && pl > ctx->actual) {
		/*
		 *          *
		 *         /
		 *    *.../
		 *     \ /
		 *      *
		 */

		/*
		 * This pattern does not happen.
		 */
	}

	else {
		bugcheck();
	}
}

