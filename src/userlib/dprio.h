/*
 * DPRIO (deferred set priority) userspace functions definitions.
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

#ifndef __USERLIB_DPRIO_H__
#define __USERLIB_DPRIO_H__

/*
 * Userland side library for "deferred set priority" system facility.
 *
 * Use sequence:
 *
 *      dprio_threadgroup_t tg = dprio_alloc_threadgroup(...);
 *      dprio_perthread_set_t pset = dprio_alloc_perthread_set(...);
 *
 *      in each thread:
 *
 *		dprio_perthread_t ctx = dprio_get_perthread(pset, index);
 *      	dprio_init_thread(ctx, tg);
 *      	....
 *      	dprio_setnow(pl);
 *      	dprio_set(pl, errctx);
 *      	[repeat dprio_set and dprio_setnow]
 *      	....
 *      	dprio_uninit_thread();
 *
 *      wait till threads terminate
 *
 *      dprio_free_perthread_set(pset);
 *      dprio_free_threadgroup(tg);
 *
 * Two caveats the client of DPRIO library needs to be aware of are related to
 * the very nature of DPRIO library as "caching" the thread priority setting
 * in the userspace:
 *
 * (a) sched_getattr(2), sched_getparam(2) and sched_getscheduler(2) return
 *     current OS-level thread scheduling policy and priority setting for the
 *     thread, that is very likely to be different from thread’s current
 *     logical priority cached in the userspace which, after all, is intended
 *     in most cases not to be propagated to the kernel.
 *
 * (b) DPRIO user-level library tracks the latest thread priority setting it
 *     propagated to the kernel and makes its caching behavior decisions based
 *     on the knowledge of this setting held inside the library. The library
 *     assumes its knowledge accurately represents kernel-level thread priority
 *     setting.
 *
 *     Direct sched_setattr(2), sched_setparam(2) and sched_setscheduler(2)
 *     executed for the application thread either by the application itself or
 *     by an external process will invalidate this knowledge. If such an
 *     invalidation happens, it is the responsibility of the application to
 *     execute library method dprio_setnow(pl, DPRIO_FORCE) to resync
 *     kernel-level thread priority setting with the library-cached state and
 *     application’s idea what the thread’s priority should be.
 *
 * The client of user-level DPRIO library must also be careful about
 * SCHED_RESET_ON_FORK flag, since in addition to issuing DPRIO requests the
 * library may invoke sched_setattr(2) directly, which will fail if priority
 * level descriptor passed to it does not have SCHED_FLAG_RESET_ON_FORK set.
 * The library tries to mitigate this issue by checking if SCHED_RESET_ON_FORK
 * was set at the time of thread initialization for the library, and if so
 * merging SCHED_FLAG_RESET_ON_FORK into subsequent requests to sched_setattr(2),
 * however if SCHED_RESET_ON_FORK is set subsequently to calling
 * dprio_init_thread, then library caller is responsible for managing the state
 * of SCHED_FLAG_RESET_ON_FORK in definitions of logical priority levels.
 */

#include "sched_attr.h"

/* Opaque data types */
typedef struct __dprio_threadgroup *dprio_threadgroup_t;
typedef struct __dprio_perthread_set *dprio_perthread_set_t;
typedef struct __dprio_perthread *dprio_perthread_t;

/*
 * "On error" callback definition.
 *
 * May be invoked in response to dprio_set or dprio_setnow when they detect
 * that either current or previous request to set priority failed.
 *
 * In case of dprio_setnow the call is only for previous failures.
 * Errors for current request via dprio_setnow are reported via return
 * status of dprio_setnow and errno.
 *
 * @error	The cause for failure, errno-style.
 *      	EWOULDBLOCK means that ku comminication area was paged
 *      	out or partially inaccessible (bad mapping).
 *
 * @err_pl	Priority level requested that caused the error to happen.
 *
 * @err_errctx  @errctx that was specified in the call to dprio_set for
 * 		@err_pl
 *
 * @new_pl	Priority level that application currently desires to set.
 *
 * @new_errctx  If @new_pl results from dprio_set, then @errctx specified
 *      	in this dprio_set call. Otherwise if @new_pl results from
 *      	dprio_setnow, then DPRIO_NO_ERRCTX.
 *
 * @recoverable Indicates whether dprio library can automatically recover
 * 		to @new_pl.
 *
 * If @recoverable is true and onerror function returns true, dprio library
 * will attempt automatic recovery on return from onerror handler by trying
 * to set task priority to @new_pl. In case of recovery attempt failure,
 * onerror procedure will be invoked again, this time with @recovery set to
 * false.
 *
 * If onerror procedure returns false, dprio library will not try to
 * perform automatic recovery. It is a reponsibility of the application then
 * to perform whatever corrective steps it finds necessary.
 */
typedef int (*dprio_onerror_proc_t)(
	int error,
	int err_pl, unsigned long err_errctx,
	int new_pl, unsigned long new_errctx,
	int recoverable
);

#define DPRIO_NO_ERRCTX ((unsigned long) (long) -2)


/*
 * Validate the definitions of logical priority levels.
 *
 * Return true if they look sane.
 * Return false if they look incorrect, e.g. not in reasonably ascending order.
 */
int dprio_validate_pl(int minpl, int maxpl,
		      const struct sched_attr *plsched,
		      int* plbad);


/*
 * Allocate thread group descriptor.
 *
 * Threads in the group share common definition of priority levels
 * and "onerror" callback.
 *
 * @minpl	Minimum logical priority level
 *
 * @maxpl	Maximum logical priority level
 *
 * @plsched     Logical priority levels mapping to their definitions
 * 		in sched_attr format. plsched[0] corresponds to minpl.
 *      	Array size is (maxpl - minpl + 1).
 *
 *      	For the application to perform in a meaningful way,
 *      	mapping of priority levels to OS-level scheduling attributes
 *      	must be defined in an increasing order, i.e. if pl2 >= pl1,
 *      	plsched for pl2 must be >= plsched for pl1:
 *
 *      	    (plsched[pl2 - minpl + 1] >= plsched[pl1 - minpl + 1])
 *
 *      	It is acceptable for adjacent logical priority level
 *      	to translate to the same OS-level priority, the library will
 *      	understand this and properly handle such level definitions.
 *      	However you do not want to define higher logical pl map to a
 *      	lower OS-level priority.
 *
 * @onerror     Callback routine to be called when dprio_set results in
 *      	an error. This callback is invoked some time after
 *      	the failing dprio_set, when an error is spotted during
 *      	a subsequebnt dprio_set call.
 *
 * On failure returns NULL.
 */
dprio_threadgroup_t dprio_alloc_threadgroup(
	int minpl, int maxpl,
	const struct sched_attr *plsched,
	dprio_onerror_proc_t onerror);

/*
 * Deallocate previously allocated thread group descriptor.
 */
void dprio_free_threadgroup(dprio_threadgroup_t tg);

/*
 * Allocate a set of perthread dprio context structures.
 *
 * Each thread utilizing "deferred set priority" facility, i.e. calling
 * dprio_set(...) or dprio_setnow(...) must have a dprio context associated
 * first with the thread.
 *
 * dprio_alloc_perthread(...) allocates a set of @count perthread dprio context
 * structures that can later be bound to threads. Structures in the allocated
 * set are properly aligned and do not cross page boundary.
 *
 * Note that the allocated set is _not_ an array of structures. Use
 * dprio_get_perthread(...) to access the set element.
 *
 * @count	Number of structures to be allocated.
 *
 * @alloc_count	Number of structures actually allocated. The number of actually
 *      	allocated structures may exceed @count. The caller may pass NULL
 *      	if not interested to learn the number of actually allocated
 *      	structures.
 *
 * @struct_size Size of the context structure. If 0, parameter value defaults to
 * 		sizeof(struct __dprio_perthread).
 *
 * @flags	DPRIO_ALLOC_MLOCK indicates that allocated pages must be locked
 *      	in memory. If dprio_alloc_perthread_set is unable to lock the
 *      	allocated pages, it will fail and return NULL. If it were able to
 *      	lock the pages, *@locked will be set to true.
 *
 *      	DPRIO_ALLOC_TRY_MLOCK requests dprio_alloc_perthread_set to try
 *      	locking the allocated pages in memory. If dprio_alloc_perthread_set
 *      	is unable to lock the allocated pages, it will set *@locked to false.
 *      	If pages are successfully locked, *@locked is set to true.
 *
 * @locked	Set to true if pages have been successfully locked in memory,
 *      	false otherwise. Caller may pass NULL if not intersted in the
 *      	outcome.
 *
 * On failure returns NULL.
 */
dprio_perthread_set_t dprio_alloc_perthread_set(
	unsigned int count,
	unsigned int *alloc_count,   /* optional, may be NULL */
	size_t struct_size,
	int flags,
	int *locked);                /* optional, may be NULL */
#define DPRIO_ALLOC_MLOCK 	(1 << 0)
#define DPRIO_ALLOC_TRY_MLOCK 	(1 << 1)

/*
 * Deallocate previously allocated set of dprio perthread context structures.
 */
void dprio_free_perthread_set(dprio_perthread_set_t);

/*
 * Get an element from the previously allocated set of perthread structures.
 * @index is in range [0 ... @count - 1] or [0 ... *@alloc_count - 1]      .
 * If @index is incorrect, will return NULL.     								   .
 */
dprio_perthread_t dprio_get_perthread(dprio_perthread_set_t pset, unsigned int index);

/*
 * Initialize thread for using dprio.
 * On success will return 0         .
 * In error will return -1 and errno will be set accordingly.     			    .
 */
int dprio_init_thread(dprio_perthread_t ctx, dprio_threadgroup_t tg);

/*
 * Uninitialize thread after dprio_init_thread(...).
 */
void dprio_uninit_thread(void);

/*
 * Set real (os-level) thread priority
 *
 * If @flags contains DPRIO_FORCE, then disregard all cached state and
 * reinitialize it. This may be helpful (1) if thread priority has been changed
 * directly with a system call (either by the thread itself or other thread/task)
 * bypassing dprio_xxx routines, so cached dprio state is invalid; or (2) if
 * the knowledge of current priority level has been lost due to errors.
 *
 * If DPRIO_FORCE is not specified, change thread priority only if @pl is different
 * from the last actually-known set pl.
 *
 * At the exit from this function cached priority is supposed to be identical to
 * real os-level priority and there is no pending "deferred set priority" request.
 */
int dprio_setnow(int pl, unsigned int flags);

#define DPRIO_FORCE	(1 << 0)
#define DPRIO_NOSTAT	(1 << 1)	/* disable statistics */

/*
 * Request to set thread priority level to @pl.
 * Priority change will be performed asynchronously, when and only if needed.
 * Errors will be reported asynchronously via @onerror callback 	    .
 * The value of @errctx will be passed to the callback.     								    .
 */
void dprio_set(int pl, unsigned long errctx);

/*
 * Return current logical priority level.
 *
 * This level may have already been propagated to os-level task setting or
 * pending in the buffer to be set. In the latter case there is a possibility
 * an attempt to set priority level may still fail.
 *
 * May return -1 if current logical priority level is unknown.
 */
int dprio_get(void);

#ifdef DPRIO_STAT
extern struct dprio_stat {
	unsigned long dprio_set;
	unsigned long dprio_setnow;
	unsigned long actual_setprio;
} dprio_stat;
#endif

#endif

