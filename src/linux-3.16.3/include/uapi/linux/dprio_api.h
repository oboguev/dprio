/*
 * Deferred set priority.
 *
 * This file contains the defitions for dprio(2) userspace-kernel interface.
 */

#ifndef _UAPI_LINUX_DPRIO_API_H
#define _UAPI_LINUX_DPRIO_API_H

#ifndef __KERNEL__
  #include <linux/types.h>
  #include <sched.h>
#endif

/*
 * Userspace-kernel dprio protocol is as follows:
 *
 * Userspace:
 *
 *     Select and fill-in dprio_ku_area:
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
 *     1) On task preemption attempt or at other processing point,
 *        such as fork or exec, read @cmd.
 *        If cannot (e.g. @cmd inaccessible incl. page swapped out), quit.
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
 *        thread preemption cycle. Thus @resp value of DPRIO_RESP_UNKNOWN may
 *        be transient and overwritten with DPRIO_RESP_OK or DPRIO_RESP_ERROR
 *        if @cmd is not reset to 0 by the kernel (or to 0 or to the address
 *        of another dprio_ku_area by the userspace).
 *
 *     5) Read @sched_attr.
 *        If cannot (e.g. inaccessible), quit.
 *
 *     6) Try to change task scheduling attributes in accordance with read-in
 *        value of @sched_attr.
 *
 *     7) If successful, set @resp = DPRIO_RESP_OK and Quit.
 *
 *     8) If unsuccessful, set @error = appopriate errno-style value.
 *        If cannot (e.g. @error inaccessible), quit.
 *        Set @resp = DPRIO_RESP_ERROR.
 *        If cannot (e.g. @resp inaccessible), quit.
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
 *     Request has failed, @error has errno-style error code.
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
 * It is up to the client access methods whether it will want to define
 * strucutre elements as volatile.
 */
#ifndef __dprio_volatile
  #define __dprio_volatile
#endif

struct dprio_ku_area {
	/*
	 * Size of struct sched_attr may change in future definitions
	 * of the structure, therefore @sched_attr should come after
	 * @resp and @error in order to maintain the compatibility
	 * between userland and kernel built with different versions
	 * of struct sched_attr definition.
	 *
	 * Userland code should use volatile and/or compiler barriers
	 * to ensure the protocol.
	 */
	__dprio_volatile __u32 resp;		/* DPRIO_RESP_xxx */
	__dprio_volatile __u32 error;		/* one of errno values */
	__dprio_volatile struct sched_attr sched_attr;
};

#endif /* _UAPI_LINUX_DPRIO_API_H */

