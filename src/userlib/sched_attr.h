/*
 * This file is needed only until sched_attr related definitions are proivded
 * in regular glibc or Linux user-level public header files
 */

#ifndef __USERLIB_SCHED_H__
#define __USERLIB_SCHED_H__

#include <unistd.h>
#include <sched.h>
#include <linux/sched.h>
#include <sys/syscall.h>

typedef int32_t s32;
typedef uint32_t u32;
typedef uint64_t u64;

#ifndef SCHED_DEADLINE
  #define SCHED_DEADLINE  6
#endif

#ifndef SCHED_FLAG_RESET_ON_FORK

struct sched_attr {
	u32 size;

	u32 sched_policy;
	u64 sched_flags;

	/* SCHED_NORMAL, SCHED_BATCH */
	s32 sched_nice;

	/* SCHED_FIFO, SCHED_RR */
	u32 sched_priority;

	/* SCHED_DEADLINE */
	u64 sched_runtime;
	u64 sched_deadline;
	u64 sched_period;
};

#define SCHED_FLAG_RESET_ON_FORK	0x01

/* x86-64 specific */
#if !defined(__NR_sched_setattr) && defined(__x86_64__)
  #define __NR_sched_setattr 	314
#endif

/* x86-64 specific */
#if !defined(__NR_sched_getattr) && defined(__x86_64__)
  #define __NR_sched_getattr 	315
#endif

/* x86-32 specific */
#if !defined(__NR_sched_setattr) && defined(__i386__)
  #define __NR_sched_setattr 	351
#endif

/* x86-32 specific */
#if !defined(__NR_sched_getattr) && defined(__i386__)
  #define __NR_sched_getattr 	352
#endif

#ifndef SYS_sched_getattr
  #define SYS_sched_getattr 	__NR_sched_getattr
#endif

#ifndef SYS_sched_setattr
  #define SYS_sched_setattr 	__NR_sched_setattr
#endif

static inline int sched_getattr(pid_t pid, const struct sched_attr *attr,
				unsigned int size, unsigned int flags)
{
	return syscall(SYS_sched_getattr, pid, attr, size, flags);
}

static inline int sched_setattr(pid_t pid, const struct sched_attr *attr,
				unsigned int flags)
{
	return syscall(SYS_sched_setattr, pid, attr, flags);
}

#endif /* SCHED_FLAG_RESET_ON_FORK */
#endif /* __USERLIB_SCHED_H__ */

