/*
 * include/linux/authlist.h
 *
 * Authorization list.
 *
 * Started by (C) 2014 Sergey Oboguev <oboguev@yahoo.com>
 *
 * This code is licenced under the GPL version 2 or later.
 * For details see linux-kernel-base/COPYING.
 */

#ifndef _LINUX_AUTHLIST_H
#define _LINUX_AUTHLIST_H

#include <linux/uidgid.h>
#include <linux/rwsem.h>

/*
 * String representation of authorization list is a sequence of
 * whitespace-separated entries in the format
 *
 *     uid:<numeric-uid>
 *     gid:<numeric-gid>
 *     nouid:<numeric-uid>
 *     nogid:<numeric-gid>
 *     everybody
 *     nobody
 *
 * For instance:
 *
 *     uid:47  uid:100  gid:12  nobody
 * or
 *
 *     nogid:300  everybody
 *
 * Terminal entry must be either "nobody" or "everybody".
 */

/*
 * Define types of entries in the list.
 *
 * AUTHLIST_KIND_EVERYBODY or AUTHLIST_KIND_NOBODY must be the
 * terminal entry.
 */
enum authlist_kind {
	AUTHLIST_KIND_UID = 0,		/* allow UID */
	AUTHLIST_KIND_GID,		/* allow GID */
	AUTHLIST_KIND_NOUID,		/* disallow UID */
	AUTHLIST_KIND_NOGID,		/* disallow GID */
	AUTHLIST_KIND_EVERYBODY,	/* allow everybody */
	AUTHLIST_KIND_NOBODY		/* disallow everybody */
};

struct authlist_entry {
	enum authlist_kind kind;
	union {
		kuid_t	kuid;
		kgid_t	kgid;
	};
};

/*
 * @rws			rw semaphore to synchronize access to the structure
 *
 * @initial_value	used only if @nentries is 0, can be either
 *			AUTHLIST_KIND_EVERYBODY or AUTHLIST_KIND_NOBODY
 *
 * @nentries		count of entries, 0 means use @initial_value
 *
 * @entries		array of authlist_entry structures,
 *			size of the array is given by @nentries
 */
struct authlist {
	struct rw_semaphore rws;
	enum authlist_kind initial_value;
	int nentries;
	struct authlist_entry *entries;
};


#define AUTHLIST_INITIALIZER(name, _initial_value)	\
{							\
	.rws = __RWSEM_INITIALIZER(name.rws),		\
	.initial_value = (_initial_value),		\
	.nentries = 0,					\
	.entries = NULL					\
}

/*
 * Maximum authlist string length limit.
 *
 * Imposed to prevent malicious attempts to cause exessive memory allocation
 * by using insanely long authlist strings.
 */
#define AUTHLIST_LENGTH_LIMIT	(1024 * 32)


/*
 * sysctl routine to read-in the authlist from the userspace
 * and write it out to the userspace
 */
int proc_doauthlist(struct ctl_table *table, int write,
		    void __user *buffer, size_t *lenp, loff_t *ppos);


/*
 * Check if @authlist permits the caller with credentials @cred to perform
 * the operation guarded by the @authlist.
 */
int authlist_check_permission(struct authlist *authlist,
			      const struct cred *cred);

#endif /* _LINUX_AUTHLIST_H */

