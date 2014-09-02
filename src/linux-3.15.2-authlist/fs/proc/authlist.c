/*
 * fs/proc/authlist.c
 *
 * Authorization list.
 *
 * Started by (C) 2014 Sergey Oboguev <oboguev@yahoo.com>
 *
 * This code is licenced under the GPL version 2 or later.
 * For details see linux-kernel-base/COPYING.
 */

#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/unistd.h>
#include <linux/stddef.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/compiler.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/sysctl.h>
#include <linux/authlist.h>

#define error_out(rc)  do { error = (rc);  goto out; } while (0)

static const char tag_uid[] = "uid";
static const char tag_nouid[] = "nouid";
static const char tag_gid[] = "gid";
static const char tag_nogid[] = "nogid";
static const char tag_everybody[] = "everybody";
static const char tag_nobody[] = "nobody";

static inline bool is_ws(char c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static inline bool is_ws_eos(char c)
{
	return is_ws(c) || c == '\0';
}

/* count whitespace-separated entries in the descriptor string */
static int count_entries(const char *desc)
{
	const char *p = desc;
	int nentries = 0;

	for (;;) {
		/* skip leading whitespace */
		while (is_ws(*p))
			p++;

		/* reached the end of the string? */
		if (*p == '\0')
			break;

		/* detected non-ws section */
		nentries++;

		/* skip non-ws section */
		while (!is_ws_eos(*p))
			p++;
	}

	return nentries;
}

static inline bool istag(const char **ep, const char *tag)
{
	int len = strlen(tag);
	const char *p = *ep;

	if (0 == strncmp(p, tag, len)) {
		if (is_ws_eos(p[len])) {
			*ep += len;
			return true;
		}
	}

	return false;
}

static inline bool istag_col(const char **ep, const char *tag)
{
	int len = strlen(tag);
	const char *p = *ep;

	if (0 == strncmp(p, tag, len) && p[len] == ':') {
		*ep += len + 1;
		return true;
	}

	return false;
}

static int parse_id(const char **ep, struct authlist_entry *entry,
		    enum authlist_kind kind)
{
	struct user_namespace *ns = current_user_ns();
	/* decimal representation of 32-bit number fits in 10 chars */
	char sval[11];
	const char *p = *ep;
	char *xp = sval;
	int error;
	uid_t uid;
	gid_t gid;

	while (isdigit(*p)) {
		if (xp - sval >= sizeof(sval) - 1)
			return -EINVAL;
		*xp++ = *p++;
	}
	*xp = '\0';
	if (!sval[0] || !is_ws_eos(*p))
		return -EINVAL;

	switch (kind) {
	case AUTHLIST_KIND_UID:
	case AUTHLIST_KIND_NOUID:
		error = kstrtouint(sval, 10, &uid);
		if (error)
			return error;
		entry->kuid = make_kuid(ns, uid);
		if (!uid_valid(entry->kuid))
			return -EINVAL;
		break;

	case AUTHLIST_KIND_GID:
	case AUTHLIST_KIND_NOGID:
		error = kstrtouint(sval, 10, &gid);
		if (error)
			return error;
		entry->kgid = make_kgid(ns, gid);
		if (!gid_valid(entry->kgid))
			return -EINVAL;
		break;

	default:
		return -EINVAL;
	}

	entry->kind = kind;
	*ep = p;

	return 0;
}

static int parse_entry(const char **ep, struct authlist_entry *entry)
{
	if (istag(ep, tag_everybody))
		entry->kind = AUTHLIST_KIND_EVERYBODY;
	else if (istag(ep, tag_nobody))
		entry->kind = AUTHLIST_KIND_NOBODY;
	else if (istag_col(ep, tag_uid))
		return parse_id(ep, entry, AUTHLIST_KIND_UID);
	else if (istag_col(ep, tag_nouid))
		return parse_id(ep, entry, AUTHLIST_KIND_NOUID);
	else if (istag_col(ep, tag_gid))
		return parse_id(ep, entry, AUTHLIST_KIND_GID);
	else if (istag_col(ep, tag_nogid))
		return parse_id(ep, entry, AUTHLIST_KIND_NOGID);
	else
		return -EINVAL;

	return 0;
}

/*
 * Import authlist from the userspace
 */
static int write_authlist(struct authlist *authlist, void __user *buffer,
			  size_t *lenp, loff_t *ppos)
{
	struct authlist_entry *entries = NULL, *old_entries;
	char *memblk = NULL;
	int error = 0;
	int nentries;
	int ne;
	int terminal = -1;
	const char *p;

	/* ensure atomic transfer */
	if (*ppos != 0)
		return -EINVAL;

	if (*lenp > AUTHLIST_LENGTH_LIMIT)
		return -EINVAL;

	memblk = kmalloc(*lenp + 1, GFP_KERNEL);
	if (memblk == NULL)
		return -ENOMEM;

	if (copy_from_user(memblk, buffer, *lenp))
		error_out(-EFAULT);

	memblk[*lenp] = '\0';

	nentries = count_entries(memblk);
	if (nentries == 0)
		error_out(-EINVAL);

	entries = kmalloc(sizeof(struct authlist_entry) * nentries, GFP_KERNEL);
	if (entries == NULL)
		error_out(-ENOMEM);

	for (p = memblk, ne = 0;; ne++) {
		/* skip leading whitespace */
		while (is_ws(*p))
			p++;

		/* reached the end of the string? */
		if (*p == '\0')
			break;

		error = parse_entry(&p, entries + ne);
		if (error)
			goto out;

		switch (entries[ne].kind) {
		case AUTHLIST_KIND_EVERYBODY:
		case AUTHLIST_KIND_NOBODY:
			if (terminal != -1)
				error_out(-EINVAL);
			terminal = ne;
			break;

		default:
			break;
		}
	}

	/*
	 * Last entry must be everybody/nobody.
	 * Intermediate entry cannot be everybody/nobody.
	 */
	if (terminal != nentries - 1)
		error_out(-EINVAL);

	down_write(&authlist->rws);
	old_entries = authlist->entries;
	authlist->nentries = nentries;
	authlist->entries = entries;
	up_write(&authlist->rws);

	kfree(old_entries);
	entries = NULL;

	*ppos += *lenp;

out:

	kfree(memblk);
	kfree(entries);

	return error;
}

/*
 * Export authlist to the userspace
 */
static int read_authlist(struct authlist *authlist,
			 void __user *buffer,
			 size_t *lenp, loff_t *ppos)
{
	struct user_namespace *ns = current_user_ns();
	char *memblk = NULL;
	char *vp = NULL;
	int error = 0;
	int len;
	uid_t uid;
	gid_t gid;

	down_read(&authlist->rws);

	if (authlist->nentries == 0) {
		switch (authlist->initial_value) {
		case AUTHLIST_KIND_EVERYBODY:
			vp = (char *) tag_everybody;
			break;

		case AUTHLIST_KIND_NOBODY:
		default:
			vp = (char *) tag_nobody;
			break;
		}
	} else {
		struct authlist_entry *entry;
		/* <space>noguid:4294967295 */
		size_t maxentrysize = 1 + 6 + 1 + 10;
		size_t alloc_size = maxentrysize * authlist->nentries + 1;
		int ne;

		memblk = kmalloc(alloc_size, GFP_KERNEL);
		if (memblk == NULL) {
			up_read(&authlist->rws);
			return -ENOMEM;
		}

		vp = memblk;
		*vp = '\0';
		entry = authlist->entries;
		for (ne = 0;  ne < authlist->nentries;  ne++, entry++) {
			vp += strlen(vp);
			if (ne != 0)
				*vp++ = ' ';
			switch (entry->kind) {
			case AUTHLIST_KIND_UID:
				uid = from_kuid(ns, entry->kuid);
				if (uid == (uid_t) -1) {
					error = EIDRM;
					break;
				}
				sprintf(vp, "%s:%u", tag_uid, (unsigned) uid);
				break;

			case AUTHLIST_KIND_NOUID:
				uid = from_kuid(ns, entry->kuid);
				if (uid == (uid_t) -1) {
					error = EIDRM;
					break;
				}
				sprintf(vp, "%s:%u", tag_nouid, (unsigned) uid);
				break;

			case AUTHLIST_KIND_GID:
				gid = from_kgid(ns, entry->kgid);
				if (gid == (gid_t) -1) {
					error = EIDRM;
					break;
				}
				sprintf(vp, "%s:%u", tag_gid, (unsigned) gid);
				break;

			case AUTHLIST_KIND_NOGID:
				gid = from_kgid(ns, entry->kgid);
				if (gid == (gid_t) -1) {
					error = EIDRM;
					break;
				}
				sprintf(vp, "%s:%u", tag_nogid, (unsigned) gid);
				break;

			case AUTHLIST_KIND_EVERYBODY:
				strcpy(vp, tag_everybody);
				break;

			case AUTHLIST_KIND_NOBODY:
				strcpy(vp, tag_nobody);
				break;
			}

			if (unlikely(error != 0)) {
				up_read(&authlist->rws);
				kfree(memblk);
				return error;
			}
		}

		vp = memblk;
	}

	up_read(&authlist->rws);

	len = strlen(vp);

	/* ensure atomic transfer */
	if (*ppos != 0) {
		if (*ppos == len + 1) {
			*lenp = 0;
			goto out;
		}
		error_out(-EINVAL);
	}

	if (len + 2 > *lenp)
		error_out(-ETOOSMALL);

	if (likely(len) && copy_to_user(buffer, vp, len))
		error_out(-EFAULT);

	if (copy_to_user(buffer + len, "\n", 2))
		error_out(-EFAULT);

	*lenp = len + 1;
	*ppos += len + 1;

out:

	kfree(memblk);

	return error;
}

/*
 * proc_doauthlist - read or write authorization list
 * @table: the sysctl table
 * @write: true if this is a write to the sysctl file
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * Reads/writes an authorization list as a string from/to the user buffer.
 *
 * On struct authlist -> userspace string read, if the user buffer provided
 * is not large enough to hold the string atomically, an error will be
 * returned. The copied string will include '\n' and is NUL-terminated.
 *
 * On userspace string -> struct authlist write, if the user buffer does not
 * contain a valid string-from authorization list atomically, or if the
 * descriptor is malformatted, an error will be returned.
 *
 * Returns 0 on success.
 */
int proc_doauthlist(struct ctl_table *table, int write,
		    void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct authlist *authlist = (struct authlist *) table->data;

	if (write)
		return write_authlist(authlist, buffer, lenp, ppos);
	else
		return read_authlist(authlist, buffer, lenp, ppos);
}

static bool in_egroup(const struct cred *cred, kgid_t kgid)
{
	if (gid_eq(cred->egid, kgid))
		return true;

	return groups_search(cred->group_info, kgid);
}

/*
 * Check if @authlist permits the called with @cred credentials to perform the
 * operation guarded by the @authlist.
 */
int authlist_check_permission(struct authlist *authlist,
			      const struct cred *cred)
{
	struct authlist_entry *entry;
	int ne, error = 0;

	down_read(&authlist->rws);

	if (authlist->nentries == 0) {
		if (authlist->initial_value == AUTHLIST_KIND_EVERYBODY)
			error_out(0);
		error_out(-EPERM);
	}

	entry = authlist->entries;

	for (ne = 0;  ne < authlist->nentries;  ne++, entry++) {
		switch (entry->kind) {
		case AUTHLIST_KIND_UID:
			if (uid_eq(entry->kuid, cred->euid))
				error_out(0);
			break;

		case AUTHLIST_KIND_NOUID:
			if (uid_eq(entry->kuid, cred->euid))
				error_out(-EPERM);
			break;

		case AUTHLIST_KIND_GID:
			if (in_egroup(cred, entry->kgid))
				error_out(0);
			break;

		case AUTHLIST_KIND_NOGID:
			if (in_egroup(cred, entry->kgid))
				error_out(-EPERM);
			break;

		case AUTHLIST_KIND_EVERYBODY:
			error_out(0);

		case AUTHLIST_KIND_NOBODY:
			error_out(-EPERM);
		}
	}

out:

	up_read(&authlist->rws);

	return error;
}

