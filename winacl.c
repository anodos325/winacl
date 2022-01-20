/*-
 * Copyright 2022 iXsystems, Inc.
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <sys/types.h>
#include <sys/acl.h>
#include <errno.h>
#include <sys/stat.h>
#include <err.h>
#include <fts.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>


#define	WA_RECURSIVE            0x00000001      /* recursive */
#define	WA_VERBOSE              0x00000002      /* print more stuff */
#define	WA_TRAVERSE             0x00000010      /* traverse filesystem mountpoints */
#define	WA_TRIAL                0x00000100      /* trial run */
#define	WA_FORCE                0x00000400      /* force */

#define	ACL_MAX_DEPTH 2
#define	SAFE_FREE(x) do { if ((x) != NULL) {free(x); (x)=NULL;} } while(0)
#define	ACL_FREE(x) do { if ((x) != NULL) {acl_free(x); (x)=NULL;} } while(0)

enum wa_action {
	WA_NULL,
	WA_CLONE,
	WA_STRIP,
	WA_CHOWN,
	WA_RESTORE,
	WA_DEDUP
};

struct acls {
	acl_t dacl;
	acl_t facl;
};

struct winacl_config {
	char *source;
	char *path;
	char *chroot;
	acl_t source_acl;
	dev_t root_dev;
	struct acls acls_to_set[ACL_MAX_DEPTH];
	uid_t uid;
	gid_t gid;
	int flags;
	enum wa_action action;
	bool (*op)(FTSENT *ftsent);
};

static bool clone_acl(FTSENT *ftsent);
static bool strip_acl(FTSENT *ftsent);
static bool chown_acl(FTSENT *ftsent);
static bool dedup_acl(FTSENT *ftsent);
static bool restore_acl(FTSENT *ftsent);

const struct {
	const char *str;
	enum wa_action action;
	bool (*op)(FTSENT *ftsent);
} actions [] = {
	{ "clone", WA_CLONE, clone_acl },
	{ "strip", WA_STRIP, strip_acl },
	{ "chown", WA_CHOWN, chown_acl },
	{ "restore", WA_DEDUP, restore_acl },
	{ "dedup", WA_DEDUP, dedup_acl }
};

size_t actions_size = sizeof(actions) / sizeof(actions[0]);
static struct winacl_config w = (struct winacl_config) {
	.uid = -1,
	.gid = -1,
	.action = WA_NULL
};

static bool
get_action(const char *str) {
	int i;
	for (i = 0; i < actions_size; i++) {
		if (strcasecmp(actions[i].str, str) != 0)
			continue;

		w.op = actions[i].op;
		w.action = actions[i].action;
		return true;
	}
	fprintf(stderr, "%s: invalid action\n", str);
	return false;
}

static char *
action_str(enum wa_action action_in) {
	int i;
	for (i = 0; i < actions_size; i++) {
		if (actions[i].action != action_in)
			continue;
		return strdup(actions[i].str);
	}
	return NULL;
};

static void
free_config() {
	int i;
	for (i = 0; i < ACL_MAX_DEPTH; i++) {
		struct acls check = w.acls_to_set[i];
		ACL_FREE(check.dacl);
		ACL_FREE(check.facl);
	}
	SAFE_FREE(w.source);
	SAFE_FREE(w.path);
	SAFE_FREE(w.chroot);
	ACL_FREE(w.source_acl);
}

static void
usage(char *path)
{
	if (strcmp(path, "cloneacl") == 0) {
	fprintf(stderr,
		"Usage: %s [OPTIONS] ...\n"
		"Where option is:\n"
		"    -s <path>                    # source for ACL. If none specified then ACL taken from -p\n"
		"    -p <path>                    # path to recursively set ACL\n"
		"    -v                           # verbose\n",
		path
	);
	} else {
	fprintf(stderr,
		"Usage: %s [OPTIONS] ...\n"
		"Where option is:\n"
		"    -a <clone|strip|chown|restore> # action to perform <restore is experimental!>\n"
		"    -O <owner>                     # change owner\n"
		"    -G <group>                     # change group\n"
		"    -c <path>                      # chroot path\n"
		"    -s <source>                    # source (if cloning ACL). If none specified then ACL taken from -p\n"
		"    -p <path>                      # path to set\n"
		"    -r                             # recursive\n"
		"    -v                             # verbose\n"
		"    -t                             # trial run - makes no changes\n"
		"    -x                             # traverse filesystem mountpoints\n"
		"    -f                             # force acl inheritance (restore action)\n",
		path
	);
	}

	exit(0);
}

static bool
strip_acl(FTSENT *entry)
{
	/*
	 * Convert non-trivial ACL to trivial ACL.
	 * This function is only called when action is set
	 * to 'strip'. A trivial ACL is one that is fully
	 * represented by the posix mode. If the goal is to
	 * simply remove ACLs, it will generally be more
	 * efficient to strip the ACL using setfacl -b
	 * from the root directory and then use the 'clone'
	 * action to set the ACL recursively.
	 */
	char *path = NULL;
	acl_t acl_tmp = NULL, acl_new = NULL;

	path = entry == NULL ? w.path : entry->fts_accpath;

	if (w.flags & WA_VERBOSE)
		fprintf(stdout, "%s\n", path);

	acl_tmp = acl_get_file(path, ACL_TYPE_NFS4);
	if (acl_tmp == NULL) {
		warn("%s: acl_get_file() failed: %s", path, strerror(errno));
		return (false);
	}

	acl_new = acl_strip_np(acl_tmp, 0);
	if (acl_new == NULL) {
		warn("%s: acl_strip_np() failed: %s", path, strerror(errno));
		ACL_FREE(acl_tmp);
		return (false);
	}

	if (acl_set_file(path, ACL_TYPE_NFS4, acl_new) < 0) {
		warn("%s: acl_set_file() failed: %s", path, strerror(errno));
		ACL_FREE(acl_tmp);
		ACL_FREE(acl_new);
		return (false);
	}
	ACL_FREE(acl_tmp);
	ACL_FREE(acl_new);

	if (w.uid != -1 || w.gid != -1) {
		if (chown(path, w.uid, w.gid) < 0) {
			warn("%s: chown() failed: %s", path, strerror(errno));
			return (false);
		}
	}
	return (true);
}

static bool
chown_acl(FTSENT *entry)
{
	int error;
	if ((w.uid == (uid_t)-1 || w.uid == entry->fts_statp->st_uid) &&
	    (w.gid == (gid_t)-1 || w.gid == entry->fts_statp->st_gid)){
		return (true);
	}

	if (w.flags & WA_VERBOSE)
		fprintf(stdout, "%s\n", entry->fts_accpath);

	if (w.flags & WA_TRIAL)
		return (true);

	error = chown(entry->fts_accpath, w.uid, w.gid);
	if (error)
		warn("%s: chown() failed", entry->fts_accpath);

	return error ? (false) : (true);
}

static bool
clone_acl(FTSENT *entry)
{
	acl_t acl_new = NULL;
	int error;
	char *path = entry->fts_accpath;

	if (w.flags & WA_VERBOSE)
		fprintf(stdout, "%s\n", entry->fts_path);

	if (entry->fts_level == FTS_ROOTLEVEL) {
		acl_new = w.source_acl;
	} else {
		struct acls d;
		if ((entry->fts_level -1) >= ACL_MAX_DEPTH) {
			d = w.acls_to_set[ACL_MAX_DEPTH-1];
		} else {
			d = w.acls_to_set[entry->fts_level - 1];
		}

		acl_new = S_ISDIR(entry->fts_statp->st_mode) ? d.dacl : d.facl;
	}

	if (w.flags & WA_TRIAL) {
		return (true);
	}

	error = acl_set_file(path, ACL_TYPE_NFS4, acl_new);
	if (error) {
		warn("%s: acl_set_file() failed: %s", path, strerror(errno));
		return (false);
	}

	if (w.uid != -1 || w.gid != -1) {
		error = chown(path, w.uid, w.gid);
		if (error) {
			warn("%s: chown() failed: %s", path, strerror(errno));
			return (false);
		}
	}

	return (true);
}

static inline char *get_relative_path(FTSENT *entry, size_t plen)
{
	char *relpath = NULL;
	relpath = entry->fts_path + plen;
	if (relpath[0] == '/') {
		relpath++;
	}
	return relpath;
}

static int get_acl_parent(FTSENT *fts_entry);
static int acl_cmp(acl_t source, acl_t dest, int flags);

static bool
restore_acl(FTSENT *entry)
{
	static size_t slen, plen;
	int rval;
	char *relpath = NULL;
	char shadow_path[PATH_MAX] = {0};
	acl_t acl_new = NULL, acl_old = NULL;
	struct acls orig = w.acls_to_set[0];

	if (slen == 0) {
		slen = strlen(w.source);
		plen = strlen(w.path);
	}

	relpath = get_relative_path(entry, plen);

	if (strlen(relpath) + slen > PATH_MAX) {
		warn("%s: path in snapshot directory is too long", relpath);
		return (false);
	}

	rval = snprintf(shadow_path, sizeof(shadow_path), "%s/%s", w.source, relpath);
	if (rval < 0) {
		warn("%s: snprintf failed", relpath);
		return (false);
	}

	acl_new = acl_get_file(shadow_path, ACL_TYPE_NFS4);
	if (acl_new == NULL) {
		if (errno == ENOENT) {
			if (w.flags & WA_FORCE) {
				rval = get_acl_parent(entry);
				if (rval != 0) {
					fprintf(stdout, "! %s\n", shadow_path);
					return true;
				}
				acl_new = acl_dup(S_ISDIR(entry->fts_statp->st_mode) ? orig.dacl : orig.facl);
				if (acl_new == NULL) {
					warn("%s: acl_dup() failed", shadow_path);
					return false;
				}
			}
			else {
				fprintf(stdout, "! %s\n", shadow_path);
				return true;
			}
		} else {
			warn("%s: acl_get_file() failed", shadow_path);
			return false;
		}
	}

	acl_old = acl_get_file(entry->fts_path, ACL_TYPE_NFS4);
	if (acl_old == NULL) {
		warn("%s: acl_get_file() failed", entry->fts_path);
		return false;
	}

	rval = acl_cmp(acl_new, acl_old, w.flags);
	if (rval == 0) {
		return true;
	}

	if (w.flags & WA_VERBOSE) {
		fprintf(stdout, "%s -> %s\n", shadow_path, entry->fts_path);
	}
	if ((w.flags & WA_TRIAL) == 0) {
		rval = acl_set_file(entry->fts_accpath,
				    ACL_TYPE_NFS4, acl_new);
		if (rval < 0) {
			warn("%s: acl_set_file() failed", entry->fts_accpath);
			ACL_FREE(acl_old);
			ACL_FREE(acl_new);
			return false;
		}
	}

	ACL_FREE(acl_old);
	ACL_FREE(acl_new);
	return (true);
}

static bool ace_cmp(acl_entry_t s_entry, acl_entry_t p_entry, int flags);

static bool
acl_entry_is_present(acl_entry_t to_check, acl_t theacl)
{
	int entry_id = ACL_FIRST_ENTRY;
	acl_entry_t source_entry;

	while (acl_get_entry(theacl, entry_id, &source_entry) == 1) {
		bool ace_is_same;
		entry_id = ACL_NEXT_ENTRY;

		ace_is_same = ace_cmp(to_check, source_entry, 0);
		if (ace_is_same) {
			return (true);
		}
	}
	return (false);
}

static bool
dedup_acl(FTSENT *entry)
{
	int error;
	int entry_id = ACL_FIRST_ENTRY;
	acl_t orig_acl = NULL, new_acl = NULL;
	acl_entry_t orig_entry;
	bool has_first = false;

	orig_acl = acl_get_file(entry->fts_accpath, ACL_TYPE_NFS4);
	if (orig_acl == NULL) {
		warn("%s, acl_get_file() failed", entry->fts_accpath);
		return (false);
	}

	new_acl = acl_init(ACL_MAX_ENTRIES);
	if (new_acl == NULL) {
		warn("acl_init() failed");
		ACL_FREE(orig_acl);
		return (false);
	}

	while (acl_get_entry(orig_acl, entry_id, &orig_entry) == 1) {
		bool entry_present;
		acl_entry_t new_entry;

		entry_id = ACL_NEXT_ENTRY;
		entry_present = acl_entry_is_present(orig_entry, new_acl);
		if (entry_present)
			continue;

		error = acl_create_entry_np(&new_acl, &new_entry,
		    has_first ? ACL_NEXT_ENTRY : ACL_FIRST_ENTRY);
		if (error)
			err(EX_OSERR, "acl_create_entry() failed");

		error = acl_copy_entry(new_entry, orig_entry);
		if (error)
			err(EX_OSERR, "acl_copy_entry() failed");

		has_first = true;
	}

	// count didn't change and so skip ACL write
	if (orig_acl->ats_acl.acl_cnt == new_acl->ats_acl.acl_cnt) {
		printf("%s + [ no changes ]\n", entry->fts_path);
		return (true);
	}

	if (w.flags & WA_VERBOSE) {
		fprintf(stdout, "%s + [COUNT %d -> %d]\n", entry->fts_path,
			orig_acl->ats_acl.acl_cnt, new_acl->ats_acl.acl_cnt);
	}

	if (w.flags & WA_TRIAL) {
		char *acl_str = acl_to_text(new_acl, NULL);
		if (acl_str == NULL)
			err(EX_OSERR, "acl_to_test() failed");
		fprintf(stdout, "%s", acl_str);
		SAFE_FREE(acl_str);
		ACL_FREE(orig_acl);
		ACL_FREE(new_acl);
		return (true);
	}

	error = acl_set_file(entry->fts_accpath, ACL_TYPE_NFS4, new_acl);
	if (error)
		warn("%s: acl_set_file() failed", entry->fts_accpath);

	ACL_FREE(orig_acl);
	ACL_FREE(new_acl);
	return (error ? false : true);
}

static int calculate_inherited_acl(acl_t parent_acl, int level);
/*
 * Iterate through linked list of parent directories until we are able
 * to find one that exists in the snapshot directory. Use this ACL
 * to calculate an inherited acl.
 */
static int get_acl_parent(FTSENT *fts_entry)
{
	int rval;
	FTSENT *p = NULL;
	char *path = NULL;
	char shadow_path[PATH_MAX] = {0};
	acl_t parent_acl;

	if (fts_entry->fts_parent == NULL) {
		/*
		 * No parent node indicates we're at fts root level.
		 */
		parent_acl = acl_get_file(w.source, ACL_TYPE_NFS4);
		if (parent_acl == NULL) {
			return -1;
		}
		rval = calculate_inherited_acl(parent_acl, 0);
		if (rval != 0) {
			warn("%s: acl_get_file() failed", w.source);
		}
		ACL_FREE(parent_acl);
		return rval;
	}

	for (p=fts_entry->fts_parent; p; p=p->fts_parent) {
		rval = snprintf(shadow_path, sizeof(shadow_path),
				"%s/%s", w.source, p->fts_accpath);
		if (rval < 0) {
			warn("%s: snprintf failed", p->fts_accpath);
			return -1;
		}

		parent_acl = acl_get_file(shadow_path, ACL_TYPE_NFS4);
		if (parent_acl == NULL) {
			if (errno == ENOENT) {
				continue;
			}
			else {
				warn("%s: acl_get_file() failed", shadow_path);
				return -1;

			}
		}

		rval = calculate_inherited_acl(parent_acl, 0);
		if (rval == 0) {
			ACL_FREE(parent_acl);
			return 0;
		}
		warn("%s: acl_get_file() failed", shadow_path);
		ACL_FREE(parent_acl);
	}
	return -1;
}

static bool ace_cmp(acl_entry_t s_entry, acl_entry_t p_entry, int flags)
{
	if (s_entry->ae_tag != p_entry->ae_tag) {
		if (flags & WA_VERBOSE) {
			fprintf(stdout, "+ [ACL tag 0x%08x -> 0x%08x] ",
				s_entry->ae_tag, p_entry->ae_tag);
		}
		return false;
	}
	if (s_entry->ae_id != p_entry->ae_id) {
		if (flags & WA_VERBOSE) {
			fprintf(stdout, "+ [ACL id %d -> %d] ",
				s_entry->ae_id, p_entry->ae_id);
		}
		return false;
	}
	if (s_entry->ae_perm != p_entry->ae_perm) {
		if (flags & WA_VERBOSE) {
			fprintf(stdout, "+ [ACL perm 0x%08x -> 0x%08x] ",
				s_entry->ae_perm, p_entry->ae_perm);
		}
		return false;
	}
	if (s_entry->ae_entry_type != p_entry->ae_entry_type) {
		if (flags & WA_VERBOSE) {
			fprintf(stdout, "+ [ACL entry_type 0x%08x -> 0x%08x] ",
				s_entry->ae_entry_type, p_entry->ae_entry_type);
		}
		return false;
	}
	if (s_entry->ae_flags != p_entry->ae_flags) {
		if (flags & WA_VERBOSE) {
			fprintf(stdout, "+ [ACL entry_flags 0x%08x -> 0x%08x] ",
					s_entry->ae_flags, p_entry->ae_flags);
		}
		return false;
	}
	return true;
}
/*
 * Compare two acl_t structs. Return 0 on success -1 on failure.
 */
static int acl_cmp(acl_t source, acl_t dest, int flags)
{
	acl_entry_t s_entry, p_entry;
	acl_permset_t s_perm, p_perm;
	acl_tag_t s_tag, p_tag;
	acl_flagset_t s_flag, p_flag;

	int entry_id = ACL_FIRST_ENTRY;
	int rv;

	if (source->ats_acl.acl_cnt != dest->ats_acl.acl_cnt) {
		if (flags & WA_VERBOSE) {
			fprintf(stdout, "+ [COUNT %d -> %d] ",
				source->ats_acl.acl_cnt,
				dest->ats_acl.acl_cnt);
		}
		return -1;
	}

	while (acl_get_entry(source, entry_id, &s_entry) == 1) {
		bool ace_is_same;
		entry_id = ACL_NEXT_ENTRY;
		rv = acl_get_entry(dest, entry_id, &p_entry);
		if (rv != 1) {
			if (flags & WA_VERBOSE) {
				fprintf(stdout, "+ [ACL_ERROR: %s] ",
					strerror(errno));
			}
			return -1;
		}

		ace_is_same = ace_cmp(s_entry, p_entry, flags);
		if (!ace_is_same)
			return -1;
	}
	return 0;
}

static bool
do_fts_walk()
{
	FTS *ftsp = NULL;
	FTSENT *entry = NULL;
	bool ok;
	int error, options = 0;
	struct stat ftsroot_st;
	char *paths[2] = { w.path, NULL };

	error = stat(w.path, &ftsroot_st);
	if (error)
		err(EX_OSERR, "%s: stat() failed", w.path);

	if ((w.flags & WA_TRAVERSE) == 0 || (w.flags & WA_RESTORE)) {
		options |= FTS_XDEV;
	}

	ftsp = fts_open(paths, (FTS_PHYSICAL | options), NULL);
	if (ftsp == NULL) {
		err(EX_OSERR, "fts_open()");
	}

	for (ok = true; (entry = fts_read(ftsp)) != NULL;) {
		if (((w.flags & WA_RECURSIVE) == 0) &&
		    (entry->fts_level == FTS_ROOTLEVEL)) {
			ok = w.op(entry);
			break;
		}
		if ((options & FTS_XDEV) &&
		    (ftsroot_st.st_dev != entry->fts_statp->st_dev)){
			continue;
		}
		switch(entry->fts_info) {
		case FTS_D:
		case FTS_F:
			ok = w.op(entry);
			if (!ok && (errno == EOPNOTSUPP) &&
			    strcmp(entry->fts_accpath, ".zfs") == 0) {
				fts_set(ftsp, entry, FTS_SKIP);
			}
			break;
		case FTS_ERR:
			warnx("%s: %s", entry->fts_path,
			      strerror(entry->fts_errno));
			ok = false;
			break;
		}
		if (!ok) {
			err(EX_OSERR, "%s: operation [%s] failed",
			    entry->fts_accpath, action_str(w.action));
		}
	}

	return (ok);
}

static int
calculate_inherited_acl(acl_t parent_acl, int level)
{
	/*
	 * Generates an inherited directory ACL and file ACL based
	 * on the ACL specified in the parent_acl. Behavior in the absence of
	 * inheriting aces in the parent ACL is as follows: if the parent_acl
	 * is trivial (i.e. can be expressed as posix mode without
	 * information loss), then apply the mode recursively. If the ACL
	 * is non-trivial, then user intention is less clear and so error
	 * out.
	 *
	 * Currently, nfsv41 inheritance is not implemented.
	 */
	int trivial = 0;
	acl_t tmp_acl;
	acl_entry_t entry, file_entry, dir_entry;
	acl_permset_t permset;
	acl_flagset_t flagset, file_flag, dir_flag;
	int entry_id, f_entry_id, d_entry_id, must_set_facl, must_set_dacl;
	int ret = 0;
	entry_id = f_entry_id = d_entry_id = ACL_FIRST_ENTRY;
	must_set_facl = must_set_dacl = true;
	struct acls *the_acls = &w.acls_to_set[level];

	ACL_FREE(the_acls->dacl);
	ACL_FREE(the_acls->facl);

	/*
	 * Short-circuit for trivial ACLs. If ACL is trivial,
	 * assume that user does not want to apply ACL inheritance rules.
	 */
	if (acl_is_trivial_np(parent_acl, &trivial) != 0) {
		err(EX_OSERR, "acl_is_trivial_np() failed");
	}
	if (trivial) {
		the_acls->dacl = acl_dup(parent_acl);
		the_acls->facl = acl_dup(parent_acl);
		return ret;
	}

	/* initialize separate directory and file ACLs */
	if ((the_acls->dacl = acl_init(ACL_MAX_ENTRIES)) == NULL) {
		err(EX_OSERR, "failed to initialize directory ACL");
	}
	if ((the_acls->facl = acl_init(ACL_MAX_ENTRIES)) == NULL) {
		err(EX_OSERR, "failed to initialize file ACL");
	}

	tmp_acl = acl_dup(parent_acl);
	if (tmp_acl == NULL) {
		err(EX_OSERR, "acl_dup() failed");
	}

	while (acl_get_entry(tmp_acl, entry_id, &entry) == 1) {
		entry_id = ACL_NEXT_ENTRY;
		if (acl_get_permset(entry, &permset)) {
			err(EX_OSERR, "acl_get_permset() failed");
		}
		if (acl_get_flagset_np(entry, &flagset)) {
			err(EX_OSERR, "acl_get_flagset_np() failed");
		}

		/* Entry is not inheritable at all. Skip. */
		if ((*flagset & (ACL_ENTRY_DIRECTORY_INHERIT|ACL_ENTRY_FILE_INHERIT)) == 0) {
			continue;
		}

		/* Skip if the ACE has NO_PROPAGATE flag set and does not have INHERIT_ONLY flag. */
		if ((*flagset & ACL_ENTRY_NO_PROPAGATE_INHERIT) &&
		    (*flagset & ACL_ENTRY_INHERIT_ONLY) == 0) {
			continue;
		}

		/*
		 * By the time we've gotten here, we're inheriting something somewhere.
		 * Strip inherit only from the flagset and set ACL_ENTRY_INHERITED.
		 */

		*flagset &= ~ACL_ENTRY_INHERIT_ONLY;
		*flagset |= ACL_ENTRY_INHERITED;

		if ((*flagset & ACL_ENTRY_FILE_INHERIT) == 0) {
			must_set_facl = false;
		}

		/*
		 * Add the entries to the file ACL and directory ACL. Since files and directories
		 * will require differnt flags to be set, we make separate calls to acl_get_flagset_np()
		 * to modify the flagset of the new ACEs.
		 */
		if (must_set_facl) {
			if (acl_create_entry_np(&the_acls->facl, &file_entry, f_entry_id) == -1) {
				err(EX_OSERR, "acl_create_entry() failed");
			}
			if (acl_copy_entry(file_entry, entry) == -1) {
				err(EX_OSERR, "acl_create_entry() failed");
			}
			if (acl_get_flagset_np(file_entry, &file_flag)) {
				err(EX_OSERR, "acl_get_flagset_np() failed");
			}
			*file_flag &= ~(ACL_ENTRY_DIRECTORY_INHERIT|ACL_ENTRY_FILE_INHERIT|ACL_ENTRY_NO_PROPAGATE_INHERIT);
			f_entry_id ++;
		}
		if (must_set_dacl) {
			if (acl_create_entry_np(&the_acls->dacl, &dir_entry, d_entry_id) == -1) {
				err(EX_OSERR, "acl_create_entry() failed");
			}
			if (acl_copy_entry(dir_entry, entry) == -1) {
				err(EX_OSERR, "acl_create_entry() failed");
			}
			if (acl_get_flagset_np(dir_entry, &dir_flag)) {
				err(EX_OSERR, "acl_get_flagset_np() failed");
			}
			/*
			 * Special handling for NO_PROPAGATE_INHERIT. Original flags at
			 * this point would have been fdin, din, or fin. In the case of
			 * fin, the acl entry must not be added to the dacl (since it only
			 * applies to files).
			 */
			if (*flagset & ACL_ENTRY_NO_PROPAGATE_INHERIT) {
				if ((*flagset & ACL_ENTRY_DIRECTORY_INHERIT) == 0) {
					continue;
				}
				*dir_flag &= ~(ACL_ENTRY_DIRECTORY_INHERIT|ACL_ENTRY_FILE_INHERIT|ACL_ENTRY_NO_PROPAGATE_INHERIT);
			}
			/*
			 * If only FILE_INHERIT is set then turn on INHERIT_ONLY
			 * on directories. This is to prevent ACE from applying to directories.
			 */
			else if ((*flagset & ACL_ENTRY_DIRECTORY_INHERIT) == 0) {
				*dir_flag |= ACL_ENTRY_INHERIT_ONLY;
			}
			d_entry_id ++;
		}
		must_set_dacl = must_set_facl = true;

	}
	ACL_FREE(tmp_acl);
	if ( d_entry_id == 0 || f_entry_id == 0 ) {
		errno = EINVAL;
		warn("%s: acl_set_file() failed. Calculated invalid ACL with no inherited entries.", w.source);
		ret = -1;
	}
	return (ret);
}


static uid_t
id(const char *name, const char *type)
{
	uid_t val;
	char *ep = NULL;

	/*
	 * We know that uid_t's and gid_t's are unsigned longs.
	 */
	errno = 0;
	val = strtoul(name, &ep, 10);
	if (errno || *ep != '\0')
		errx(1, "%s: illegal %s name", name, type);
	return (val);
}

static gid_t
a_gid(const char *s)
{
	struct group *gr = NULL;
	return ((gr = getgrnam(s)) != NULL) ? gr->gr_gid : id(s, "group");
}

static uid_t
a_uid(const char *s)
{
	struct passwd *pw = NULL;
	return ((pw = getpwnam(s)) != NULL) ? pw->pw_uid : id(s, "user");
}

static void
usage_check()
{
	if (w.path == NULL) {
		fprintf(stderr, "no path specified\n");
		usage("winacl");
	}

	if (w.action == WA_NULL) {
		fprintf(stderr, "no action specified\n");
		usage("winacl");
	}
}

int
main(int argc, char **argv)
{
	int ch, ret, i;
	acl_t source_acl = NULL;
	char *p = argv[0];
	ch = ret = 0;
	struct stat st;
	bool ok;

	if (argc < 2) {
		usage(argv[0]);
	}

	for (i = 0; i < ACL_MAX_DEPTH; i++) {
		w.acls_to_set[i].dacl = NULL;
		w.acls_to_set[i].facl = NULL;
	}

	while ((ch = getopt(argc, argv, "a:O:G:c:s:p:rftvx")) != -1) {
		switch (ch) {
		case 'a':
			ok = get_action(optarg);
			if (!ok || w.action == WA_NULL) {
				usage(argv[0]);
			}
			break;

		case 'O':
			w.uid = a_uid(optarg);
			break;

		case 'G':
			w.gid = a_gid(optarg);
			break;

		case 'c':
			w.chroot = realpath(optarg, NULL);
			if (w.chroot == NULL)
				err(EX_OSERR, "%s: realpath() failed", optarg);
			break;

		case 's':
			w.source = realpath(optarg, NULL);
			if (w.source == NULL)
				err(EX_OSERR, "%s: realpath() failed", optarg);
			break;

		case 'p':
			w.path = realpath(optarg, NULL);
			if (w.path == NULL)
				err(EX_OSERR, "%s: realpath() failed", optarg);
			break;

		case 'r':
			w.flags |= WA_RECURSIVE;
			break;

		case 't':
			w.flags |= WA_TRIAL;
			break;

		case 'v':
			w.flags |= WA_VERBOSE;
			break;

		case 'x':
			w.flags |= WA_TRAVERSE;
			break;

		case 'f':
			w.flags |= WA_FORCE;
			break;

		case '?':
		default:
			usage(argv[0]);
		}
	}

	usage_check();

	/* set the source to the destination if we lack -s */
	if (w.source == NULL) {
		if (w.flags & WA_RESTORE) {
			warn("source must be set for restore jobs");
			return (1);
		}
		w.source = strdup(w.path);
	}

	if (stat("/", &st) < 0) {
		warn("%s: stat() failed.", "/");
		free_config();
		return (1);
	}
	w.root_dev = st.st_dev;

	if (w.chroot != NULL) {
		if (w.source != NULL) {
			if (strncmp(w.chroot, w.source, strlen(w.chroot)) != 0) {
				warn("%s: path does not lie in chroot path.", w.source);
				free_config();
				return (1);
			}
			if (strlen(w.chroot) == strlen(w.source)) {
				w.source = strdup(".");
			} else {
				char *tmp = strdup(w.source + strlen(w.chroot));
				SAFE_FREE(w.source);
				w.source = tmp;
			}
		}
		if (w.path != NULL ) {
			if (strncmp(w.chroot, w.path, strlen(w.chroot)) != 0) {
				warn("%s: path does not lie in chroot path.", w.path);
				free_config();
				return (1);
			}
			if (strlen(w.chroot) == strlen(w.path)) {
				w.path = strdup(".");
			}
			else {
				char *tmp = strdup(w.path + strlen(w.chroot));
				SAFE_FREE(w.path);
				w.path = tmp;
			}
		}
		ret = chdir(w.chroot);
		if (ret == -1) {
			warn("%s: chdir() failed.", w.chroot);
			free_config();
			return (1);
		}
		ret = chroot(w.chroot);
		if (ret == -1) {
			warn("%s: chroot() failed.", w.chroot);
			free_config();
			return (1);
		}
		printf("path: [%s]\n", w.path);
		if (access(w.path, F_OK) < 0) {
			warn("%s: access() failed after chroot.", w.path);
			free_config();
			return (1);
		}
	}

	if (access(w.source, F_OK) < 0) {
		warn("%s: access() failed.", w.source);
		free_config();
		return (1);
	}
	if (pathconf(w.source, _PC_ACL_NFS4) < 0) {
		warn("%s: pathconf(..., _PC_ACL_NFS4) failed. Path does not support NFS4 ACL.", w.source);
		free_config();
		return (1);
	}

	if (w.flags & WA_CLONE){
		int depth = 0;
		w.source_acl = acl_get_file(w.source, ACL_TYPE_NFS4);
		if (w.source_acl == NULL) {
			err(EX_OSERR, "%s: acl_get_file() failed", w.source);
			free_config();
			return (1);
		}

		for (depth = 0; depth < ACL_MAX_DEPTH; depth++) {
			acl_t origin = NULL;
			origin = (depth == 0) ? w.source_acl : w.acls_to_set[depth - 1].dacl;
			if (calculate_inherited_acl(origin, depth) != 0) {
				free_config();
				return (1);
			}
		}
	}

	ok = do_fts_walk();
	free_config();
	return (ok ? 0 : 1);
}
