/* Copyright (C) 2002, 2003, 2004, 2005 Thorsten Kukuk
   Author: Thorsten Kukuk <kukuk@suse.de>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifndef __PUBLIC_H__
#define __PUBLIC_H__

#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <sys/cdefs.h>
#include <rpc/types.h>

#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#endif

#ifndef __attribute_warn_unused_result__
#define __attribute_warn_unused_result__
#endif

#define DAY (24L*3600L)
#define SCALE DAY

enum service_t {S_NONE, S_LOCAL, S_YP, S_NISPLUS, S_LDAP};
typedef enum service_t service_t;

enum todo_t {DO_MODIFY, DO_CREATE, DO_DELETE, DO_CREATE_SHADOW,
	     DO_DELETE_SHADOW};
typedef enum todo_t todo_t;

struct user_t {
  todo_t todo;
  char *pwdbuffer;
  size_t pwdbuflen;
  struct passwd pw;
  char *spwbuffer;
  size_t spwbuflen;
  struct spwd sp;
  int use_shadow;
  enum service_t service;
  char *new_name;
  char *newpassword;
  char *oldclearpwd;
  int have_new_uid;
  uid_t new_uid;
  int have_new_gid;
  gid_t new_gid;
  char *new_shell;
  char *new_gecos;
  char *new_home;
  int sp_changed;
  struct spwd spn;
  char *binddn;
};
typedef struct user_t user_t;

struct faillog
{
  short fail_cnt;
  short fail_max;
  char fail_line[12];
  time_t fail_time;
  long fail_locktime;
};
typedef struct faillog faillog;

extern void init_environment (void);
extern void print_error (const char *program);
extern void print_version (const char *program, const char *years);

extern char *date2str (time_t date);
extern long int str2date (const char *str);

extern int strtoid (const char *arg, uint32_t *idptr) __attribute_warn_unused_result__;

extern int check_name (const char *name) __attribute_warn_unused_result__;
extern int check_home (const char *home) __attribute_warn_unused_result__;

extern int npd_upd_pwd (const char *domainname, user_t *data) __attribute_warn_unused_result__;
extern char *get_value (const char *oldf, const char *prompt) __attribute_warn_unused_result__;
extern char *getnismaster (void) __attribute_warn_unused_result__;
extern void free_user_t (user_t *data);
extern user_t *do_getpwnam (const char *user, const char *use_service) __attribute_warn_unused_result__;
extern int lock_database (void) __attribute_warn_unused_result__;
extern int write_user_data (user_t *data, int is_locked) __attribute_warn_unused_result__;
extern const char *nsw2str (service_t service);
extern int do_authentication (const char *prog, const char *caller,
			      user_t *pw_data) __attribute_warn_unused_result__;
extern int get_old_clear_password (user_t *pw_data);
extern int call_script (const char *variable, const char *name, uid_t uid,
			gid_t gid, const char *home, const char *program) __attribute_warn_unused_result__;
extern int copy_dir_rec (const char *src, const char *dst,
		         int preserve_id, uid_t uid, gid_t gid) __attribute_warn_unused_result__;
extern int remove_dir_rec (const char *tree);
extern int chown_dir_rec (const char *src, uid_t old_uid, uid_t new_uid,
	       		  gid_t old_gid, gid_t new_gid) __attribute_warn_unused_result__;
extern int is_logged_in (const char *user) __attribute_warn_unused_result__;

extern int copy_xattr (const char *from, const char *to) __attribute_warn_unused_result__;

extern char **remove_gr_mem (const char *name, char **gr_mem);


#ifdef WITH_SELINUX
extern int selinux_check_access (const char *__chuser,
				 unsigned int __selaccess) __attribute_warn_unused_result__;
extern int set_default_context (const char *filename,
				char **prev_context) __attribute_warn_unused_result__;
extern int restore_default_context (char *prev_context) __attribute_warn_unused_result__;
#endif

#endif /* __PUBLIC_H__ */
