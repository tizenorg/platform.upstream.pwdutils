/* Copyright (C) 2004, 2005 Thorsten Kukuk
   Author: Thorsten Kukuk <kukuk@thkukuk.de>

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

#ifndef __LOGGING_H__
#define __LOGGING_H__

#include <stdarg.h>

extern void open_sec_log (const char *program);

struct logfunc_t {
  void (*sec_log_fnc) (const char *program, unsigned int id, ...);
  void (*open_sec_log_fnc) (const char *arguments);
  struct logfunc_t *next;
};

extern struct logfunc_t *logfunc_list;

#define sec_log(program, id, args...)			\
  do {							\
    struct logfunc_t *listptr = logfunc_list;		\
    while (listptr)					\
      {							\
	listptr->sec_log_fnc (program, id, ##args);	\
	listptr = listptr->next;			\
      }							\
  } while (0);

#define MSG_PATH_ARG_DENIED 1 /* caller uid */
#define MSG_PERMISSION_DENIED 2 /* account, id, caller uid */
#define MSG_SHADOW_DATA_PRINTED 3 /* account, uid, caller uid */
#define MSG_UNKNOWN_GROUP 4 /* group, caller uid */
#define MSG_CHANGING_GROUP_PASSWORD 5 /* group, caller uid */
#define MSG_PASSWORD_CHANGE_ABORTED 6 /* account, caller uid */
#define MSG_MAX_GROUP_PASSWD_TRIES 7 /* group, caller uid */
#define MSG_ERROR_CHANGE_GROUP_PASSWORD 8 /* group, caller uid */
#define MSG_GROUP_PASSWORD_REMOVED 9 /* group, gid, caller uid */
#define MSG_GROUP_PASSWORD_CHANGED 10 /* group, gid, caller uid */
#define MSG_NO_FREE_GID 11 /* gid_min, gid max */
#define MSG_GID_NOT_UNIQUE 12 /* new_gid, caller uid */
#define MSG_GROUP_NAME_INVALID 13 /* group, caller uid */
#define MSG_GROUP_FILE_ALREADY_LOCKED 14 /* - */
#define MSG_GROUP_ALREADY_EXISTS 15 /* group, caller uid */
#define MSG_ERROR_ADDING_NEW_GROUP 16 /* group, gid, caller uid */
#define MSG_NEW_GROUP_ADDED 17 /* group, gid, caller uid */
#define MSG_GID_IS_PRIMARY_GROUP 18 /* gid, group, caller uid */
#define MSG_CANNOT_REMOVE_PRIMARY_GROUP 19 /* group, caller uid */
#define MSG_ERROR_REMOVING_GROUP 20 /* group, gid, caller uid */
#define MSG_GROUP_DELETED 21 /* group, gid, caller uid */
#define MSG_PASSWD_FILE_ALREADY_LOCKED 22 /* - */
#define MSG_ERROR_MODIFYING_GROUP 23 /* group, gid, caller uid */
#define MSG_USER_REMOVED_FROM_GROUP 24 /* user, group, gid, caller uid */
#define MSG_USER_ADDED_TO_GROUP 25 /* user, group, gid, caller uid */
#define MSG_GROUP_NAME_CHANGED 26 /* new name, old name, gid, caller uid */
#define MSG_GROUP_ID_CHANGED 27 /* group, new gid, old gid, caller uid */
#define MSG_PASSWORD_STATUS_FOR_ALL_DENIED 28 /* caller uid */
#define MSG_DISPLAY_PASSWORD_STATUS_FOR_ALL 29 /* caller uid */
#define MSG_UNKNOWN_USER 30 /* account, caller uid */
#define MSG_PASSWORD_CHANGE_DENIED 31 /* account, uid, caller uid */
#define MSG_DISPLAY_PASSWORD_STATUS 32 /* account, uid, caller uid */
#define MSG_PASSWORD_CHANGE_FAILED 33 /* pam error, account, uid, caller uid */
#define MSG_PASSWORD_CHANGED 34 /* account, uid, caller uid */
#define MSG_NO_FREE_UID 35 /* uid min, uid max */
#define MSG_NO_ACCOUNT_FOUND 36 /* caller uid */
#define MSG_CONFIG_DEFAULTS_CHANGED 37 /* gid, home, shell, inactive, expire, caller uid */
#define MSG_UPDATING_DEFAULT_CONFIG_FAILED 38 /* config file, caller uid */
#define MSG_UID_NOT_UNIQUE 39 /* new_uid, caller uid */
#define MSG_USER_NAME_INVALID 40 /* account, caller uid */
#define MSG_USER_ALREADY_EXISTS 41 /* account, caller uid */
#define MSG_NEW_USER_ADDED 42 /* account, uid, gid, home, shell, caller uid */
#define MSG_HOME_DIR_CREATED 43 /* account, uid, home, caller uid */
#define MSG_CALL_SCRIPT 44 /* variable, script, name, uid, gid, home, caller uid */
#define MSG_ERROR_REMOVE_USER_FROM_GROUP 45 /* account, uid, group, gid, caller uid */
#define MSG_NOT_OWNED_BY_USER 46 /* file, account, uid, caller uid */
#define MSG_HOME_DIR_REMOVED 47 /* account, uid, home, caller uid */
#define MSG_ERROR_REMOVING_USER 48 /* account, uid, caller uid */
#define MSG_USER_DELETED 49 /* account, uid, caller uid */
#define MSG_ERROR_RENAME_USER_IN_GROUP 50 /* account, uid, group, gid, caller uid */
#define MSG_USER_RENAMED_IN_GROUP 51 /* account, old account, uid, group, gid, caller uid */
#define MSG_ERROR_MODIFYING_USER 52 /* account, uid, caller uid */
#define MSG_ACCOUNT_IN_USE 53 /* account, uid, caller uid */
#define MSG_USER_NAME_CHANGED 54 /* new account, old account, uid, caller uid */
#define MSG_USER_ID_CHANGED 55 /* account, new id, old id, caller id */
#define MSG_GECOS_CHANGED 56 /* account, id, new gecos, old gecos, caller id */
#define MSG_PRIMARY_GROUP_CHANGED 57 /* account, id, new gid, old gid, caller id */
#define MSG_HOME_DIR_CHANGED 58 /* account, id, new home, old home, caller id */
#define MSG_SHELL_CHANGED 59 /* account, id, new shell, old shell, caller id */
#define MSG_INACTIVE_DAYS_CHANGED 60 /* account, id, inactive days, old value, caller id */
#define MSG_EXPIRE_DATE_CHANGED 61 /* account, id, expire date, old date, caller id */
#define MSG_DROP_PRIVILEGE_FAILED 62 /* errno, caller id */
#define MSG_MAIL_FILE_CREATED 63 /* account, caller id */
#define MSG_MINIMUM_AGE 64 /* account, uid, min, old min, caller id */
#define MSG_MAXIMUM_AGE 65 /* account, uid, max, old max, caller id */
#define MSG_WARNING_DAYS 66 /* account, uid, warn, old warn, caller id */
#define MSG_INACTIVE_DAYS 67 /* account, uid, inactive, old inactive, caller id */
#define MSG_LAST_CHANGE_DATE 68 /* account, uid, change, old change, caller id */
#define MSG_EXPIRE_DATE 69 /* account, uid, expire, old expire, caller id */
#define MSG_STDIN_FOR_NONROOT_DENIED 70 /* caller id */

#endif
