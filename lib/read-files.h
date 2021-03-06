/* Copyright (C) 2003 Thorsten Kukuk
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

#ifndef __READ_FILES_H__
#define __READ_FILES_H__

#include <grp.h>
#include <pwd.h>
#include <nss.h>
#include <shadow.h>

extern char *files_etc_dir;

enum nss_status files_getpwnam_r (const char *name, struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop);
enum nss_status files_getpwuid_r (uid_t uid, struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop);
enum nss_status files_getspnam_r (const char *name, struct spwd *result,
		  		  char *buffer, size_t buflen, int *errnop);
enum nss_status files_getpwent_r (struct passwd *result, char *buffer,
				  size_t buflen, int *errnop);
enum nss_status files_getspent_r (struct spwd *result, char *buffer,
                                  size_t buflen, int *errnop);

enum nss_status files_getgrnam_r (const char *name, struct group *result,
                                  char *buffer, size_t buflen, int *errnop);
enum nss_status files_getgrgid_r (uid_t uid, struct group *result,
                                  char *buffer, size_t buflen, int *errnop);
enum nss_status files_getgrent_r (struct group *result, char *buffer,
				  size_t buflen, int *errnop);

int parse_pwent (char *line, struct passwd *result, int strict);
int parse_spent (char *line, struct spwd *result, int strict);
int parse_grent (char *line, struct group *result,
		 char *buffer, size_t buflen, int *errnop, int strict);

#endif /* __PUBLIC_H__ */
