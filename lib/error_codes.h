/* Copyright (C) 2002, 2003 Thorsten Kukuk
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

#ifndef __ERROR_CODES_H__
#define __ERROR_CODES_H__

/*
 * exit status values
 */

#define E_SUCCESS        0	/* Success */
#define E_NOPERM         1	/* Permission denied */
#define E_USAGE          2	/* Invalid combination of options */
#define E_FAILURE        3	/* Unexpected failure, nothing done */
#define E_MISSING        4	/* Unexpected failure, passwd file missing */
#define E_PWDBUSY        5	/* passwd file busy, try again later */
#define E_BAD_ARG        6	/* Invalid argument to option */
#define E_PAM_ERROR      7	/* PAM returns with an error */
#define E_NO_LOCAL_USER  8	/* The user is not in the local shadow file */
#define E_NAME_IN_USE	 9	/* The user does already exist */
#define E_GRP_UPDATE	10	/* Updating group file failed */
#define E_UID_IN_USE	11	/* The given user ID does already exist */
#define E_HOMEDIR       12	/* Cannot create Home Directory */
#define E_LOGIN_DEFS	13	/* /etc/login.defs read/write failure */
#define E_NOTFOUND	14	/* Specified group not found */
#define E_USER_BUSY	15	/* User currently logged in */
#define E_GID_IN_USE	16	/* The given group ID does already exist */
#define E_GROUP_BUSY	17	/* Group is primary group of an user */
#define E_NO_SHADOW	18	/* User does not have a shadow entry */
#define E_MAIL_SPOOL	19	/* Can't create mail spool */

#define E_WRONG_VERSION 21	/* Protocol mismatch on server */
#define E_UNKNOWN_USER	22	/* User is not known on server */
#define E_SSL_FAILURE   23      /* SSL error, nothing done */

#endif

