/* Copyright (C) 2004, 2005, 2008 Thorsten Kukuk
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

typedef struct msg_table_entry {
  const char *msg;
  int result;
} msg_table_entry_t;

static msg_table_entry_t msg_table[] = {
  /*  0 */ {"NULL", 0},
  /*  1 */ {"path specification denied - by=%u", 0},
  {"permission denied - account=%s, id=%u, by=%u", 0},
  {"password aging information displayed - account=%s, uid=%u, by=%u", 1},
  {"group is unknown - group=%s, by=%u", 0},
  {"user changing the password for group - group=%s, by=%u", 1},
  {"password change aborted - for=%s, by=%u", 0},
  {"password modification exceeded max tries, aborted - group=%s, by=%u", 0},
  {"failed to change group password - group=%s, by=%u", 0},
  {"group password removed - group=%s, gid=%u, by=%u", 1},
  /* 10 */ {"group password changed - group=%s, gid=%u, by=%u", 1},
  {"can't get unique gid in range %u - %u", 0},
  {"GID %u is not unique - by=%u", 0},
  {"invalid name - group=%s, by=%u", 0},
  {"cannot lock group file: already locked", 0},
  {"group already exists - group=%s, by=%u", 0},
  {"failed to add new group - group=%s, gid=%u, by=%u", 0},
  {"new group added - group=%s, gid=%u, by=%u", 1},
  {"GID `%u' is primary group of `%s' - by=%u", 1},
  {"cannot remove user's primary group - group=%s, by=%u", 0},
  /* 20 */ {"failed to delete group - group=%s, gid=%u, by=%u", 0},
  {"group deleted - group=%s, gid=%u, by=%u", 1},
  {"cannot lock password file: already locked", 0},
  {"failed to modify group - group=%s, gid=%u, by=%u", 0},
  {"account removed from group - account=%s, group=%s, gid=%u, by=%u", 1},
  {"account added to group - account=%s, group=%s, gid=%u, by=%u", 1},
  {"group name changed  - group=%s, old group=%s, gid=%u, by=%u", 1},
  {"group gid changed - group=%s, gid=%u, old gid=%u, by=%u", 1},
  {"password status display for all users denied - by=%u", 0},
  {"password status displayed for all users - by=%u", 1},
  /* 30 */ {"account is unknown - account=%s, by=%u", 0},
  /* 31 */ {"password change denied - account=%s, uid=%u, by=%u", 0},
  /* 32 */ {"password status displayed - account=%s, uid=%u, by=%u", 1},
  /* 33 */ {"password change failed, pam error %d - account=%s, uid=%u, by=%u", 0},
  /* 34 */ {"password changed - account=%s, uid=%u, by=%u", 1},
  /* 35 */ {"can't get unique uid in range %u - %u", 0},
  /* 36 */ {"cannot determine account name - uid=%u", 0},
  /* 37 */ {"defaults changed - gid=%u, home=%s, shell=%s, inactive=%li, expire=%s, by=%u", 1},
  /* 38 */ {"updating default config file `%s' faild - by=%u", 0},
  /* 39 */ {"UID %u is not unique - by=%u", 0},
  /* 40 */ {"invalid name - account=%s, by=%u", 0},
  {"account already exists - account=%s, by=%u", 0},
  {"new account added - account=%s, uid=%u, gid=%u, home=%s, shell=%s, by=%u", 1},
  {"home directory created - account=%s, uid=%u, home=%s, by=%u", 1},
  {"running %s command - script=%s, account=%s, uid=%u, gid=%u, home=%s, by=%u", 1},
  {"error removing account from group - account=%s, uid=%u, group=%s, gid=%u, by=%u", 0},
  {"`%s' is not owned by user, not removed - account=%s, uid=%u, by %u", 0},
  {"home directory deleted - account=%s, uid=%u, home=%s, by=%u", 1},
  {"failed to delete account - account=%s, uid=%u, by=%u", 0},
  {"account deleted - account=%s, uid=%u, by=%u", 1},
  /* 50 */ {"error renaming account in group - account=%s, uid=%u, group=%s, gid=%u, by=%u", 0},
  /* 51 */ {"account name renamed in group - new=%s, old=%s, uid=%u, group=%s, gid=%u, by=%u", 1},
  /* 52 */ {"failed to modify account - account=%s, uid=%u, by=%u", 0},
  /* 53 */ {"account is currently in use - account=%s, uid=%u, by=%u", 0},
  /* 54 */ {"account name changed - new=%s, old=%s, uid=%u, by=%u", 1},
  /* 55 */ {"UID changed - account=%s, new id=%u, old id=%u, by=%u", 1},
  /* 56 */ {"account GECOS changed - account=%s, uid=%u, GECOS='%s', old GECOS='%s', by=%u", 1},
  /* 57 */ {"default group changed - account=%s, uid=%u, gid=%u, old gid=%u, by=%u", 1},
  /* 58 */ {"home directory changed - account=%s, uid=%u, home=%s, old home=%s, by=%u", 1},
  /* 59 */ {"shell changed - account=%s, uid=%u, shell=%s, old shell=%s, by=%u", 1},
  /* 60 */ {"inactive days changed - account=%s, uid=%u, inactive=%li, old=%li, by=%u", 1},
  /* 61 */ {"expiration date changed - account=%s, uid=%u, expire=%s, old date=%s, by=%u", 1},
  /* 62 */ {"failed to drop privileges, errno=%d - by=%u", 0},
  /* 63 */ {"mail spool file created - account=%s, by=%u", 1},
  /* 64 */ {"password minimum age changed - account=%s, uid=%u, min=%li, old min=%li, by=%u", 1},
  /* 65 */ {"password maximum age changed - account=%s, uid=%u, max=%li, old max=%li, by=%u", 1},
  /* 66 */ {"password warning days changed - account=%s, uid=%u, warn=%li, old warn=%li, by=%u", 1},
  /* 67 */ {"password inactive days changed - account=%s, uid=%u, inactive=%li, old inactive=%li, by=%u", 1},
  /* 68 */ {"password last change date changed - account=%s, uid=%u, change=%s, old change=%s, by=%u", 1},
  /* 69 */ {"password expiration date changed - account=%s, uid=%u, expire=%s, old expire=%s, by=%u", 1},
  /* 70 */ {"user tried to set the password from stdin - by=%u", 0}};
