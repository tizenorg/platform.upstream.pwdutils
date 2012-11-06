/* Copyright (C) 2003, 2005 Thorsten Kukuk
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

#ifndef __GROUP_H__
#define __GROUP_H__

#include <grp.h>
#include <public.h>
#include <sys/cdefs.h>

#ifndef __attribute_warn_unused_result__
#define __attribute_warn_unused_result__
#endif

struct group_t {
  todo_t todo;
  char *grpbuffer;
  size_t grpbuflen;
  struct group gr;
  int use_gshadow;
  enum service_t service;
  char *new_name;
  int have_new_gid;
  gid_t new_gid;
  char *newpassword;
  char *oldclearpwd;
  char **new_gr_mem;
  char *binddn;
};
typedef struct group_t group_t;

extern void free_group_t (group_t *data);
extern group_t *find_group_data (const char *group, gid_t gid,
				 const char *use_service);
extern int write_group_data (group_t *data, int is_locked) __attribute_warn_unused_result__;

#endif /* __GROUP_H__ */
