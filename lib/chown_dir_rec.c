/* Copyright (C) 2003, 2005, 2012 Thorsten Kukuk
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#include "i18n.h"
#include "public.h"

static inline int
chown_entry (const char *entry, struct stat *st,
	     uid_t old_uid, uid_t new_uid, gid_t old_gid, gid_t new_gid)
{
  uid_t use_uid;
  gid_t use_gid;

  if (st->st_uid == old_uid)
    use_uid = new_uid;
  else
    use_uid = st->st_uid;

  if (st->st_gid == old_gid)
    use_gid = new_gid;
  else
    use_gid = st->st_gid;

  if (use_uid != st->st_uid || use_gid != st->st_gid)
    {
      if (lchown (entry, use_uid, use_gid) < 0)
	{
	  fprintf (stderr,
		   _("Cannot change owner/group for `%s': %s\n"),
		   entry, strerror (errno));
	  return -1;
	}
    }
  return 0;
}

/* This function walks a directory tree and changes the ownership
   and group of all files owned by the provided old ID's.  */
int
chown_dir_rec (const char *src, uid_t old_uid, uid_t new_uid,
	       gid_t old_gid, gid_t new_gid)
{
  struct dirent *entry;
  DIR *dir = opendir (src);
  struct stat st;
  int retval = 0;

  if (dir == NULL)
    return -1;

  while ((entry = readdir (dir)) != NULL)
    {
      /* Skip "." and ".." directory entries.  */
      if (strcmp (entry->d_name, ".") == 0 ||
          strcmp (entry->d_name, "..") == 0)
        continue;
      else
        {
          char srcfile[strlen (src) + strlen (entry->d_name) + 2];
	  char *cp;

          /* create source and destination filename with full path.  */
          cp = stpcpy (srcfile, src);
          *cp++ = '/';
          strcpy (cp, entry->d_name);

          if (lstat (srcfile, &st) != 0)
            continue;

	  if (S_ISDIR(st.st_mode))
	    retval = chown_dir_rec (srcfile, old_uid, new_uid,
				      old_gid, new_gid);
	  else
	    retval = chown_entry (srcfile, &st, old_uid, new_uid,
				  old_gid, new_gid);
	}
    }

  if (lstat (src, &st) == 0)
    retval = chown_entry (src, &st, old_uid, new_uid, old_gid, new_gid);

  closedir (dir);
  return retval;
}
