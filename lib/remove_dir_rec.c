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

/* Recursive removeal of a directory and subdirectories. Return values:
   -1: Error occured.
    0: No error.
*/
int
remove_dir_rec (const char *tree)
{
  struct dirent *entry;
  DIR *dir = opendir (tree);
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
	  char srcfile[strlen (tree) + strlen (entry->d_name) + 2];
	  struct stat st;
	  char *cp;

	  /* create source and destination filename with full path.  */
	  cp = stpcpy (srcfile, tree);
	  *cp++ = '/';
	  strcpy (cp, entry->d_name);

	  if (lstat (srcfile, &st) != 0)
	    continue;

	  if (S_ISDIR(st.st_mode))
	    {
	      if (remove_dir_rec (srcfile) != 0)
		retval = -1;

	    }
	  else if (unlink (srcfile) != 0)
	    {
	      fprintf (stderr, _("Cannot remove file `%s': %s\n"),
		       srcfile, strerror (errno));
	      retval = -1;
	    }
	}
    }

  if (rmdir (tree) != 0)
    {
      fprintf (stderr, _("Cannot remove directory `%s': %s\n"),
	       tree, strerror (errno));
      retval = -1;
    }

  closedir (dir);

  return retval;
}
