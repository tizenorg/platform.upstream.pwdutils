/* Copyright (C) 2003, 2005, 2010 Thorsten Kukuk
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

/* Recursive copy of a directory. Return values:
   -1: Error occured, remove the tree.
    0: No error.
    1: There was on error in a deeper level, this is only informative.
*/
int
copy_dir_rec (const char *src, const char *dst, int preserve_id,
	      uid_t uid, gid_t gid)
{
  struct dirent *entry;
  DIR *dir = opendir (src);
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
	  char dstfile[strlen (dst) + strlen (entry->d_name) + 2];
	  struct stat st;
	  char *cp;

	  /* create source and destination filename with full path.  */
	  cp = stpcpy (srcfile, src);
	  *cp++ = '/';
	  strcpy (cp, entry->d_name);

	  cp = stpcpy (dstfile, dst);
	  *cp++ = '/';
	  strcpy (cp, entry->d_name);

	  if (lstat (srcfile, &st) != 0)
	    continue;

	  if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
	    {
	      if (mknod (dstfile, st.st_mode & ~07777, st.st_rdev) != 0)
		{
		  fprintf (stderr, _("Can't create `%s': %m\n"),
			   dstfile);
		  retval = 1;
		}
	      else if (chown (dstfile,
			      preserve_id ? st.st_uid : uid,
			      preserve_id ? st.st_gid : gid) != 0 ||
		       chmod (dstfile, st.st_mode & 07777) != 0)
		{
		  unlink (dstfile);
		  retval = 1;
		}
	      else if (copy_xattr (srcfile, dstfile) != 0)
		{
		  unlink (dstfile);
		  retval = 1;
		}
	    }
	  else if (S_ISDIR(st.st_mode))
	    {
	      if (mkdir (dstfile, 0) != 0)
		{
		  fprintf (stderr, _("Cannot create directory `%s': %s\n"),
			   dstfile, strerror (errno));
		  retval = 1;
		}
	      else
		{
		  retval = copy_dir_rec (srcfile, dstfile,
					 preserve_id, uid, gid);
		  if (retval < 0 ||
		      chown (dstfile,
			     preserve_id ? st.st_uid : uid,
			     preserve_id ? st.st_gid : gid) != 0 ||
		      chmod (dstfile, st.st_mode & 07777) != 0)
		    {
		      fprintf (stderr, _("Cannot change permissions for `%s': %s\n"),
			       dstfile, strerror (errno));
		      /* An error occured, remove the new subtree.  */
		      remove_dir_rec (dstfile);
		      retval = 1;
		    }
		  else if (copy_xattr (srcfile, dstfile) != 0)
		    {
		      remove_dir_rec (dstfile);
		      retval = 1;
		    }
		}
	    }
	  else if (S_ISLNK(st.st_mode))
	    {
	      char buffer[4096];
	      int len = readlink (srcfile, buffer, sizeof (buffer));

	      if (len < 0)
		retval = 1;
	      else
		{
		  buffer[len] = '\0';
		  if (symlink (buffer, dstfile) != 0)
		    {
		      fprintf (stderr, _("Cannot create symlink `%s': %s\n"),
			       dstfile, strerror (errno));
		      retval = 1;
		    }
		  else if (lchown (dstfile,
				   preserve_id ? st.st_uid : uid,
				   preserve_id ? st.st_gid : gid) != 0)
		    {
		      fprintf (stderr,
                               _("Cannot change owner/group for `%s': %s\n"),
			       dstfile, strerror (errno));
		      unlink (dstfile);
		      retval = 1;
		    }
		  else if (copy_xattr (srcfile, dstfile) != 0)
		    {
		      unlink (dstfile);
		      retval = 1;
		    }
		}
	    }
	  else if (S_ISREG(st.st_mode))
	    /* Here we should only copy regular files.  */
	    {
	      int src_fd, dst_fd;

	      src_fd = open (srcfile, O_RDONLY);
	      if (src_fd < 0)
		{
		  retval = 1;
		  continue;
		}
	      dst_fd = open (dstfile, O_WRONLY|O_CREAT|O_TRUNC, 0);
	      if (dst_fd < 0)
		{
		  close (src_fd);
		  retval = 1;
		}
	      else
		{
		  char buffer[4096];
		  int cnt;

		  while ((cnt = read (src_fd, buffer, sizeof (buffer))) > 0)
		    {
		      if (write (dst_fd, buffer, cnt) != cnt)
			{
			  fprintf (stderr, _("Cannot copy `%s': %s\n"),
				   srcfile, strerror (errno));
			  cnt = -1;
			  break;
			}
		    }
		  close (src_fd);
		  close (dst_fd);
		  if (cnt < 0 /* Remove file if copy failed. */ ||
		      chown (dstfile,
			     preserve_id ? st.st_uid : uid,
			     preserve_id ? st.st_gid : gid) != 0 ||
		      chmod (dstfile, st.st_mode & 07777))
		    {
		      fprintf (stderr, _("Cannot change permissions for `%s': %s\n"),
			       dstfile, strerror (errno));
		      unlink (dstfile);
		      retval = 1;
		    }
		  else if (copy_xattr (srcfile, dstfile) != 0)
		    {
		      unlink (dstfile);
		      retval = 1;
		    }
		}
	    }
	  else
	    {
	      /* skip all other types: FIFO, socket, ... */
	      fprintf (stderr,
		       _("Warning: ignoring `%s', not a regular file\n"),
		       srcfile);
	    }
	}
    }

  closedir (dir);

  return retval;
}
