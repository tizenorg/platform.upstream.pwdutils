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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "public.h"

/* Check, if new home directory is a valid path. Don't allow
   files or special passwd delimeter in path.  */
int
check_home (const char *home)
{
  struct stat st;

  if (strcspn (home, ":\n") != strlen (home) || *home != '/' ||
      (stat (home, &st) == 0 && !S_ISDIR(st.st_mode)))
    return -1;

  return 0;
}
