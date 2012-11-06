/* Copyright (C) 2004 Thorsten Kukuk
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
#include <stdlib.h>
#include <limits.h>

#include "public.h"

/* convert string into a UID/GID.  */
int
strtoid (const char *arg, uint32_t *idptr)
{
  long long val;
  char *cp;

  val = strtoll (arg, &cp, 10);
  if (*cp != '\0' ||
      ((val == LONG_LONG_MAX || val == LONG_LONG_MIN) && errno == ERANGE)
      || val > (UINT_MAX - 1) || val < 0)    /* invalid number */
    /* (UINT_MAX -1), because we cannot chown a file to
       UINT_MAX, which is equal to -1, which mean chown will
       not change the file owner at all.  */
    return -1;

  *idptr = val;

  return 0;
}
