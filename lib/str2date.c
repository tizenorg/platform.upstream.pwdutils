/* Copyright (C) 2003, 2004 Thorsten Kukuk
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

#define _XOPEN_SOURCE 600

#include <time.h>
#include <stdio.h>
#include <string.h>

#include "public.h"

/* convert a string to a time_t value and return it as number
   of days since 1.1.1970.  */
long int
str2date (const char *str)
{
  struct tm tp;
  char *cp;
  time_t result;

  memset (&tp, 0, sizeof tp);
  cp = strptime (str, "%Y-%m-%d", &tp);
  if (!cp || *cp != '\0')
    return -1;

  result = mktime (&tp);
  if (result == (time_t) -1)
    return -1;

  return (result + (DAY/2)) / DAY;
}
