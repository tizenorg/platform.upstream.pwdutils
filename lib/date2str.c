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

#include <time.h>
#include <stdio.h>
#include <string.h>

#include "public.h"

/* convert time_t into a readable date string.  */
char *
date2str (time_t date)
{
  struct tm *tp;
  char buf[12];

  tp = gmtime (&date);
#ifdef HAVE_STRFTIME
  strftime (buf, sizeof (buf), "%Y-%m-%d", tp);
#else
  snprintf (buf, sizeof (buf), "%04d-%02d-%02d",
	    tp->tm_year + 1900, tp->tm_mon + 1, tp->tm_mday);
#endif
  return strdup (buf);
}

