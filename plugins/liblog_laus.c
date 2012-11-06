/* Copyright (C) 2004, 2005 Thorsten Kukuk
   Author: Thorsten Kukuk <kukuk@thkukuk.de>

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
#include <config.h>
#endif

#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>
#include <laus.h>

#include "logging.h"

#include "msg_table.h"

void laus_sec_log (const char *program, unsigned int id, ...);
void laus_open_sec_log (const char *arguments);

static int __laus_active;

void
laus_sec_log (const char *program, unsigned int id, ...)
{
  va_list ap;
  int rc;
  char *buf = NULL;

  if (id > sizeof (msg_table) / sizeof (char *))
    abort ();

  if(!__laus_active)
    return;

  va_start (ap, id);
  if (msg_table[id] != NULL)
    {
      if (vasprintf (&buf, msg_table[id], ap) < 0)
	{
	  int err = errno;

	  syslog(LOG_WARNING,
		 "LAuS error - %s:%i - laus_log: (%i) %s\n",
		 __FILE__, __LINE__,
		 err, laus_strerror(err));
	  return;
	}
      rc = laus_log (NO_TAG, "%s: %s", program, buf);
      free (buf);
      if (rc < 0)
	{
	  int err = errno;

	  syslog(LOG_WARNING,
		 "LAuS error - %s:%i - laus_log: (%i) %s\n",
		 __FILE__, __LINE__,
		 err, laus_strerror(err));
	}
    }
  va_end (ap);
}

void
laus_open_sec_log (const char *arguments __attribute__((unused)))
{
  int rc = laus_open (NULL);
  if (rc < 0)
    {
      int err = errno;

      syslog(LOG_WARNING,
	     "LAuS error - %s:%i - laus_open: (%i) %s\n",
	     __FILE__, __LINE__,
	     err, laus_strerror(err));
      __laus_active = 0;
    }
  else
    __laus_active = 1;

  return;
}
