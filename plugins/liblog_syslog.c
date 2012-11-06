/* Copyright (C) 2004,2005, 2008 Thorsten Kukuk
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
#include "logging.h"
#include "msg_table.h"

void syslog_sec_log (const char *program, unsigned int id, ...);
void syslog_open_sec_log (const char *arguments);

void
syslog_sec_log (const char *program __attribute__((unused)),
		  unsigned int id, ...)
{
  va_list ap;

  if (id > sizeof (msg_table) / sizeof (char *))
    abort ();

  va_start (ap, id);
  if (msg_table[id].msg != NULL)
    vsyslog (LOG_INFO, msg_table[id].msg, ap);

  va_end (ap);
}

void
syslog_open_sec_log (const char *arguments __attribute__((unused)))
{
  return;
}
