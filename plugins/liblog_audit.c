/* Copyright (C) 2005, 2008 Thorsten Kukuk
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

#include <errno.h>
#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "logging.h"
#include "msg_table.h"

#include <libaudit.h>

void audit_sec_log (const char *program, unsigned int id, ...);
void audit_open_sec_log (const char *arguments);

static int audit_fd = -1;

void
audit_sec_log (const char *program __attribute__((unused)),
		  unsigned int id, ...)
{
  char buffer[1024 * 8];
  va_list ap;

  if (id > sizeof (msg_table) / sizeof (char *))
    abort ();

  if (msg_table[id].msg == NULL)
    return;

  va_start (ap, id);
  vsnprintf (buffer, sizeof (buffer), msg_table[id].msg, ap);
  va_end (ap);

  errno = 0;
  audit_fd = audit_open ();
  if (audit_fd < 0)
    {
      /* You get ECONNREFUSED only when the kernel doesn't have
	 audit compiled in. Otherwise, this should only fail in
	 case of extreme resource shortage, need to prevent login
	 in that case for CAPP compliance. */
      if (errno != ECONNREFUSED)
	syslog (LOG_CRIT, "audit_open() failed: %s", strerror(errno));
    }
  else
    {
      /* audit_log_acct_message(int audit_fd, int type,
		const char *pgname, const char *op, const char *name,
                unsigned int id,  const  char  *host,
                const char *addr, const char *tty, int result);
      */
      int retval = audit_log_acct_message(audit_fd, AUDIT_USER_CHAUTHTOK,
               program, buffer, NULL,
               id, NULL,
               NULL, NULL, msg_table[id].result);
      audit_close (audit_fd);

      if (retval > 0)
	return;
    }

  /* Seems audit subsystem is not enabled */
  syslog (LOG_NOTICE, "%s", buffer);
}

void
audit_open_sec_log (const char *arguments __attribute__((unused)))
{
  return;
}
