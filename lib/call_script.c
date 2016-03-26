/* Copyright (C) 2003, 2004, 2005, 2008 Thorsten Kukuk
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
#include <config.h>
#endif

#include <grp.h>
#include <pwd.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

#include "i18n.h"
#include "public.h"
#include "logging.h"
#include "logindefs.h"

/* call_script reads the command to be called for "variable"
   from /etc/login.defs. */
int
call_script (const char *variable, const char *name, uid_t uid,
	     gid_t gid, const char *home, const char *program)
{
  const char *script;
  int status;
  pid_t child_pid;

  script = getlogindefs_str (variable, NULL);

  if (script == NULL || *script == '\0')
    return 0;

  sec_log (program, MSG_CALL_SCRIPT,
	   variable, script, name, uid, gid, home?home:"", getuid ());

  switch ((child_pid = fork ()))
    {
    case 0: /* Child.  */
      {
	char *uid_s, *gid_s;

	if (asprintf (&uid_s, "%u", uid) < 0)
	  return ENOMEM;
	if (asprintf (&gid_s, "%u", gid) < 0)
	  return ENOMEM;

	execl (script, script, name, uid_s, gid_s, home, (char *) 0);
	perror (script);
	_exit (1);
      }
    case -1: /* Error occurs.  */
      fprintf (stderr, _("Cannot fork: %s\n"), strerror (errno));
      return -1;
      break;
    default: /* Parent.  */
      while (waitpid (child_pid, &status, 0) == -1)
        {
          int err = errno;
          if (err != EINTR)
            fprintf (stderr, _("waitpid (%d) failed: %s\n"),
                     child_pid, strerror (err));
        }
      break;
    }
  return status;
}
