/* Copyright (C) 2002, 2003, 2004, 2005 Thorsten Kukuk
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

#include <errno.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include "i18n.h"
#include "public.h"
#include "logindefs.h"

int
do_authentication (const char *prog, const char *caller, user_t *pw_data)
{
  /* If the user needs to authenticate itself, let PAM do the job.  */
  pam_handle_t *pamh = NULL;
  struct pam_conv conv = { misc_conv, NULL };
  int retcode;
  const char *cp;

  retcode = pam_start (prog, caller, &conv, &pamh);
  if (retcode != PAM_SUCCESS)
    {
      openlog (prog, LOG_PID, LOG_AUTHPRIV);
      fprintf (stderr, _("%s: PAM Failure, aborting: %s\n"),
	       prog, pam_strerror (pamh, retcode));
      syslog (LOG_ERR, "Couldn't initialize PAM: %s",
	      pam_strerror (pamh, retcode));
      return 1;
    }

  retcode = pam_authenticate (pamh, 0);
  if (retcode != PAM_SUCCESS)
    {
    bailout:
      openlog (prog, LOG_PID, LOG_AUTHPRIV);
      syslog (LOG_ERR, "User %s: %s", caller,
	      pam_strerror (pamh, retcode));
      sleep (getlogindefs_num ("FAIL_DELAY", 1));
      fprintf(stderr, "%s\n", pam_strerror (pamh, retcode));
      return 1;
    }

  retcode = pam_acct_mgmt (pamh, 0);
  if (retcode == PAM_NEW_AUTHTOK_REQD)
    retcode = pam_chauthtok (pamh, PAM_CHANGE_EXPIRED_AUTHTOK);
  if (retcode != PAM_SUCCESS)
    goto bailout;

  retcode = pam_setcred (pamh, 0);
  if (retcode != PAM_SUCCESS)
    goto bailout;

  if (pw_data)
    {
      cp = pam_getenv (pamh, "PAM_AUTHTOK");
      if (cp)
	pw_data->oldclearpwd = strdup (cp);
    }

  pam_end (pamh, 0);

  openlog (prog, LOG_PID, LOG_AUTHPRIV);

  return 0;
}

int
get_old_clear_password (user_t *pw_data)
{
  /* If we don't have the clear password, the user don't need to
     authenticate or we don't use a PAM module which gives us the
     password.  */
  if (pw_data->oldclearpwd == NULL)
    {
      char prompt[130];
      char *cp;

      snprintf (prompt, sizeof (prompt), _("Enter login(%s) password:"),
		nsw2str (pw_data->service));
      cp = getpass (prompt);
      pw_data->oldclearpwd = strdup (cp);
    }
  return 0;
}
