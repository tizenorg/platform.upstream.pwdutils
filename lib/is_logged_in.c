/* Copyright (C) 2003, 2005 Thorsten Kukuk
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

#include <utmp.h>
#include <string.h>

#include "i18n.h"
#include "public.h"

/* Check if the user is logged in.
    0: user is not logged in
    1: user is logged in
*/
int
is_logged_in (const char *user)
{
  struct utmp *utp;

  setutent ();
  while ((utp = getutent ()))
    {
      if (utp->ut_type == USER_PROCESS &&
	  strncmp (utp->ut_user, user, sizeof utp->ut_user) == 0)
	return 1;
    }
  return 0;
}
