/* Copyright (C) 2004, 2005 Thorsten Kukuk
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

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#ifdef USE_LDAP

#include <unistd.h>
#include <string.h>

#include "i18n.h"
#include "libldap.h"

char *
get_caller_dn (void)
{
  /* A user tries to add an account stored in a LDAP database and
     knows the Manager dn, now we need the password from him.  */
  ldap_session_t *session = create_ldap_session (LDAP_PATH_CONF);
  struct passwd *pw;
  char *cp;

  if (session == NULL)
    return NULL;

  pw = getpwuid (getuid ());

  cp = convert_user_to_dn (session, strdupa (pw->pw_name));

  close_ldap_session (session);

  return cp;
}

#endif
