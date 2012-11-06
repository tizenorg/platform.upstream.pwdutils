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
#include "config.h"
#endif

#include <utmp.h>
#include <stdio.h>
#include <string.h>
#include <regex.h>

#include "i18n.h"
#include "public.h"
#include "logindefs.h"

/* Return 0 if name is POSIX conform, -1 else.  */
int
check_name (const char *name)
{
  const char *class;
  regex_t reg;
  int result;
  char *buf;

  /* The login name/group name should not be longer than the space we
     have for it in the utmp entry.  */
  if (strlen (name) > UT_NAMESIZE)
    return -1;

  /* User/group names must match [A-Za-z_][A-Za-z0-9_-.]*[A-Za-z0-9_-.$]?.
     This is the POSIX portable character class. The $ at the end is
     needed for SAMBA. But user can also specify something else in
     /etc/login.defs.  */
  class = getlogindefs_str ("CHARACTER_CLASS",
			    "[A-Za-z_][A-Za-z0-9_.-]*[A-Za-z0-9_.$-]\\?");

  if (class == NULL || strlen (class) == 0)
    return 0;

  if (asprintf (&buf, "^%s$", class) < 0)
    return -1;

  memset (&reg, 0, sizeof (regex_t));
  result = regcomp (&reg, buf, 0);
  free (buf);

  if (result)
    {
      size_t length = regerror (result, &reg, NULL, 0);
      char *buffer = malloc (length);
      if (buffer == NULL)
	fputs ("running out of memory!\n", stderr);
      else
	{
	  regerror (result, &reg, buffer, length);
	  fprintf (stderr, _("Can't compile regular expression: %s\n"),
		   buffer);
	  return -1;
        }
    }

  if (regexec (&reg, name, 0, NULL, 0) != 0)
    return -1;

  return 0;
}
