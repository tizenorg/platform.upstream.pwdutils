/* Copyright (C) 2002, 2004 Thorsten Kukuk
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

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "public.h"
#include "utf8conv.h"

/* prompt the user with the name of the field being changed and the
   current value.
   return value:
   NULL -> Ctrl-D was pressed
   "" -> Field was cleard by user. User can enter a space or
         "none" to do this.
   oldf -> User entered only <return>.
   newf -> User entered something new . */
char *
get_value (const char *oldf, const char *prompt)
{
  char newf[BUFSIZ];
  char *cp;
  char *locstr;

  locstr = oldf ? utf8_to_locale (oldf) : strdup ("");
  printf ("\t%s [%s]: ", prompt, locstr);
  free (locstr);
  if (fgets(newf, sizeof (newf), stdin) != newf)
    {
      /* print newline to get defined output.  */
      printf ("\n");
      return NULL;
    }

  if ((cp = strchr(newf, '\n')) != NULL)
    *cp = '\0';

  if (newf[0]) /* something is entered */
    {
      /* if none is entered, return an empty string. If somebody
	 wishes to enter "none", he as to add a space.  */
      if (strcasecmp ("none", newf) == 0)
	return strdup ("");

      /* Remove leading and trailing whitespace. This also
	 makes it possible to change the field to empty or
	 "none" by entering a space.  */

      /* cp should point to the trailing '\0'.  */
      cp = &newf[strlen(newf)];

      while (--cp >= newf && isspace(*cp))
	;
      *++cp = '\0';

      cp = newf;
      while (*cp && isspace(*cp))
	cp++;

      return locale_to_utf8 (cp);
    }
  return strdup (oldf ?:"");
}

#ifdef TEST
int
main (int argc, char **argv)
{
  char *cp;

  cp = get_value ("test", "t1");

  printf("cp=\"%s\"\n", cp);

  return 0;
}
#endif
