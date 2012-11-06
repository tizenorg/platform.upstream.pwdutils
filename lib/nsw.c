/* Copyright (C) 2002, 2003 Thorsten Kukuk
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nsw.h"

#define PATH_NSWCONF "/etc/nsswitch.conf"

static FILE *nssfile = NULL;

static int
setnswent (void)
{
  if (nssfile)
    fclose (nssfile);

  nssfile = fopen (PATH_NSWCONF, "r");

  return (nssfile == NULL ? -1 : 0);
}

static void
endnswent (void)
{
  if (nssfile)
    {
      fclose (nssfile);
      nssfile = NULL;
    }
}

static struct nsw *
getnswent (void)
{
  struct nsw *nswb;
  char buf[1024];
  char *cp, *tmp;
  int count;

  if (!nssfile)
    setnswent ();


  if (nssfile == NULL)
    return NULL;

  nswb = calloc (1, sizeof (struct nsw));

  do {
    cp = fgets (buf, sizeof (buf), nssfile);
    if (cp == NULL)
      return NULL;

    tmp = strchr (cp, '#');
    if (tmp)
      *tmp = '\0';

    while (isspace (*cp))
      cp++;
  }
  while (*cp == '\0');

  tmp = cp;

  cp = strchr (cp, ':');
  if (!cp)
    return NULL;

  *cp++ = '\0';
  nswb->name = strdup (tmp);

  while (isspace (*cp))
    cp++;

  count = 3;
  nswb->orders = malloc ((count + 1) * sizeof (char *));
  for (nswb->orderc = 0; *cp; nswb->orderc++)
    {
      tmp = cp;

      while (!isspace (*cp) && *cp != '\0')
	++cp;

      if (*cp)
        *cp++ = '\0';

      if (nswb->orderc >= count)
        {
          count += 3;
          nswb->orders = realloc (nswb->orders, (count + 1) * sizeof (char *));
        }

      nswb->orders[nswb->orderc] = strdup (tmp);

      while (isspace (*cp))
        cp++;
    }

  nswb->orders[nswb->orderc] = NULL;

  return nswb;
}

void
nsw_free (struct nsw *ptr)
{
  int i;

  free (ptr->name);
  for (i = 0; i < ptr->orderc; ++i)
    free (ptr->orders[i]);

  if (ptr->orders)
    free (ptr->orders);
  free (ptr);

  return;
}

/* If we don't have a nsswitch.conf file, return
   dummy entry "service: files".  */
static struct nsw *
create_dummy_files (const char *name)
{
  struct nsw *nswp = calloc (1, sizeof (struct nsw));
  if (nswp == NULL)
    return NULL;

  nswp->name = strdup (name);
  nswp->orderc = 1;
  nswp->orders = calloc (2, sizeof (char *));
  nswp->orders[0] = strdup ("files");
  nswp->orders[1] = NULL;

  return nswp;
}


struct nsw *
_getnswbyname (const char *name)
{
  struct nsw *result;

  if (setnswent () != 0)
    return create_dummy_files (name);

  while ((result = getnswent ()) != NULL)
    {
      if (strcmp (name, result->name) == 0)
	{
	  endnswent ();
	  return result;
	}
      else
	nsw_free (result);
    }

  endnswent ();

  return NULL;
}
