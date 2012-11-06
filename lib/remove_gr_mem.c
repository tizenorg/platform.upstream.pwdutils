/* Copyright (C) 2004 Thorsten Kukuk
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

#include <string.h>
#include <unistd.h>
#include "public.h"

char **
remove_gr_mem (const char *name, char **gr_mem)
{
  char **groups;
  unsigned int i, j;

  for (i = 0; gr_mem[i]; i++) ;
  ++i;                          /* for trailing NULL pointer */

  groups = malloc (i * sizeof (char *));
  for (i = 0, j = 0; gr_mem[i]; i++)
    {
      if (strcmp (name, gr_mem[i]) != 0)
        {
          groups[j] = strdup (gr_mem[i]);
          ++j;
        }
    }

  groups[j] = NULL;

  return groups;
}

