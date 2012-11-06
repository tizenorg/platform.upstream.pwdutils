/* Copyright (C) 2002, 2003, 2005 Thorsten Kukuk
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
#include <unistd.h>

#include "i18n.h"
#include "public.h"


#define MAX_LOCK_RETRIES 3 /* How often should we try to lock password file */

int
lock_database (void)
{
  int retries = 0;

  while (lckpwdf () && retries < MAX_LOCK_RETRIES)
    {
      sleep (1);
      ++retries;
    }

  if (retries == MAX_LOCK_RETRIES)
    return 1;

  return 0;
}
