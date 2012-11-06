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

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <iconv.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <langinfo.h>

#include "utf8conv.h"

static char *
call_iconv (const char *from, const char *to, const char *str)
{
  size_t nconv, srclen, dstlen;
  iconv_t ih = iconv_open (to, from);
  char *srcstr, *dststr, *resstr;

  if (ih == (iconv_t) -1)
    {
      /* Something went wrong.  */
      if (errno == EINVAL)
	fprintf (stderr, "conversion from `%s' to `%s' not available.\n",
		 from, to);
      else
	perror ("iconv_open");

      return NULL;
    }

  srcstr = strdupa (str);
  srclen = strlen (srcstr);
  dstlen = srclen * 4;
  dststr = malloc (dstlen);
  if (dststr == NULL)
    return NULL;
  resstr = dststr;

  nconv = iconv (ih, &srcstr, &srclen, &dststr, &dstlen);
  if (nconv == (size_t) -1)
    {
      if (errno != EILSEQ)
	perror ("iconv");
      free (resstr);
      return strdup (str);
    }
  *dststr = '\0';

  if (iconv_close (ih) != 0)
    perror ("iconv_close");

  return resstr;
}

char *
utf8_to_locale (const char *str)
{
  char *to = nl_langinfo (CODESET);
  char *res;

  if (to == NULL ||
      strcmp (to, "C") == 0 ||
      strcmp (to, "UTF-8") == 0)
    return strdup (str);

  res = call_iconv ("UTF-8", to, str);

  if (res == NULL)
    return strdup (str);

  return res;
}

char *
locale_to_utf8 (const char *str)
{
  char *from = nl_langinfo (CODESET);
  char *res;

  if (from == NULL ||
      strcmp (from, "C") == 0 ||
      strcmp (from, "UTF-8") == 0)
    return strdup (str);

  res = call_iconv (from, "UTF-8", str);

  if (res == NULL)
    return strdup (str);

  return res;
}
