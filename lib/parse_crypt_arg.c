/* Copyright (C) 2004, 2005 Thorsten Kukuk
   Author: Thorsten Kukuk <kukuk@thkukuk.de>

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


#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#if defined(HAVE_XCRYPT_H)
#include <xcrypt.h>
#elif defined(HAVE_CRYPT_H)
#include <crypt.h>
#endif

#include "i18n.h"
#include "parse_crypt_arg.h"

#ifndef RANDOM_DEVICE
#define RANDOM_DEVICE "/dev/urandom"
#endif

#if defined(HAVE_XCRYPT_GENSALT_R)
static int
read_loop (int fd, char *buffer, int count)
{
  int offset, block;

  offset = 0;
  while (count > 0)
    {
      block = read(fd, &buffer[offset], count);

      if (block < 0)
        {
          if (errno == EINTR)
            continue;
          return block;
        }
      if (!block)
        return offset;

      offset += block;
      count -= block;
    }

  return offset;
}
#endif

char *
#if defined(HAVE_XCRYPT_GENSALT_R)
make_crypt_salt (const char *crypt_prefix, int crypt_rounds)
#else
make_crypt_salt (const char *crypt_prefix __attribute__ ((unused)),
                 int crypt_rounds __attribute__ ((unused)))
#endif
{
#if defined(HAVE_XCRYPT_GENSALT_R)
#define CRYPT_GENSALT_OUTPUT_SIZE (7 + 22 + 1)
  int fd;
  char entropy[16];
  char *retval;
  char output[CRYPT_GENSALT_OUTPUT_SIZE];

  fd = open (RANDOM_DEVICE, O_RDONLY);
  if (fd < 0)
    {
      fprintf (stderr, _("Can't open %s for reading: %s\n"),
               RANDOM_DEVICE, strerror (errno));
      return NULL;
    }

  if (read_loop (fd, entropy, sizeof(entropy)) != sizeof(entropy))
    {
      close (fd);
      fprintf (stderr, _("Unable to obtain entropy from %s\n"),
               RANDOM_DEVICE);
      return NULL;
    }

  close (fd);

  retval = xcrypt_gensalt_r (crypt_prefix, crypt_rounds, entropy,
                             sizeof (entropy), output, sizeof(output));

  memset (entropy, 0, sizeof (entropy));

  if (!retval)
    {
      fprintf (stderr,
               _("Unable to generate a salt, check your crypt settings.\n"));
      return NULL;
    }

  return strdup (retval);
#else
#define ascii_to_bin(c) ((c)>='a'?(c-59):(c)>='A'?((c)-53):(c)-'.')
#define bin_to_ascii(c) ((c)>=38?((c)-38+'a'):(c)>=12?((c)-12+'A'):(c)+'.')

  time_t tm;
  char salt[3];

  time (&tm);
  salt[0] = bin_to_ascii(tm & 0x3f);
  salt[1] = bin_to_ascii((tm >> 6) & 0x3f);
  salt[2] = '\0';

  return strdup (salt);
#endif
}

crypt_t
parse_crypt_arg (const char *arg)
{
  if (strcasecmp (arg, "des") == 0)
    return DES;
  else if (strcasecmp (arg, "md5") == 0)
    return MD5;
  else if (strcasecmp (arg, "blowfish") == 0 ||
           strcasecmp (arg, "bf") == 0)
    {
#if defined(HAVE_XCRYPT_GENSALT_R)
      return BLOWFISH;
#else
      fprintf (stderr, _("No support for blowfish compiled in, using MD5.\n"));
      return MD5;
#endif
    }

  fprintf (stderr, _("No support for %s available, using DES.\n"), optarg);
  return DES;
}
