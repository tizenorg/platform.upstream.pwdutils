/* Copyright (C) 2004, 2011 Thorsten Kukuk
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

#include <grp.h>
#include <shadow.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>

#include "read-files.h"

#define ISCOLON(c) ((c) == ':')

#define STRING_FIELD(variable, terminator_p, swallow)                        \
  {                                                                           \
    variable = line;                                                          \
    while (*line != '\0' && !terminator_p (*line))                            \
      ++line;                                                                 \
    if (*line != '\0')                                                        \
      {                                                                       \
        *line = '\0';                                                         \
        do                                                                    \
          ++line;                                                             \
        while (swallow && terminator_p (*line));                              \
      }                                                                       \
    else if (strict)                                                          \
      return 0;                                                               \
  }

#define INT_FIELD(variable, terminator_p, swallow, base, convert)            \
  {                                                                           \
    char *endp;                                                               \
    variable = convert (strtoul (line, &endp, base));                         \
    if (endp == line)                                                         \
      return 0;                                                               \
    else if (terminator_p (*endp))                                            \
      do                                                                      \
        ++endp;                                                               \
      while (swallow && terminator_p (*endp));                                \
    else if (*endp != '\0')                                                   \
      return 0;                                                               \
    line = endp;                                                              \
  }

#define INT_FIELD_MAYBE_NULL(variable, terminator_p, swallow, base, convert, default)        \
  {                                                                           \
    char *endp;                                                               \
    if (*line == '\0')                                                        \
      /* We expect some more input, so don't allow the string to end here. */ \
      return 0;                                                               \
    variable = convert (strtoul (line, &endp, base));                         \
    if (endp == line)                                                         \
      variable = default;                                                     \
    if (terminator_p (*endp))                                                 \
      do                                                                      \
        ++endp;                                                               \
      while (swallow && terminator_p (*endp));                                \
    else if (*endp != '\0')                                                   \
      return 0;                                                               \
    line = endp;                                                              \
  }

static char **
parse_list (char *line, char *data, size_t datalen, int *errnop)
{
  void *eol;
  char **list, **p;

  if (line >= data && line < data + datalen)
    /* Find the end of the line buffer, we will use the space in DATA after
       it for storing the vector of pointers.  */
    eol = strchr (line, '\0') + 1;
  else
    /* LINE does not point within DATA->linebuffer, so that space is
       not being used for scratch space right now.  We can use all of
       it for the pointer vector storage.  */
    eol = data;
  /* Adjust the pointer so it is aligned for storing pointers.  */
  eol = (char *) eol + __alignof__ (char *) - 1;
  eol = (char *) eol - ((char *) eol - (char *) 0) % __alignof__ (char *);
  /* We will start the storage here for the vector of pointers.  */
  list = (char **) eol;

  p = list;
  while (1)
    {
      char *elt;

      if ((size_t) ((char *) &p[1] - (char *) data) > datalen)
        {
          /* We cannot fit another pointer in the buffer.  */
          *errnop = ERANGE;
          return NULL;
        }
      if (*line == '\0')
        break;

      /* Skip leading white space.  This might not be portable but useful.  */
      while (isspace (*line))
        ++line;

      elt = line;
      while (1)
        {
          if (*line == '\0' || *line == ',')
            {
              /* End of the next entry.  */
              if (line > elt)
                /* We really found some data.  */
                *p++ = elt;

              /* Terminate string if necessary.  */
              if (*line != '\0')
                *line++ = '\0';
              break;
            }
          ++line;
        }
    }
  *p = NULL;

  return list;
}


int
parse_grent (char *line, struct group *result,
             char *buffer, size_t buflen, int *errnop, int strict)
{
  size_t linelen;
  char *p = strpbrk (line, "\n");
  if (p != NULL)
    *p = '\0';
  linelen = strlen (line);
  if (linelen >= buflen)
    {
      *errnop = ERANGE;
      return -1;
    }
  strcpy (buffer, line);
  line = buffer;
  STRING_FIELD (result->gr_name, ISCOLON, 0);
  if (line[0] == '\0' && !strict
      && (result->gr_name[0] == '+' || result->gr_name[0] == '-'))
    {
      result->gr_passwd = NULL;
      result->gr_gid = 0;
    }
  else
    {
      STRING_FIELD (result->gr_passwd, ISCOLON, 0);
      if (result->gr_name[0] == '+' || result->gr_name[0] == '-')
        INT_FIELD_MAYBE_NULL (result->gr_gid, ISCOLON, 0, 10, , 0)
      else
        INT_FIELD (result->gr_gid, ISCOLON, 0, 10,)
    }
  {
    char **list = parse_list (line, buffer + (linelen + 1),
			      buflen - (linelen + 1), errnop);
    if (list)
      result->gr_mem = list;
    else
      return -1;          /* -1 indicates we ran out of space.  */
  }

  return 1;
}
