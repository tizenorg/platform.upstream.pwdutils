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

#include <pwd.h>
#include <shadow.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

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

int
parse_pwent (char *line, struct passwd *result, int strict)
{
  char *p = strpbrk (line, "\n");
  if (p != NULL)
    *p = '\0';
  STRING_FIELD (result->pw_name, ISCOLON, 0);
  if (line[0] == '\0' && !strict
      && (result->pw_name[0] == '+' || result->pw_name[0] == '-'))
    {
      /* This a special case.  We allow lines containing only a `+' sign
        since this is used for nss_compat.  All other services will
        reject this entry later.  Initialize all other fields now.  */
     result->pw_passwd = NULL;
     result->pw_uid = 0;
     result->pw_gid = 0;
     result->pw_gecos = NULL;
     result->pw_dir = NULL;
     result->pw_shell = NULL;
   }
 else
   {
     STRING_FIELD (result->pw_passwd, ISCOLON, 0);
     if (result->pw_name[0] == '+' || result->pw_name[0] == '-')
       {
         INT_FIELD_MAYBE_NULL (result->pw_uid, ISCOLON, 0, 10, , 0)
         INT_FIELD_MAYBE_NULL (result->pw_gid, ISCOLON, 0, 10, , 0)
       }
     else
       {
         INT_FIELD (result->pw_uid, ISCOLON, 0, 10,)
         INT_FIELD (result->pw_gid, ISCOLON, 0, 10,)
       }
     STRING_FIELD (result->pw_gecos, ISCOLON, 0);
     STRING_FIELD (result->pw_dir, ISCOLON, 0);
     result->pw_shell = line;
   }
  return 1;
}


/* Predicate which always returns false, needed below.  */
#undef FALSE
#define FALSE(arg) 0

int
parse_spent (char *line, struct spwd *result, int strict)
{
  char *p = strpbrk (line, "\n");
  if (p != NULL)
    *p = '\0';

 result->sp_namp = line;
 while (*line != '\0' && !ISCOLON (*line))
   ++line;
 if (*line != '\0')
   {
     *line = '\0';
     ++line;
   }

 if (line[0] == '\0'
     && (result->sp_namp[0] == '+' || result->sp_namp[0] == '-'))
   {
     result->sp_pwdp = NULL;
     result->sp_lstchg = 0;
     result->sp_min = 0;
     result->sp_max = 0;
     result->sp_warn = -1l;
     result->sp_inact = -1l;
     result->sp_expire = -1l;
     result->sp_flag = ~0ul;
   }
 else
   {
     result->sp_pwdp = line;
     while (*line != '\0' && !ISCOLON (*line))
       ++line;
     if (*line != '\0')
       {
	 *line = '\0';
	 ++line;
       }
     else if (strict)
       return 0;
     INT_FIELD_MAYBE_NULL (result->sp_lstchg, ISCOLON, 0, 10, (long int),
                           (long int) -1);
     INT_FIELD_MAYBE_NULL (result->sp_min, ISCOLON, 0, 10, (long int),
                           (long int) -1);
     INT_FIELD_MAYBE_NULL (result->sp_max, ISCOLON, 0, 10, (long int),
                           (long int) -1);
     while (isspace (*line))
       ++line;
     if (*line == '\0')
       {
         /* The old form.  */
         result->sp_warn = -1l;
         result->sp_inact = -1l;
         result->sp_expire = -1l;
         result->sp_flag = ~0ul;
	 if (strict)
	   return 0;
       }
     else
       {
         INT_FIELD_MAYBE_NULL (result->sp_warn, ISCOLON, 0, 10, (long int),
                               (long int) -1);
         INT_FIELD_MAYBE_NULL (result->sp_inact, ISCOLON, 0, 10, (long int),
                               (long int) -1);
         INT_FIELD_MAYBE_NULL (result->sp_expire, ISCOLON, 0, 10, (long int),
                               (long int) -1);
         if (*line != '\0')
           INT_FIELD_MAYBE_NULL (result->sp_flag, FALSE, 0, 10,
                                 (unsigned long int), ~0ul)
         else
           result->sp_flag = ~0ul;
       }
   }
  return 1;
}
