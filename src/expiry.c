/* Copyright (C) 2003, 2004, 2005 Thorsten Kukuk
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

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "i18n.h"
#include "public.h"
#include "utf8conv.h"
#include "logging.h"
#include "error_codes.h"

#define SCALE DAY

static void
print_usage (FILE *stream, const char *program)
{
  fprintf (stream, _("Usage: %s [-f]\n"),
           program);
}

static void
print_help (const char *program)
{
  print_usage (stdout, program);
  fprintf (stdout, _("%s - check password expiration and enforce password change\n\n"), program);

  fputs (_("  -f, --force    The caller is forced to change the password\n"),
	 stdout);
  fputs (_("      --help     Give this help list\n"), stdout);
  fputs (_("  -u, --usage    Give a short usage message\n"), stdout);
  fputs (_("  -v, --version  Print program version\n"), stdout);
}

static int
c2n (char c)
{
  if (c == '.')
    return 0;
  else if (c == '/')
    return 1;
  else if (c >= '0' && c <= '9')
    return 2 + (c - '0');
  else if (c >= 'A' && c <= 'Z')
    return 12 + (c - 'A');
  else if (c >= 'a' && c <= 'z')
    return 38 + (c - 'a');
  else return -1;
}

static long
str2week (char *date)
{
  if (date == NULL || strlen (date) == 0)
    return -1;

  if (strlen (date) == 1)
    return c2n (date[0]);
  else
    return c2n (date[0]) + (c2n (date[1]) * 64);
}

static int
hp_expire (const struct passwd *pw)
{
  long min, max;
  char *age;

  age = strchr (pw->pw_passwd, ',');
  if (age == NULL)
    return 0;
  ++age;

  max = c2n (age[0]);
  if (max < 0)
    {
    error_state:
      fprintf (stderr, _("Age field for %s is wrong"),
	       utf8_to_locale (pw->pw_name));
      return -1;
    }
  ++age;

  if (age == NULL)
    goto error_state;

  min = c2n (age[0]);
  if (min < 0)
    goto error_state;
  ++age;

  if (age == NULL)
    goto error_state;

  if ((max == 0 && min == 0) ||
      ((time(0)/(SCALE*7) > str2week (age) + max) && (max >= min)))
    {
      fprintf (stdout,
	       _("Your password has expired. Choose a new password."));
      return 1;
    }

  return 0;
}

static int
expire (const struct spwd *sp)
{
  /* Print when the user has to change his password the next time ! */
  long now, remain;

  now = time (NULL) / SCALE;

  if (sp->sp_expire > 0 && now >= sp->sp_expire)
    {
      fprintf (stdout,
	       _("Your login has expired. "
		 "Contact the system administrator.\n"));
      return 3;
    }

  if (sp->sp_lstchg == 0)
    {
      fprintf (stdout,
	       _("Password changing requested. Choose a new password.\n"));
      return 1;
    }
  else if (sp->sp_lstchg > 0 && sp->sp_max >= 0 &&
           (now > sp->sp_lstchg + sp->sp_max))
    {
      if ((sp->sp_inact >= 0 &&
	   now >= sp->sp_lstchg + sp->sp_max + sp->sp_inact) ||
	  (sp->sp_max < sp->sp_min))
        {
	  fprintf (stdout, _("Your password is inactive. "
			     "Contact the system administrator.\n"));
          return 2;
        }

      fprintf (stdout, _("Your password has expired. "
			 "Choose a new password.\n"));
      return 1;
    }

  if (sp->sp_lstchg != -1 && sp->sp_max != -1 && sp->sp_warn != -1)
    if ((remain = (sp->sp_lstchg + sp->sp_max) - now) <= sp->sp_warn)
      {
	if (remain > 1)
	  fprintf (stdout, _("Your password will expire in %ld days.\n"),
		   remain);
	else if (remain == 1)
	  fprintf (stdout, _("Your password will expire tomorrow.\n"));
	else if (remain == 0)
	  fprintf (stdout, _("Your password will expire within 24 hours.\n"));
      }

  return 0;
}


int
main (int argc, char *argv[])
{
  const char *program = "expiry";
  struct passwd resultpwbuf;
  struct passwd *pw;
  struct spwd resultspbuf;
  struct spwd *sp;
  uid_t uid = getuid ();
  int force = 0, result = -1;

#ifdef ENABLE_NLS
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  open_sec_log (program);

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] = {
        {"check",   no_argument, NULL, 'c' },
        {"force",   no_argument, NULL, 'f' },
        {"version", no_argument, NULL, 'v' },
        {"usage",   no_argument, NULL, 'u' },
        {"help",    no_argument, NULL, '\255' },
        {NULL,      0,           NULL, '\0'}
      };

      c = getopt_long (argc, argv, "cfvu",
                       long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
	{
	case 'c':
	  /* Dummy for compatibility with expiry from shadow suite.  */
	  break;
	case 'f':
	  ++force;
	  break;
	case '\255':
          print_help (program);
          return 0;
        case 'v':
          print_version (program, "2005");
          return 0;
        case 'u':
          print_usage (stdout, program);
	  return 0;
	default:
	  print_error (program);
	  return E_USAGE;
	}
    }

  argc -= optind;
  argv += optind;

  if (argc > 1)
    {
      fprintf (stderr, _("%s: Too many arguments.\n"), program);
      print_error (program);
      return E_USAGE;
    }
  else
    {
      int buflen = 256;
      char *buffer = malloc (buflen);

      /* Determine our own user name.  */
      while (getpwuid_r (uid, &resultpwbuf, buffer, buflen, &pw) != 0
             && errno == ERANGE)
        {
          errno = 0;
          buflen += 256;
          buffer = realloc (buffer, buflen);
        }

      if (!pw)
        {
          fprintf (stderr, _("%s: Cannot determine your user name.\n"),
                   program);
          return E_UNKNOWN_USER;
        }

      buffer = malloc (buflen);
      /* Determine our own user name.  */
      while (getspnam_r (pw->pw_name, &resultspbuf, buffer, buflen, &sp) != 0
             && errno == ERANGE)
        {
          errno = 0;
          buflen += 256;
          buffer = realloc (buffer, buflen);
        }
    }

  if (strchr (pw->pw_passwd, ',') != NULL)
    result = hp_expire (pw);
  else if (sp != NULL)
    result = expire (sp);

  if (result == -1)
    return E_FAILURE;

  if (force && result == 1)
    {
      int i;

      /* close all filehandles.  */
      for (i = 3; i < getdtablesize(); ++i)
	close (i);

      /* one single newline.  */
      fputs ("\n", stdout);

      /* drop privilegs.  */
      if (setgid (getgid ()) || setuid (uid))
        {
	  sec_log (program, MSG_DROP_PRIVILEGE_FAILED, errno, uid);
          fprintf (stderr, _("%s: Failed to drop privileges: %s\n"),
                   program, strerror (errno));
          return E_FAILURE;
        }

      execl (PASSWD_PROGRAM, PASSWD_PROGRAM, pw->pw_name, (char *)0);
      perror ("Can't execute " PASSWD_PROGRAM);
      return E_FAILURE;
    }

  return 0;
}
