/* Copyright (C) 2002, 2003, 2004, 2005 Thorsten Kukuk
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
#include <wchar.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <wctype.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <shadow.h>
#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#include <selinux/av_permissions.h>
#endif
#ifdef HAVE_LIBNSCD_H
#include <libnscd.h>
#endif

#include "i18n.h"
#include "public.h"
#include "utf8conv.h"
#include "logindefs.h"
#include "error_codes.h"
#include "read-files.h"

#ifdef USE_LDAP
#include "libldap.h"
#endif

#ifndef _
#define _(String) gettext (String)
#endif

static int shadow_chfn = 0;

struct fn_info {
  char *fullname;
  char *roomno;
  char *work_phone;
  char *home_phone;
  char *other;
};
typedef struct fn_info fn_info;

static void
print_usage_shadow (FILE *stream, const char *program)
{
  fprintf (stream, _("Usage: %s [-f name] [-r room] [-w work_phone]\n       [-h home_phone] [-o other] [-q] [-u] [-v] [user]\n"),
	   program);
}

static void
print_help_shadow (const char *program)
{
  print_usage_shadow (stdout, program);
  fprintf (stdout, _("%s - change user name and information\n\n"),
	   program);
  fputs (_("  -f full-name   Change your real name\n"), stdout);
  fputs (_("  -r room        Change your office room number\n"), stdout);
  fputs (_("  -w work_phone  Change your office phone number\n"), stdout);
  fputs (_("  -h home_phone  Change your home phone number\n"), stdout);
  fputs (_("  -o other       Change the undefined portions of the GECOS field\n"), stdout);
  fputs (_("  -q, --quiet    Don't be verbose\n"), stdout);
  if (strcmp(program, "chfn") == 0)
    fputs (_("  --service srv  Use nameservice 'srv'\n"), stdout);
  fputs (_("      --help     Give this help list\n"), stdout);
  fputs (_("  -u, --usage    Give a short usage message\n"), stdout);
  fputs (_("  -v, --version  Print program version\n"), stdout);

  if (strcmp(program, "chfn") == 0)
    fputs (_("Valid services are: files, nis, nisplus, ldap\n"),
	   stdout);
}

static void
print_usage_util (FILE *stream, const char *program)
{
  fprintf (stream, _("Usage: %s [-D binddn] [-P path] [-f name] [-o office] [-p office-phone]\n       [-h home-phone][-m other] [-q] [-u] [-v] [user]\n"),
	   program);
}

static void
print_help_util (const char *program)
{
  print_usage_util (stdout, program);
  fprintf (stdout, _("%s - change user name and information\n\n"),
	   program);
#ifdef USE_LDAP
  fputs (_("  -D binddn      Use dn \"binddn\" to bind to the LDAP directory\n"),
         stdout);
#endif
  fputs (_("  -P path        Search passwd and shadow file in \"path\"\n"),
         stdout);
  fputs (_("  -f full-name   Change your real name\n"), stdout);
  fputs (_("  -o office      Change your office room number\n"), stdout);
  fputs (_("  -p phone       Change your office phone number\n"), stdout);
  fputs (_("  -h home-phone  Change your home phone number\n"), stdout);
  fputs (_("  -m other       Change the undefined portions of the GECOS field\n"), stdout);
  if (strcmp(program, "chfn") == 0)
    fputs (_("  --service srv  Use nameservice 'srv'\n"), stdout);
  fputs (_("  -q, --quiet    Don't be verbose\n"), stdout);
  fputs (_("      --help     Give this help list\n"), stdout);
  fputs (_("  -u, --usage    Give a short usage message\n"), stdout);
  fputs (_("  -v, --version  Print program version\n"), stdout);

  if (strcmp(program, "chfn") == 0)
    fputs (_("Valid services are: files, nis, nisplus, ldap\n"),
	   stdout);
}

static int
may_change_field (int field)
{
  const char *cp;

  /* root is always allowed to change everything.  */
  if (getuid () == 0)
    return 1;

  cp = getlogindefs_str ("CHFN_RESTRICT", "");
  /* CHFN_RESTRICT specifies exactly which fields may be changed
     by regular users.  */
  if (!cp)
    cp = "";
  /*  For backward compatibility, "yes" is equivalent to "rwh",
      "no" is equivalent to "frwh".  */
  else if (strcmp (cp, "yes") == 0)
    cp = "rwh";
  else if (strcmp (cp, "no") == 0)
    cp = "frwh";
  if (strchr (cp, field))
    return 1;
  return 0;
}

/* get_fields - change the user's GECOS information interactively
   prompt the user for each of the four fields and fill in the fields from
   the user's response, or leave alone if nothing was entered.  */
static void
get_fields (fn_info *old, fn_info *new)
{
  printf (_("Enter the new value, or press ENTER for the default\n"));

  /* Allow the user to abort with Ctrl-C.  */
  signal (SIGINT, SIG_DFL);

  if (may_change_field ('f'))
    new->fullname = get_value (old->fullname, _("Full Name"));
  else
    printf (_("\tFull Name: %s\n"), old->fullname ?:"");

  if (may_change_field ('r'))
    new->roomno = get_value (old->roomno, _("Room Number"));
  else
    printf (_("\tRoom Number: %s\n"), old->roomno ?:"");

  if (may_change_field ('w'))
    new->work_phone = get_value (old->work_phone, _("Work Phone"));
  else
    printf (_("\tWork Phone: %s\n"), old->work_phone ?:"");

  if (may_change_field ('h'))
    new->home_phone = get_value (old->home_phone, _("Home Phone"));
  else
    printf (_("\tHome Phone: %s\n"), old->home_phone ?:"");

  if (getuid() == 0)
    new->other = get_value (old->other, _("Other"));
  else
    printf (_("\tOther: %s\n"), old->other ?:"");

  signal (SIGINT, SIG_IGN);
}

/* parse_passwd () -- take a struct password and fill in the
   fields of the struct fn_info.  */
static void
parse_passwd (const char *gecos, struct fn_info *info)
{
  if (gecos)
    {
      char *cp = strdup (gecos);
      info->fullname = cp;
      cp = strchr (cp, ',');
      if (cp) { *cp = 0, cp++; } else return;
      info->roomno = cp;
      cp = strchr (cp, ',');
      if (cp) { *cp = 0, cp++; } else return;
      info->work_phone = cp;
      cp = strchr (cp, ',');
      if (cp) { *cp = 0, cp++; } else return;
      info->home_phone = cp;
      /*  extra fields contain site-specific information, and
       *  can not be changed by this version of chfn.  */
      cp = strchr (cp, ',');
      if (cp) { *cp = 0, cp++; } else return;
      info->other = cp;
    }
}

/* convert a multibye string to a wide character string, so
   that we can use iswprint.  */
static wchar_t *
mbstowcs_alloc (const char *string)
{
  size_t size = strlen (string) + 1;
  wchar_t *buf = malloc (size * sizeof (wchar_t));

  if (buf == NULL)
    return NULL;

  size = mbstowcs (buf, string, size);
  if (size == (size_t) -1)
    return NULL;
  buf = realloc (buf, (size + 1) * sizeof (wchar_t));
  return buf;
}

static int
check_field (const char *program, const char *field, const char *illegal)
{
  wchar_t *wstr = mbstowcs_alloc (field);
  wchar_t *willegal = mbstowcs_alloc (illegal);
  size_t i;

  /* keep /etc/passwd clean. */
  for (i = 0; i < wcslen (wstr); i++)
    {
      wchar_t c = wstr[i];
      if (wcschr (willegal, c) != NULL || c == '"' || c == '\n')
	{
	  printf (_("%s: The characters '%s\"' are not allowed.\n"),
		  program, illegal);
	  return 1;
        }
      if (iswcntrl (c))
	{
	  printf (_("%s: Control characters are not allowed.\n"), program);
	  return 1;
        }
    }

  return 0;
}

int
main (int argc, char *argv[])
{
  uid_t uid = getuid ();
  user_t *pw_data = NULL;
  char *use_service = NULL;
  char *caller_name = NULL;
  char *new_gecos = NULL;
  char *locale_name;
  int interactive = 1;
  fn_info new;
  int silent = 0;
#ifdef USE_LDAP
  char *binddn = NULL;
#endif
  static struct option long_options_shadow[] = {
    {"full-name",   required_argument, NULL, 'f' },
    {"room",        required_argument, NULL, 'r' },
    {"work-phone",  required_argument, NULL, 'w' },
    {"home-phone",  required_argument, NULL, 'h' },
    {"other",       required_argument, NULL, 'o' },
    {"service",     required_argument, NULL, '\254' },
    {"quiet",       no_argument,       NULL, 'q' },
    {"version",     no_argument,       NULL, 'v' },
    {"usage",       no_argument,       NULL, 'u' },
    {"help",        no_argument,       NULL, '\255' },
    {NULL,          0,                 NULL, '\0'}
  };
  static char *optstring_shadow = "f:r:w:h:o:qvu";
  static struct option long_options_util[] = {
#ifdef USE_LDAP
    {"binddn",      required_argument, NULL, 'D' },
#endif
    {"path",        required_argument, NULL, 'P' },
    {"full-name",   required_argument, NULL, 'f' },
    {"office",      required_argument, NULL, 'o' },
    {"phone",       required_argument, NULL, 'p' },
    {"home-phone",  required_argument, NULL, 'h' },
    {"other",       required_argument, NULL, 'm' },
    {"quiet",       no_argument,       NULL, 'q' },
    {"version",     no_argument,       NULL, 'v' },
    {"usage",       no_argument,       NULL, 'u' },
    {"service",     required_argument, NULL, '\254' },
    {"help",        no_argument,       NULL, '\255' },
    {NULL,          0,                 NULL, '\0'}
  };
  static char *optstring_util = "D:P:f:o:p:h:m:qvu";
  struct option *long_options;
  char *optstring;
  char *envstr;
  const char *program = basename (argv[0]);

#ifdef ENABLE_NLS
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  if (strcasecmp (program, "ypchfn") == 0)
    use_service = "nis";
  else if (strcasecmp (program, "chfn") != 0)
    {
      fprintf (stderr, _("%s: Don't know what I should do.\n"), program);
      return 1;
    }

  openlog (program, LOG_PID, LOG_AUTHPRIV);

  /* Before going any further, raise the ulimit and ignore
     signals.  */
  init_environment ();

  envstr = getenv ("SHADOW_CHFN");
  if (envstr)
    {
      if (strcmp (envstr, "0") == 0)
	shadow_chfn = 0;
      else if (strcmp (envstr, "1") == 0)
	shadow_chfn = 1;
    }

  memset (&new, 0, sizeof (new));

  if (shadow_chfn)
    {
      long_options = long_options_shadow;
      optstring = optstring_shadow;
    }
  else
    {
      long_options = long_options_util;
      optstring = optstring_util;
    }

  while (1)
    {
      int c;
      int option_index = 0;

      c = getopt_long (argc, argv, optstring,
		       long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
        {
	case 'f':
	  if (!may_change_field ('f'))
	    {
	      fprintf (stderr, _("%s: Permission denied.\n"), program);
	      return 1;
	    }
	  new.fullname = locale_to_utf8 (optarg);
	  interactive = 0;
	  break;
	case 'r':
	case 'o':
	case 'm':
	  /* This four have all a different meaning, depending on
	     SHADOW_CHFN. In result we check for office/room, misc
	  field and service switch.  */
	  if ((shadow_chfn && c == 'o') ||
	      (!shadow_chfn && c == 'm'))
	    {
	      /* -o other or -m other  */
	      if (getuid() != 0)
		{
		  fprintf (stderr, _("%s: Permission denied.\n"), program);
		  return 1;
		}
	      new.other = locale_to_utf8 (optarg);
	      interactive = 0;
	    }
	  else if ((shadow_chfn && c == 'r') ||
		   (!shadow_chfn && c == 'o'))
	    {
	      /* shadow chfn has "-r room" else "-o office"  */
	      if (!may_change_field ('r'))
		{
		  fprintf (stderr, _("%s: Permission denied.\n"), program);
		  return 1;
		}
	      new.roomno = locale_to_utf8 (optarg);
	      interactive = 0;
	    }
	  break;
	case '\254':
	  if (use_service != NULL)
	    {
	      if (shadow_chfn)
		print_usage_shadow (stderr, program);
	      else
		print_usage_util (stderr, program);
	      return 1;
	    }

	  if (strcasecmp (optarg, "yp") == 0 ||
	      strcasecmp (optarg, "nis") == 0)
	    use_service = "nis";
	  else if (strcasecmp (optarg, "nis+") == 0 ||
		   strcasecmp (optarg, "nisplus") == 0)
	    use_service = "nisplus";
	  else if (strcasecmp (optarg, "files") == 0)
	    use_service = "files";
#ifdef USE_LDAP
	  else if (strcasecmp (optarg, "ldap") == 0)
	    use_service = "ldap";
#endif
	  else
	    {
	      fprintf (stderr,
		       _("Service `%s' not supported.\n"), optarg);
	      if (shadow_chfn)
		print_usage_shadow (stderr, program);
	      else
		print_usage_util (stderr, program);
	      return 1;
	    }
	  break;
	case 'w':
	case 'p':
	  if (!may_change_field ('w'))
	    {
	      fprintf (stderr, _("%s: Permission denied.\n"), program);
	      return 1;
	    }
	  new.work_phone = locale_to_utf8 (optarg);
	  interactive = 0;
	  break;
	case 'h':
	  if (!may_change_field ('h'))
	    {
	      fprintf (stderr, _("%s: Permission denied.\n"), program);
	      return 1;
	    }
	  new.home_phone = locale_to_utf8 (optarg);
	  interactive = 0;
	  break;
	case 'q':
	  silent = 1;
	  break;
#ifdef USE_LDAP
        case 'D':
          binddn = optarg;
          break;
#endif
        case 'P':
          if (uid != 0)
            {
              fprintf (stderr,
                       _("Only root is allowed to specify another path\n"));
              return E_NOPERM;
            }
          else
            files_etc_dir = strdup (optarg);
          break;
        case '\255':
	  if (shadow_chfn)
	    print_help_shadow (program);
	  else
	    print_help_util (program);
          return 0;
        case 'v':
          print_version (program, "2005");
          return 0;
        case 'u':
	  if (shadow_chfn)
	    print_usage_shadow (stdout, program);
	  else
	    print_usage_util (stdout, program);
          return 0;
        default:
          print_error (program);
          return 1;
        }
    }

  argc -= optind;
  argv += optind;

  if (argc > 1)
    {
      fprintf (stderr, _("%s: Too many arguments.\n"), program);
      print_error (program);
      return 1;
    }

  {
    int buflen = 256;
    char *buffer = alloca (buflen);
    struct passwd resultbuf;
    struct passwd *pw;

    /* Determine our own user name for authentication.  */
    while (getpwuid_r (uid, &resultbuf, buffer, buflen, &pw) != 0
	   && errno == ERANGE)
      {
	errno = 0;
	buflen += 256;
	buffer = alloca (buflen);
      }
      if (!pw)
	{
	  fprintf (stderr, _("%s: Cannot determine your user name.\n"),
		   program);
	  return 1;
	}

      caller_name = strdupa (pw->pw_name);

      /* We change the passwd information for another user, get that
	 data, too.  */
      if (argc == 1)
	{
	  char *user = locale_to_utf8 (argv[0]);

	  while (getpwnam_r (user, &resultbuf, buffer, buflen, &pw) != 0
		 && errno == ERANGE)
	    {
	      errno = 0;
	      buflen += 256;
	      buffer = alloca (buflen);
	    }
	  free (user);

	  if (!pw)
	    {
	      fprintf (stderr, _("%s: Unknown user `%s'.\n"),
		       program, argv[0]);
	      return 1;
	    }
	}

      pw_data = do_getpwnam (pw->pw_name, use_service);
      if (pw_data == NULL || pw_data->service == S_NONE)
	{
	  if (use_service)
	    fprintf (stderr,
		     _("%s: User `%s' is not known to service `%s'.\n"),
		     program, utf8_to_locale (pw->pw_name), use_service);
	  else
	    fprintf (stderr, _("%s: Unknown user `%s'.\n"), program,
		     utf8_to_locale (pw->pw_name));
	  return 1;
	}

      locale_name = utf8_to_locale (pw_data->pw.pw_name);
  }

#ifdef WITH_SELINUX
  if (is_selinux_enabled () > 0)
    {
      if ((uid == 0) &&
          (selinux_check_access (pw_data->pw.pw_name, PASSWD__CHFN) != 0))
        {
          security_context_t user_context;
          if (getprevcon (&user_context) < 0)
            user_context =
              (security_context_t) strdup (_("Unknown user context"));
	  fprintf (stderr,
		   _("%s: %s is not authorized to change the finger information for %s.\n"),
		   program, user_context, locale_name);
	  if (security_getenforce() > 0)
	    {
	      syslog (LOG_ALERT,
		      "%s is not authorized to change the finger information for %s",
		      user_context, pw_data->pw.pw_name);
	      freecon (user_context);
	      return E_NOPERM;
	    }
	  else
	    {
	      fprintf (stderr,
		       _("SELinux is in permissive mode, continuing.\n"));
	      freecon (user_context);
	    }
	}
    }
#endif

  /* Only root is allowed to change the gecos field for local users. */
  if (uid && uid != pw_data->pw.pw_uid &&
      (pw_data->service == S_LOCAL
#ifdef USE_LDAP
       || (pw_data->service == S_LDAP && binddn == NULL)
#endif
       ))
    {
      syslog (LOG_ERR, "%u cannot change finger information for `%s'",
	      uid, pw_data->pw.pw_name);
      fprintf (stderr,
	       _("You cannot change the finger information for `%s'.\n"),
	       locale_name);
      free_user_t (pw_data);
      return 1;
    }

  if (!silent)
    printf (_("Changing finger information for %s.\n"), locale_name);

  if (getlogindefs_bool ("CHFN_AUTH", 1) || pw_data->service != S_LOCAL)
    {
#ifdef USE_LDAP
      if (binddn && pw_data->service == S_LDAP)
	pw_data->oldclearpwd = strdup (get_ldap_password (binddn));
      else
#endif /* USE_LDAP */
	if (do_authentication (program, caller_name, pw_data) != 0)
	  {
	    free_user_t (pw_data);
	    return 1;
	  }
      if (pw_data->service != S_LOCAL && get_old_clear_password (pw_data) != 0)
	return 1;
    }

  {
    fn_info old;
    int len;

    memset (&old, 0, sizeof (old));

    parse_passwd (pw_data->pw.pw_gecos, &old);
    if (interactive)
      get_fields (&old, &new);

    if (!new.fullname)
      new.fullname = strdup (old.fullname ?:"");
    if (check_field (program, new.fullname, ":,=") != 0)
      {
	fprintf (stderr, _("%s: Invalid name: `%s'\n"), program,
		 utf8_to_locale (new.fullname));
	return 1;
      }
    if (!new.roomno)
      new.roomno = strdup (old.roomno ?:"");
    if (check_field (program, new.roomno, ":,=") != 0)
      {
	fprintf (stderr, _("%s: Invalid room number: `%s'\n"), program,
		 utf8_to_locale (new.roomno));
	return 1;
      }
    if (!new.work_phone)
      new.work_phone = strdup (old.work_phone ?:"");
    if (check_field (program, new.work_phone, ":,=") != 0)
      {
	fprintf (stderr, _("%s: Invalid work phone: `%s'\n"), program,
		 utf8_to_locale (new.work_phone));
	return 1;
      }
    if (!new.home_phone)
      new.home_phone = strdup (old.home_phone ?:"");
    if (check_field (program, new.home_phone, ":,=") != 0)
      {
	fprintf (stderr, _("%s: Invalid home phone: `%s'\n"), program,
		 utf8_to_locale (new.home_phone));
	return 1;
      }
    if (!new.other)
      new.other = strdup (old.other ?:"");
    if (check_field (program, new.other, ":") != 0)
      {
	fprintf (stderr, _("%s: `%s' contains illegal characters.\n"),
		 program, utf8_to_locale (new.other));
	return 1;
      }

    /* create the new gecos string */
    len = (strlen (new.fullname) + strlen (new.roomno) +
           strlen (new.work_phone) + strlen (new.home_phone) +
           strlen (new.other) + 4);
    new_gecos = (char *)malloc (len + 1);
    sprintf (new_gecos, "%s,%s,%s,%s,%s", new.fullname, new.roomno,
             new.work_phone, new.home_phone, new.other);

    /* remove trailing empty fields (but not subfields of new.other) */
    if (new.other[0] == '\0')
      {
	while (len > 0 && new_gecos[len-1] == ',')
	  len--;
	new_gecos[len] = 0;
      }
  }

  /* we don't need to change the gecos field if here is no change */
  if (strcmp (pw_data->pw.pw_gecos, new_gecos) == 0)
    {
      if (!silent)
	printf (_("Finger information not changed.\n"));
      return 0;
    }

  pw_data->new_gecos = new_gecos;

  if (write_user_data (pw_data, 0) != 0)
    {
      fprintf (stderr, _("Error while changing finger information.\n"));
      free_user_t (pw_data);
      return 1;
    }
  else
    {
#ifdef HAVE_NSCD_FLUSH_CACHE
      nscd_flush_cache ("passwd");
#endif
      if (!silent)
	printf (_("Finger information changed.\n"));
    }

  free_user_t (pw_data);

  return 0;
}
