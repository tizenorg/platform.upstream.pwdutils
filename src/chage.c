/* Copyright (C) 2002-2006, 2008 Thorsten Kukuk
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


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pwd.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <shadow.h>
#include <sys/stat.h>
#include <sys/resource.h>
#ifdef HAVE_LIBNSCD_H
#include <libnscd.h>
#endif

#include "i18n.h"
#include "error_codes.h"
#include "public.h"
#include "logindefs.h"
#include "read-files.h"
#include "utf8conv.h"
#include "logging.h"

#ifdef USE_LDAP
#include "libldap.h"
#endif

#define DAY (24L*3600L)
#define SCALE DAY

static void
print_usage (FILE *stream, const char *program)
{
  fprintf (stream, _("Usage: %s [-D binddn][-P path][-m mindays][-M maxdays][-d lastday][-I inactive][-E expiredate][-W warndays] user\n"),
	   program);
  fprintf (stream, _("       %s -l user\n"),
	   program);
}

static void
print_help (const char *program)
{
  print_usage (stdout, program);
  fprintf (stdout, _("%s - change user password expiry information\n\n"),
	   program);

#ifdef USE_LDAP
  fputs (_("  -D binddn      Use dn \"binddn\" to bind to the LDAP directory\n"),
         stdout);
#endif
  fputs (_("  -P path        Search passwd and shadow file in \"path\"\n"),
	 stdout);

  fputs (_("  --service srv  Use nameservice 'srv'\n"), stdout);
  fputs (_("  -q, --quiet    Don't be verbose\n"), stdout);
  fputs (_("      --help     Give this help list\n"), stdout);
  fputs (_("  -u, --usage    Give a short usage message\n"), stdout);
  fputs (_("  -v, --version  Print program version\n"), stdout);
  fputs (_("Valid services are: files, nis, nisplus, ldap\n"), stdout);
}

/* Print the time in a human readable format.  */
static void
print_date (time_t date)
{
#ifdef HAVE_STRFTIME
  struct tm *tp;
  char buf[80];

  tp = gmtime (&date);
  strftime (buf, sizeof buf, "%b %d, %Y", tp);
  puts (buf);
#else
  struct tm *tp;
  char *cp;

  tp = gmtime (&date);
  cp = asctime (tp);
  printf ("%6.6s, %4.4s\n", cp + 4, cp + 20);
#endif
}

/* Print the current values of the expiration fields.  */
static void
print_shadow_info (user_t *data)
{
  printf (_("Minimum:\t%ld\n"), data->sp.sp_min);
  printf (_("Maximum:\t%ld\n"), data->sp.sp_max);
  printf (_("Warning:\t%ld\n"), data->sp.sp_warn);
  printf (_("Inactive:\t%ld\n"), data->sp.sp_inact);
  printf (_("Last Change:\t\t"));
  if (data->sp.sp_lstchg == 0)
    printf (_("Unknown, password is forced to change at next login\n"));
  else if (data->sp.sp_lstchg < 0)
    printf (_("Never\n"));
  else
    print_date (data->sp.sp_lstchg * SCALE);
  printf (_("Password Expires:\t"));
  if (data->sp.sp_lstchg <= 0 || data->sp.sp_max >= 10000 * (DAY / SCALE)
      || data->sp.sp_max < 0)
    printf (_("Never\n"));
  else
    print_date (data->sp.sp_lstchg * SCALE + data->sp.sp_max * SCALE);
  printf (_("Password Inactive:\t"));
  if (data->sp.sp_lstchg <= 0 || data->sp.sp_inact < 0 ||
      data->sp.sp_max >= 10000 * (DAY / SCALE) || data->sp.sp_max < 0)
    printf (_("Never\n"));
  else
    print_date (data->sp.sp_lstchg * SCALE +
		(data->sp.sp_max + data->sp.sp_inact) * SCALE);
  printf (_("Account Expires:\t"));
  if (data->sp.sp_expire < 0)
    printf (_("Never\n"));
  else
    print_date (data->sp.sp_expire * SCALE);
}

static int
change_shadow_info (user_t *data)
{
  char *buf, *res, *cp;

  if (asprintf (&buf, "%ld", data->sp.sp_min) < 0)
    return E_FAILURE;
  res = get_value (buf, _("Minimum Password Age"));
  free (buf);
  if (res == NULL ||
      ((data->spn.sp_min = strtol (res, &cp, 10)) == 0 && *cp) ||
      data->spn.sp_min < -1)
    {
      if (cp && *cp)
	fprintf (stderr, _("Input is no integer value\n"));
      else
	fprintf (stderr, _("Negative numbers are not allowed as input (except -1)\n"));
      return E_FAILURE;
    }
  free (res);

  if (asprintf (&buf, "%ld", data->sp.sp_max) < 0)
    return E_FAILURE;
  res = get_value (buf, _("Maximum Password Age"));
  free (buf);
  if (res == NULL ||
      ((data->spn.sp_max = strtol (res, &cp, 10)) == 0 && *cp) ||
      data->spn.sp_max < -1)
    {
      if (cp && *cp)
	fprintf (stderr, _("Input is no integer value\n"));
      else
	fprintf (stderr, _("Negative numbers are not allowed as input (except -1)\n"));
      return E_FAILURE;
    }
  free (res);

  if (asprintf (&buf, "%ld", data->sp.sp_warn) < 0)
    return E_FAILURE;
  res = get_value (buf, _("Password Expiration Warning"));
  free (buf);
  if (res == NULL ||
      ((data->spn.sp_warn = strtol (res, &cp, 10)) == 0 && *cp) ||
      data->spn.sp_warn < -1)
    {
      if (cp && *cp)
	fprintf (stderr, _("Input is no integer value\n"));
      else
	fprintf (stderr, _("Negative numbers are not allowed as input (except -1)\n"));
      return E_FAILURE;
    }
  free (res);

  if (asprintf (&buf, "%ld", data->sp.sp_inact) < 0)
    return E_FAILURE;
  res = get_value (buf, _("Password Inactive"));
  free (buf);
  if (res == NULL ||
      ((data->spn.sp_inact = strtol (res, &cp, 10)) == 0 && *cp) ||
      data->spn.sp_inact < -1)
    return E_FAILURE;

  buf = date2str (data->sp.sp_lstchg * SCALE);
  res = get_value (buf, _("Last Password Change (YYYY-MM-DD)"));
  free (buf);
  if (res == NULL)
    return E_FAILURE;
  else if (strcmp (res, "1969-12-31") == 0 ||
	   strcmp (res, "0") == 0 ||
	   strcmp (res, "-1") == 0)
    data->sp.sp_lstchg = -1;
  else
    {
      data->spn.sp_lstchg = str2date (res);
      free (res);
      if (data->spn.sp_lstchg == -1)
	{
	  fprintf (stderr, _("Invalid date\n"));
	  return E_FAILURE;
	}
    }

  buf = date2str (data->sp.sp_expire * SCALE);
  res = get_value (buf, _("Account Expiration Date (YYYY-MM-DD)"));
  free (buf);
  if (res == NULL)
    return E_FAILURE;
  else if (strcmp (res, "1969-12-31") == 0 ||
	   strcmp (res, "0") == 0 ||
	   strcmp (res, "-1") == 0)
    data->spn.sp_expire = -1;
  else
    {
      data->spn.sp_expire = str2date (res);
      free (res);
      if (data->spn.sp_expire == -1)
	{
	  fprintf (stderr, _("Invalid date\n"));
	  return E_FAILURE;
	}
    }
  return 0;
}

int
main (int argc, char *argv[])
{
  const char *program = "chage";
  uid_t uid = getuid ();
  user_t *pw_data = NULL;
  char *use_service = NULL;
  char *caller_name = NULL;
  char *mindays = NULL, *maxdays = NULL, *lastday = NULL, *inactive = NULL;
  char *expiredate = NULL, *warndays = NULL;
#ifdef USE_LDAP
  char *binddn = NULL;
#endif
  int interactive = 1;
  int silent = 0;
  int l_flag = 0;

#ifdef ENABLE_NLS
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  open_sec_log(program);

  /* Before going any further, raise the ulimit and ignore
     signals.  */
  init_environment ();

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] = {
	{"mindays",    required_argument, NULL, 'm' },
	{"maxdays",    required_argument, NULL, 'M' },
	{"lastday",    required_argument, NULL, 'd' },
	{"inactive",   required_argument, NULL, 'I' },
	{"expiredate", required_argument, NULL, 'E' },
	{"warndays",   required_argument, NULL, 'W' },
	{"list",       no_argument,       NULL, 'l' },
#ifdef USE_LDAP
	{"binddn",     required_argument, NULL, 'D' },
#endif
	{"quiet",      no_argument,       NULL, 'q' },
	{"path",       required_argument, NULL, 'P' },
	{"version",    no_argument,       NULL, 'v' },
	{"usage",      no_argument,       NULL, 'u' },
	{"service",    required_argument, NULL, '\254' },
	{"help",       no_argument,       NULL, '\255' },
	{NULL,         0,                 NULL, '\0'}
      };

      c = getopt_long (argc, argv, "lm:M:d:D:I:E:W:P:vuq",
		       long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
        {
	case 'm':
	  mindays = optarg;
	  interactive = 0;
	  break;
	case 'M':
	  maxdays = optarg;
	  interactive = 0;
	  break;
	case 'd':
	  lastday = optarg;
	  interactive = 0;
	  break;
	case 'I':
	  inactive = optarg;
	  interactive = 0;
	  break;
	case 'E':
	  expiredate = optarg;
	  interactive = 0;
	  break;
	case 'W':
	  warndays = optarg;
	  interactive = 0;
	  break;
#ifdef USE_LDAP
	case 'D':
	  binddn = optarg;
	  break;
#endif
	case 'l':
	  l_flag = 1;
	  break;
	case 'P':
	  if (uid != 0)
	    {
	      sec_log (program, MSG_PATH_ARG_DENIED, uid);
	      fprintf (stderr,
		       _("Only root is allowed to specify another path\n"));
	      return E_NOPERM;
	    }
	  else
	    files_etc_dir = strdup (optarg);
	  break;
	case 'q':
	  silent = 1;
	  break;
	case '\254':
	  if (use_service != NULL)
	    {
	      print_usage (stderr, program);
	      return E_BAD_ARG;
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
	      fprintf (stderr, _("Service `%s' not supported.\n"), optarg);
	      print_usage (stderr, program);
	      return E_BAD_ARG;
	    }
	  break;
        case '\255':
          print_help (program);
          return 0;
        case 'v':
          print_version (program, "2008");
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

  if (l_flag && !interactive)
    {
      fprintf (stderr, _("%s: Do not include \"l\" with other flags\n"),
	       program);
      print_usage (stderr, program);
      return E_USAGE;
    }
  else
    {
      int buflen = 256;
      char *buffer = alloca (buflen);
      struct passwd resultbuf;
      struct passwd *pw;
      char *arg_user;

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
	  sec_log (program, MSG_NO_ACCOUNT_FOUND, uid);
	  fprintf (stderr, _("%s: Cannot determine your user name.\n"),
		   program);
	  return E_UNKNOWN_USER;
	}

      caller_name = strdupa (pw->pw_name);

      /* if we show/modify the data for another user, get the data from
	 this one.  */
      if (argc == 1)
	arg_user = locale_to_utf8 (argv[0]);
      else
	arg_user = pw->pw_name;

      pw_data = do_getpwnam (arg_user, use_service);
      if (pw_data == NULL || pw_data->service == S_NONE)
	{
	  if (use_service)
	    fprintf (stderr,
		     _("%s: User `%s' is not known to service `%s'.\n"),
		     program, utf8_to_locale (arg_user), use_service);
	  else
	    fprintf (stderr, _("%s: Unknown user `%s'.\n"), program,
		     utf8_to_locale (arg_user));
	  return E_UNKNOWN_USER;
	}
    }

  if (!l_flag)
    {
      /* Only root is allowed to change aging for local users. */
      if (uid && (pw_data->service == S_LOCAL
#ifdef USE_LDAP
		  || (pw_data->service == S_LDAP && binddn == NULL)
#endif
		  ))
	{
	  sec_log (program, MSG_PERMISSION_DENIED,
		   pw_data->pw.pw_name, pw_data->pw.pw_uid, uid);
	  fprintf (stderr,
		   _("Only an administrator is allowed to change aging information.\n"));
	  free_user_t (pw_data);
	  return E_NOPERM;
	}

      /* If no shadow entry exist for this account, check if we can
	 create them.  */
      if (!pw_data->use_shadow)
	{
	  char shadowfile[strlen (files_etc_dir) + 8];
	  char *cp = stpcpy (shadowfile, files_etc_dir);
	  strcpy (cp, "/shadow");

	  if (access (shadowfile, F_OK) != 0)
	    {
	      fprintf (stderr,
		       _("This system does not support shadow accounts.\n"));
	      return E_MISSING;
	    }
	  else if (pw_data->service != S_LOCAL)
	    {
	      fprintf (stderr,
		       _("This account does not have a shadow entry.\n"));
	      return E_MISSING;
	    }
	  else
	    {
	      /* Initialize data with dummy values. */
	      pw_data->sp.sp_lstchg = -1;
	      pw_data->sp.sp_min = -1;
	      pw_data->sp.sp_max = -1;
	      pw_data->sp.sp_warn = -1;
	      pw_data->sp.sp_inact = -1;
	      pw_data->sp.sp_expire = -1;
	      pw_data->sp.sp_flag = -1;
	    }
	}
    }

#ifdef USE_LDAP
  if (binddn && pw_data->service == S_LDAP)
    pw_data->oldclearpwd = strdup (get_ldap_password (binddn));
  else
#endif /* USE_LDAP */
    if (do_authentication (program, caller_name, pw_data) != 0)
      {
	sec_log (program, MSG_PERMISSION_DENIED,
		 pw_data->pw.pw_name, pw_data->pw.pw_uid, uid);
	free_user_t (pw_data);
	return E_NOPERM;
      }
  /* We don't need to extra ask for a password with "-l" and if the
     password is stored in the local file.  */
    else if (!l_flag && pw_data->service != S_LOCAL)
      if (get_old_clear_password (pw_data) != 0)
	{
	  free_user_t (pw_data);
	  return E_FAILURE;
	}

  if (l_flag)
    {
      if (uid != 0 && pw_data->service != S_LDAP &&
	  strcmp (caller_name, pw_data->pw.pw_name) != 0)
	{
	  sec_log (program, MSG_PERMISSION_DENIED,
		   pw_data->pw.pw_name, pw_data->pw.pw_uid, uid);
	  fprintf (stderr,
		   _("You can only list your own aging information.\n"));
	  return E_NOPERM;
	}

      if (setgid (getgid ()) || setuid (uid))
	{
	  sec_log (program, MSG_DROP_PRIVILEGE_FAILED, errno, uid);
	  fprintf (stderr, _("%s: Failed to drop privileges: %s\n"),
		   program, strerror (errno));
	  return E_FAILURE;
        }

      if (pw_data->use_shadow)
	{
	  sec_log (program, MSG_SHADOW_DATA_PRINTED,
		   pw_data->pw.pw_name, pw_data->pw.pw_uid, uid);
	  print_shadow_info (pw_data);
	}
      else
	fprintf (stdout, _("No aging information available for %s.\n"),
		 utf8_to_locale (pw_data->pw.pw_name));

      return 0;
    }

  /* Caller must be root or he needs to know the binddn and password
     for LDAP administrator.  */
  if (uid != 0
#ifdef USE_LDAP
      && !(binddn && pw_data->service == S_LDAP)
#endif
      )
    return E_USAGE;

  if (interactive)
    {
      int res;

      if (!silent)
	printf (_("Changing aging information for %s.\n"),
		utf8_to_locale (pw_data->pw.pw_name));

      if ((res = change_shadow_info (pw_data)) != 0)
	{
	  if (!silent)
	    printf (_("Aging information not changed.\n"));
	  return E_FAILURE;
	}
    }
  else
    {
      char *cp;
      int error = 0;

      if (mindays)
	if (((pw_data->spn.sp_min = strtol (mindays, &cp, 10)) == 0 && *cp) ||
	    pw_data->spn.sp_min < -1)
	  ++error;

      if (maxdays)
	if (((pw_data->spn.sp_max = strtol (maxdays, &cp, 10)) == 0 && *cp) ||
	    pw_data->spn.sp_max < -1)
	  ++error;

      if (warndays)
	if (((pw_data->spn.sp_warn = strtol (warndays, &cp, 10)) == 0 && *cp)
	    || pw_data->spn.sp_warn < -1)
	  ++error;

      if (inactive)
	if (((pw_data->spn.sp_inact = strtol (inactive, &cp, 10)) == 0 && *cp)
	    || pw_data->spn.sp_inact < -1)
	  ++error;

      if (lastday)
	{
	  if (strcmp (lastday, "1969-12-31") == 0)
	    pw_data->sp.sp_lstchg = -1;
	  else
	    {
	      pw_data->spn.sp_lstchg = str2date (lastday);
	      if (pw_data->spn.sp_lstchg == -1)
		{
		  if (((pw_data->spn.sp_lstchg =
			strtol (lastday, &cp, 10)) == 0 && *cp) ||
		      pw_data->spn.sp_lstchg < -1)
		    {
		      fprintf (stderr,
			_("Lastday is no date and no integer value >= -1\n"));
		      ++error;
		    }
		}
	    }
	}

      if (expiredate)
	{
	  if (strcmp (expiredate, "1969-12-31") == 0)
	    pw_data->spn.sp_expire = -1;
	  else
	    {
	      pw_data->spn.sp_expire = str2date (expiredate);
	      if (pw_data->spn.sp_expire == -1)
		{
		  if (((pw_data->spn.sp_expire =
			strtol (expiredate, &cp, 10)) == 0 && *cp) ||
		      pw_data->spn.sp_expire < -1)
		    {
		      fprintf (stderr, _("Expiredate is no date and no integer value >= -1\n"));
		      ++error;
		    }
		}
	    }
	}
      if (error)
	{
	  if (!silent)
	    fprintf (stderr, _("Error while parsing options.\n"));
	  free_user_t (pw_data);
	  return E_BAD_ARG;
	}
    }

  /* we don't need to change the data if there is no change */
  if (pw_data->sp.sp_min == pw_data->spn.sp_min &&
      pw_data->sp.sp_max == pw_data->spn.sp_max &&
      pw_data->sp.sp_warn == pw_data->spn.sp_warn &&
      pw_data->sp.sp_inact == pw_data->spn.sp_inact &&
      pw_data->sp.sp_lstchg == pw_data->spn.sp_lstchg &&
      pw_data->sp.sp_expire == pw_data->spn.sp_expire)
    {
      if (!silent)
	printf (_("Aging information not changed.\n"));
      return 0;
    }
  else
    {
      pw_data->sp_changed = TRUE;
      pw_data->todo = DO_MODIFY;
    }

#ifdef USE_LDAP
  if (binddn)
    pw_data->binddn = strdup (binddn);
#endif

  /* We have a shadow file, but this user does not have
     a shadow entry. Create one.  */
  if (!pw_data->use_shadow)
    {
      int rc;

      /* Backup original password and replace it with a "x"
	 in local files. Report error*/
      pw_data->todo = DO_MODIFY;
      pw_data->sp.sp_pwdp = pw_data->pw.pw_passwd;
      pw_data->newpassword = "x";
      rc = write_user_data (pw_data, 0);
      pw_data->newpassword = NULL;

      if (rc != 0)
	{
	  fprintf (stderr,
		   _("Error while converting to shadow account.\n"));
	  free_user_t (pw_data);
	  return E_FAILURE;
	}

      pw_data->use_shadow = 1;
      pw_data->todo = DO_CREATE_SHADOW;
      pw_data->sp.sp_namp = pw_data->pw.pw_name;
      pw_data->sp.sp_lstchg = pw_data->spn.sp_lstchg;
      pw_data->sp.sp_min = pw_data->spn.sp_min;
      pw_data->sp.sp_max = pw_data->spn.sp_max;
      pw_data->sp.sp_warn = pw_data->spn.sp_warn;
      pw_data->sp.sp_inact = pw_data->spn.sp_inact;
      pw_data->sp.sp_expire = pw_data->spn.sp_expire;
    }

  if (write_user_data (pw_data, 0) != 0)
    {
      fprintf (stderr, _("Error while changing aging information.\n"));
      free_user_t (pw_data);
      return E_FAILURE;
    }
  else
    {
#ifdef HAVE_NSCD_FLUSH_CACHE
      nscd_flush_cache ("passwd");
#endif
      if (!silent)
	printf (_("Aging information changed.\n"));
    }

  if (pw_data->sp.sp_min != pw_data->spn.sp_min)
    sec_log (program, MSG_MINIMUM_AGE,
	     pw_data->pw.pw_name, pw_data->pw.pw_uid,
	     pw_data->spn.sp_min, pw_data->sp.sp_min, uid);
  if (pw_data->sp.sp_max != pw_data->spn.sp_max)
    sec_log (program, MSG_MAXIMUM_AGE,
	     pw_data->pw.pw_name, pw_data->pw.pw_uid,
	     pw_data->spn.sp_max, pw_data->sp.sp_max, uid);
  if (pw_data->sp.sp_warn != pw_data->spn.sp_warn)
    sec_log (program, MSG_WARNING_DAYS,
	     pw_data->pw.pw_name, pw_data->pw.pw_uid,
	     pw_data->spn.sp_warn, pw_data->sp.sp_warn, uid);
  if (pw_data->sp.sp_inact != pw_data->spn.sp_inact)
    sec_log (program, MSG_INACTIVE_DAYS,
	     pw_data->pw.pw_name, pw_data->pw.pw_uid,
	     pw_data->spn.sp_inact, pw_data->sp.sp_inact, uid);

  if (pw_data->sp.sp_lstchg != pw_data->spn.sp_lstchg)
    {
      char *new_lstchg, *old_lstchg;

      new_lstchg = date2str (pw_data->spn.sp_lstchg * DAY);
      old_lstchg = date2str (pw_data->sp.sp_lstchg * DAY);
      sec_log (program, MSG_LAST_CHANGE_DATE,
	       pw_data->pw.pw_name, pw_data->pw.pw_uid,
	       new_lstchg, old_lstchg, uid);

      free(new_lstchg);
      free(old_lstchg);
    }
  if (pw_data->sp.sp_expire != pw_data->spn.sp_expire)
    {
      char *new_exp, *old_exp;

      new_exp = date2str (pw_data->spn.sp_expire * DAY);
      old_exp = date2str (pw_data->sp.sp_expire * DAY);
      sec_log (program, MSG_EXPIRE_DATE,
	       pw_data->pw.pw_name, pw_data->pw.pw_uid,
	       new_exp, old_exp, uid);

      free(new_exp);
      free(old_exp);
    }

  free_user_t (pw_data);

  return 0;
}
