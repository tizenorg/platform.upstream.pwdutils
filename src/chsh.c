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
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <syslog.h>
#include <string.h>
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
#include "read-files.h"
#include "error_codes.h"

#ifdef USE_LDAP
#include "libldap.h"
#endif

static void
print_usage (FILE *stream, const char *program)
{
  fprintf (stream, _("Usage: %s [-D binddn] [-P path] [-s shell] [-l] [-q]\n            [--help] [--usage] [--version] [user]\n"),
	   program);
}

static void
print_help (const char *program)
{
  print_usage (stdout, program);
  fprintf (stdout, _("%s - change login shell\n\n"), program);

#ifdef USE_LDAP
  fputs (_("  -D binddn      Use dn \"binddn\" to bind to the LDAP directory\n"),
         stdout);
#endif
  fputs (_("  -P path        Search passwd and shadow file in \"path\"\n"),
         stdout);
  fputs (_("  -l             List allowed shells from /etc/shells\n"),
         stdout);
  fputs (_("  -s shell       Use 'shell' as new login shell\n"), stdout);
  if (strcmp (program, "chsh") == 0)
    fputs (_("  --service srv  Use nameservice 'srv'\n"), stdout);
  fputs (_("  -q, --quiet    Don't be verbose\n"), stdout);
  fputs (_("      --help     Give this help list\n"), stdout);
  fputs (_("  -u, --usage    Give a short usage message\n"), stdout);
  fputs (_("  -v, --version  Print program version\n"), stdout);

  if (strcmp (program, "chsh") == 0)
    fputs (_("Valid services are: files, nis, nisplus, ldap\n"),
	   stdout);
}

/* If the given shell appears in /etc/shells, return 1. If not,
   return 0. If the given shell is NULL, /etc/shells is outputted
   to stdout. */
static int
get_shell_list (const char *shell_name)
{
#ifndef HAVE_GETUSERSHELL
  FILE *fp;
  char buf[BUFSIZ];
#else
  char *buf;
#endif
  int found;
  int len;

  found = 0;

#ifdef HAVE_GETUSERSHELL
  setusershell();
#else
  fp = fopen ("/etc/shells", "r");
  if (! fp)
    {
      if (! shell_name)
	printf (_("No known shells.\n"));
      return 1;
    }
#endif

#ifdef HAVE_GETUSERSHELL
  while ((buf = getusershell ()))
#else
  while (fgets (buf, sizeof (buf), fp) != NULL)
#endif
    {
      /* ignore comments */
      if (*buf == '#')
	continue;
      len = strlen (buf);
      /* strip the ending newline */
      if (buf[len - 1] == '\n')
	buf[len - 1] = 0;
      /* check or output the shell */
      if (shell_name)
	{
	  if (! strcmp (shell_name, buf))
	    {
	      found = 1;
	      break;
            }
        }
      else
	printf ("%s\n", buf);
    }
#ifdef HAVE_GETUSERSHELL
  endusershell();
#else
  fclose (fp);
#endif
  return found;
}

/* return 1 if the named shell begins with 'r' or 'R'
   If the first letter of the filename is 'r' or 'R', the shell is
   considered to be restricted. */
static int
restricted_shell (const char *sh)
{
#if 0
  char *cp = Basename((char *) sh);
  return *cp == 'r' || *cp == 'R';
#else
  /* Shells not listed in /etc/shells are considered to be
     restricted.  Changed this to avoid confusion with "rc"
     (the plan9 shell - not restricted despite the name
     starting with 'r'). */
  return !get_shell_list (sh);
#endif
}

/* If the shell is completely invalid, print an error and
   return 1. If root changes the shell, print only a warning.
   Only exception: Invalid characters are always not allowed.  */
static int
check_shell (const char *program, const char *shell)
{
  uid_t uid = getuid ();
  size_t i;
  int c;

  if (*shell != '/')
    {
      fprintf (stderr, _("%s: Shell must be a full path name.\n"), program);
      if (uid)
	return 1;
    }
  if (access (shell, F_OK) < 0)
    {
      fprintf (stderr, _("%s: `%s' does not exist.\n"), program, shell);
      if (uid)
	return 1;
    }
  if (access (shell, X_OK) < 0)
    {
      fprintf (stderr, _("%s: `%s' is not executable.\n"), program, shell);
      if (uid)
	return 1;
    }
  /* keep /etc/passwd clean. */
  for (i = 0; i < strlen (shell); i++)
    {
      c = shell[i];
      if (c == ',' || c == ':' || c == '=' || c == '"' || c == '\n')
	{
	  fprintf (stderr, _("%s: '%c' is not allowed.\n"), program, c);
	  return 1;
        }
      if (iscntrl (c))
	{
	  fprintf (stderr, _("%s: Control characters are not allowed.\n"),
		   program);
	  return 1;
        }
    }
  if (! get_shell_list (shell))
    {
      if (uid == 0)
	printf (_("Warning: \"%s\" is not listed in /etc/shells.\n"), shell);
      else
	{
	  fprintf (stderr, _("%s: \"%s\" is not listed in /etc/shells.\n"),
		   program, shell);
	  fprintf (stderr, _("%s: Use -l option to see list.\n"), program);
	  return 1;
	}
    }
  return 0;
}


int
main (int argc, char *argv[])
{
  uid_t uid = getuid ();
  char *new_shell = NULL;
  int l_flag = 0;
  int silent = 0;
  user_t *pw_data = NULL;
  char *use_service = NULL;
  char *caller_name = NULL;
  char *locale_name;
  const char *program = basename (argv[0]);
#ifdef USE_LDAP
  char *binddn = NULL;
#endif

#ifdef ENABLE_NLS
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  openlog (program, LOG_PID, LOG_AUTHPRIV);

  /* Before going any further, raise the ulimit and ignore
     signals.  */
  init_environment ();

  if (strcasecmp (program, "ypchsh") == 0)
    use_service = "nis";
  else if (strcasecmp (program, "chsh") != 0)
    {
      fprintf (stderr, _("%s: Don't know what I should do.\n"), program);
      return 1;
    }

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
	{
#ifdef USE_LDAP
	  {"binddn",      required_argument, NULL, 'D' },
#endif
	  {"path",        required_argument, NULL, 'P' },
	  {"shell",       required_argument, NULL, 's' },
	  {"list-shells", no_argument,       NULL, 'l' },
	  {"quiet",       no_argument,       NULL, 'q' },
	  {"version",     no_argument,       NULL, 'v' },
	  {"usage",       no_argument,       NULL, 'u' },
	  {"service",     required_argument, NULL, '\254' },
	  {"help",        no_argument,       NULL, '\255' },
	  {NULL,          0,                 NULL, '\0'}
	};

      c = getopt_long (argc, argv, "D:P:s:r:lvuq",
		       long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
        {

        case 'l':
	  l_flag = 1;
	  break;
        case 's':
	  if (! optarg)
	    {
	      print_usage (stderr, program);
	      return 1;
            }
	  new_shell = strdup (optarg);
	  break;
	case '\254':
	  if (use_service != NULL)
	    {
	      print_usage (stderr, program);
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
	      fprintf (stderr, _("Service `%s' not supported.\n"), optarg);
	      print_usage (stderr, program);
	      return 1;
	    }
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
          return 1;
        }
    }

  argc -= optind;
  argv += optind;

  if (argc > 1 || (l_flag && argc > 0))
    {
      fprintf (stderr, _("%s: Too many arguments.\n"), program);
      print_error (program);
      return 1;
    }

  if (l_flag && new_shell)
    {
      fprintf (stderr, _("%s: Too many arguments.\n"), program);
      print_error (program);
      return 1;
    }

  if (l_flag)
    {
      get_shell_list (NULL);
      return 0;
    }
  else
    {
      int buflen = 256;
      char *buffer = alloca (buflen);
      struct passwd resultbuf;
      struct passwd *pw;

      /* Determine our own user name for PAM authentication.  */
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
	    fprintf (stderr, _("%s: User `%s' is not known to service `%s'.\n"),
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
          (selinux_check_access (pw_data->pw.pw_name, PASSWD__CHSH) != 0))
        {
          security_context_t user_context;
          if (getprevcon (&user_context) < 0)
            user_context =
              (security_context_t) strdup (_("Unknown user context"));
	  fprintf (stderr,
		  _("%s: %s is not authorized to change the shell of `%s'.\n"),
		   program, user_context, locale_name);
	  if (security_getenforce() > 0)
	    {
	      syslog (LOG_ALERT,
		      "%s is not authorized to change the shell of `%s'",
		      user_context, pw_data->pw.pw_name);
	      freecon (user_context);
	      return E_NOPERM;
	    }
	  else
	    {
	      fprintf (stderr,
		       _("SELinux is in permissive mode, continuing\n"));
	      freecon (user_context);
	    }
        }
    }
#endif


  /* Only root is allowed to change shell for local users. */
  if (uid && uid != pw_data->pw.pw_uid &&
      (pw_data->service == S_LOCAL
#ifdef USE_LDAP
       || (pw_data->service == S_LDAP && binddn == NULL)
#endif
       ))
    {
      syslog (LOG_ERR, "%u cannot change shell for \"%s\"", uid,
	      pw_data->pw.pw_name);
      fprintf (stderr, _("You cannot change the shell for %s.\n"),
	       caller_name);
      free_user_t (pw_data);
      return 1;
    }

  /* Normal user with restricted shell is not allowed to change it. */
  if (uid && restricted_shell (pw_data->pw.pw_shell))
    {
      syslog (LOG_ERR, "User `%s' tries to change a restricted shell",
	      pw_data->pw.pw_name);
      fprintf(stderr, _("You cannot change a restricted shell.\n"));
      free_user_t (pw_data);
      return 1;
    }

  if (!silent)
    printf (_("Changing login shell for %s.\n"), locale_name);

  if (getlogindefs_bool ("CHFN_AUTH", 1) || pw_data->service != S_LOCAL)
    {
#ifdef USE_LDAP
      if (binddn && pw_data->service == S_LDAP)
        {
          /* A user tries to change data stored in a LDAP database and
             knows the Manager dn, now we need the password from him.  */
          ldap_session_t *session = create_ldap_session (LDAP_PATH_CONF);
          char *cp;

          if (session == NULL)
            return E_FAILURE;

          cp = getpass (_("Enter LDAP Password:"));

          pw_data->binddn = strdup (binddn);

          if (open_ldap_session (session) != 0)
            return E_FAILURE;

          if (ldap_authentication (session, NULL, binddn, cp) != 0)
            return E_NOPERM;

          close_ldap_session (session);

          pw_data->oldclearpwd = strdup (cp);
        }
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

  if (new_shell == NULL)
    {
      /* Allow user to abort with Ctrl-C here.  */
      signal (SIGINT, SIG_DFL);
      printf (_("Enter the new value, or press return for the default.\n"));
      new_shell = get_value (pw_data->pw.pw_shell, _("Login Shell"));
      signal (SIGINT, SIG_IGN);
    }

  /* we don't need to change the shell if here is no change */
  if (new_shell == NULL || strcmp (pw_data->pw.pw_shell, new_shell) == 0)
    {
      if (!silent)
	printf (_("Shell not changed.\n"));
      return 0;
    }

  pw_data->new_shell = new_shell;

  if (check_shell (program, new_shell) != 0)
    {
      free_user_t (pw_data);
      return 1;
    }

  if (write_user_data (pw_data, 0) != 0)
    {
      fprintf (stderr, _("Error while changing login shell.\n"));
      free_user_t (pw_data);
      return 1;
    }
  else
    {
#ifdef HAVE_NSCD_FLUSH_CACHE
      nscd_flush_cache ("passwd");
#endif
      if (!silent)
	printf (_("Shell changed.\n"));
    }

  free_user_t (pw_data);

  return 0;
}
