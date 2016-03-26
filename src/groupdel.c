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
#include "config.h"
#endif

#include <time.h>
#include <utmp.h>
#include <fcntl.h>
#include <paths.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <libgen.h>
#include <sys/resource.h>
#ifdef HAVE_LIBNSCD_H
#include <libnscd.h>
#endif

#ifdef USE_LDAP
#include "libldap.h"
#endif

#include "i18n.h"
#include "group.h"
#include "public.h"
#include "logging.h"
#include "utf8conv.h"
#include "logindefs.h"
#include "read-files.h"
#include "error_codes.h"

static void
print_usage (FILE *stream, const char *program)
{
  fprintf (stream, _("Usage: %s [-D binddn] [-P path] group\n"), program);
}

static void
print_help (const char *program)
{
  print_usage (stdout, program);
  fprintf (stdout, _("%s - delete a group\n\n"), program);

#ifdef USE_LDAP
  fputs (_("  -D binddn      Use dn \"binddn\" to bind to the LDAP directory\n"),
         stdout);
#endif
  fputs (_("  -P path        Search passwd, shadow and group file in \"path\"\n"),
	 stdout);
  fputs (_(" --service srv   Add account to nameservice 'srv'\n"), stdout);
  fputs (_("      --help     Give this help list\n"), stdout);
  fputs (_("  -u, --usage    Give a short usage message\n"), stdout);
  fputs (_("  -v, --version  Print program version\n"), stdout);
  fputs (_("Valid services for --service are: files, ldap\n"), stdout);
}

static const char *program = "groupdel";

static struct option long_options[] = {
#ifdef USE_LDAP
  {"binddn",      required_argument, NULL, 'D' },
#endif
  {"force",       no_argument,       NULL, 'f'},
  {"remove-home", no_argument,       NULL, 'r'},
  {"path",        required_argument, NULL, 'P'},
  {"version",     no_argument,       NULL, 'v'},
  {"service",     required_argument, NULL, '\253'},
  {"usage",       no_argument,       NULL, 'u'},
  {"help",        no_argument,       NULL, '\255'},
  {NULL, 0, NULL, '\0'}
};
static const char *short_options = "D:frP:uv";

static struct passwd *
files_getpwent (void)
{
  enum nss_status status;
  static int buflen = 256;
  static char *buffer = NULL;
  static struct passwd resultbuf;

  if (buffer == NULL)
    buffer = malloc (buflen);

  while ((status = files_getpwent_r (&resultbuf, buffer, buflen, &errno))
	 == NSS_STATUS_TRYAGAIN && errno == ERANGE)
    {
      errno = 0;
      buflen += 256;
      buffer = realloc (buffer, buflen);
    }
  if (status == NSS_STATUS_SUCCESS)
    return &resultbuf;
  else
    return NULL;
}

static int
is_primary_group (gid_t gid, int have_extrapath)
{
  struct passwd *pw;
  int retval = 0;

  setpwent ();

  while ((pw = getpwent ()))
    {
      if (pw->pw_gid == gid)
	{
	  fprintf (stderr,
		   _("%s: GID `%u' is primary group of `%s'.\n"),
		   program, (unsigned int) gid,
		   utf8_to_locale (pw->pw_name));
	  sec_log (program, MSG_GID_IS_PRIMARY_GROUP, (unsigned int) gid,
		   pw->pw_name, getuid ());
	  retval = 1;
	}
    }

  endpwent ();

  if (have_extrapath)
    while ((pw = files_getpwent ()))
      {
      if (pw->pw_gid == gid)
	{
	  fprintf (stderr,
		   _("%s: GID `%u' is primary group of `%s'.\n"),
		   program, (unsigned int) gid,
		   utf8_to_locale (pw->pw_name));
	  sec_log (program, MSG_GID_IS_PRIMARY_GROUP, (unsigned int) gid,
		   pw->pw_name, getuid ());
	  retval = 1;
	}
      }

  return retval;
}

int
main (int argc, char **argv)
{
  char *use_service = NULL;
#ifdef USE_LDAP
  char *binddn = NULL;
#endif
  char *remove_group;
  int have_extrapath = 0;
  group_t *gr_data;
  int retval = E_SUCCESS;

#ifdef ENABLE_NLS
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);
#endif

  /* Before going any further, raise the ulimit and ignore
     signals.  */

  init_environment ();

  open_sec_log (program);

  while (1)
    {
      int c;
      int option_index = 0;

      c = getopt_long (argc, argv, short_options,
		       long_options, &option_index);
      if (c == (-1))
	break;
      switch (c)
	{
#ifdef USE_LDAP
	case 'D':
	  binddn = optarg;
	  break;
#endif
	case 'P':
	  files_etc_dir = strdup (optarg);
	  have_extrapath = 1;
	  /* If -P option is used, set service to "files" if not already
	     set through an option. If we don't limitate to service files,
	     we can get trouble finding the right source.  */
	  if (!use_service)
	    use_service = "files";
	  break;
	case '\253':
	  if (use_service != NULL)
            {
              print_usage (stderr, program);
              return E_BAD_ARG;
            }

          if (strcasecmp (optarg, "files") == 0)
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
	case 'u':
	  print_usage (stdout, program);
	  return 0;
	case 'v':
	  print_version (program, "2005");
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
  else if (argc == 0)
    {
      fprintf (stderr, _("%s: Too few arguments.\n"), program);
      print_error (program);
      return E_USAGE;
    }
  else
    {
      int buflen = 256;
      char *buffer = alloca (buflen);
      struct passwd resultbuf;
      struct passwd *pw;

      /* Determine our own user name for PAM authentication.  */
      while (getpwuid_r (getuid (), &resultbuf, buffer, buflen, &pw) != 0
	     && errno == ERANGE)
	{
	  errno = 0;
	  buflen += 256;
	  buffer = alloca (buflen);
	}

      if (!pw)
	{
	  sec_log (program, MSG_NO_ACCOUNT_FOUND, getuid ());
	  fprintf (stderr, _("%s: Cannot determine your user name.\n"),
		   program);
	  return E_NOTFOUND;
	}

      if (do_authentication ("shadow", pw->pw_name, NULL) != 0)
	{
          sec_log (program, MSG_PERMISSION_DENIED, pw->pw_name,
                   pw->pw_uid, getuid());
          return E_NOPERM;
        }
    }

  remove_group = locale_to_utf8 (argv[0]);

  gr_data = find_group_data (remove_group, 0, use_service);
  if (gr_data == NULL || gr_data->service == S_NONE)
    {
      if (use_service)
	fprintf (stderr, _("%s: Group `%s' not found in service `%s'.\n"),
		 program, utf8_to_locale (remove_group), use_service);
      else
	fprintf (stderr, _("%s: Unknown group `%s'.\n"), program,
		 utf8_to_locale (remove_group));

      sec_log (program, MSG_UNKNOWN_GROUP, remove_group, getuid ());

      return E_NOTFOUND;
    }

  if (is_primary_group (gr_data->gr.gr_gid, have_extrapath))
    {
      fprintf (stderr, _("%s: Cannot remove user's primary group.\n"),
	       program);
      sec_log (program, MSG_CANNOT_REMOVE_PRIMARY_GROUP,
	       gr_data->gr.gr_name, getuid());
      return E_GROUP_BUSY;
    }

#ifdef USE_LDAP
  if (gr_data->service == S_LDAP)
    {
      if (binddn == NULL)
	{
	  binddn = get_caller_dn ();
	  if (binddn == NULL)
	    {
	      fprintf (stderr, _("%s: Cannot delete group from LDAP database without DN.\n"),
		       program);
	    }
	  else gr_data->binddn = strdup (binddn);
	}
      else
	gr_data->binddn = strdup (binddn);

      if (gr_data->oldclearpwd == NULL)
	{
	  char *cp = get_ldap_password (gr_data->binddn);

	  if (cp)
	    gr_data->oldclearpwd = strdup (cp);
	  else
	    {
	      fprintf (stderr,
		       _("%s: Group not deleted from LDAP database.\n"),
		       program);
	      return E_FAILURE;
	    }
	}
    }
#endif

#if 0 /* XXX */
  i = call_script ("GROUPDEL_PRECMD", pw_data->pw.pw_name, pw_data->pw.pw_uid,
		   pw_data->pw.pw_gid, pw_data->pw.pw_dir);
  if (i != 0)
    {
      fprintf (stderr, _("%s: GROUPDEL_PRECMD fails with exit code %d.\n"),
	       program, i);
      return E_FAILURE;
    }
#endif

  /* Lock group file, so that a concurrent processes will not
     use this group.  */
  if (gr_data->service == S_LOCAL && lock_database () != 0)
    {
      fputs (_("Cannot lock group file: already locked.\n"), stderr);
      sec_log (program, MSG_GROUP_FILE_ALREADY_LOCKED);
      return E_PWDBUSY;
    }

  gr_data->todo = DO_DELETE;
  if (write_group_data (gr_data, 1) != 0)
    {
      fprintf (stderr, _("%s: Error deleting group `%s'.\n"),
	       program, utf8_to_locale (gr_data->gr.gr_name));
      sec_log (program, MSG_ERROR_REMOVING_GROUP, gr_data->gr.gr_name,
	       gr_data->gr.gr_gid, getuid ());
      free_group_t (gr_data);
      return E_FAILURE;
    }
  else
    sec_log (program, MSG_GROUP_DELETED, gr_data->gr.gr_name,
	     gr_data->gr.gr_gid, getuid ());

#ifdef HAVE_NSCD_FLUSH_CACHE
  /* flush NSCD cache to remove group really from the system.  */
  nscd_flush_cache ("group");
#endif

  if (gr_data->service == S_LOCAL)
    ulckpwdf ();

#if 0 /* XXX */
  i = call_script ("GROUPDEL_POSTCMD", pw_data->pw.pw_name, pw_data->pw.pw_uid,
		   pw_data->pw.pw_gid, pw_data->pw.pw_dir);
  if (i != 0)
    {
      fprintf (stderr, _("%s: GROUPDEL_POSTCMD fails with exit code %d.\n"),
	       program, i);
      return E_FAILURE;
    }
#endif

  free_group_t (gr_data);

  return retval;
}
