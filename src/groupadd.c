/* Copyright (C) 2003, 2004, 2005, 2008 Thorsten Kukuk
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
  fprintf (stream, _("Usage: %s [-D binddn] [-g gid [-o]] [-r] [-P path] [-p password] group\n"),
	   program);
}

static void
print_help (const char *program)
{
  print_usage (stdout, program);
  fprintf (stdout, _("%s - create a new group\n\n"), program);

  fputs (_("  -D binddn      Use dn \"binddn\" to bind to the LDAP directory\n"), stdout);
  fputs (_("  -g gid         Force the new groupid to be the given number\n"),
	 stdout);
  fputs (_("  -o             Allow duplicate (non-unique) UID\n"), stdout);
  fputs (_("  -P path        Search passwd, shadow and group file in \"path\"\n"),
	 stdout);
  fputs (_("  -p password    Encrypted password as returned by crypt(3)\n"),
	 stdout);
  fputs (_("  -r, --system   Create a system account\n"), stdout);
  fputs (_(" --service srv   Add account to nameservice 'srv'\n"), stdout);
  fputs (_("      --help     Give this help list\n"), stdout);
  fputs (_("      --usage    Give a short usage message\n"), stdout);
  fputs (_("  -v, --version  Print program version\n"), stdout);
  fputs (_("Valid services for --service are: files, ldap\n"), stdout);
}

static const char *program = "groupadd";

static struct option long_options[] = {
#ifdef USE_LDAP
  {"binddn",      required_argument, NULL, 'D'},
#endif
  {"force",       no_argument,       NULL, 'f'},
  {"gid",         required_argument, NULL, 'g'},
  {"non-unique",  no_argument,       NULL, 'o'},
  {"path",        required_argument, NULL, 'P'},
  {"password",    required_argument, NULL, 'p'},
  {"preferred-gid", required_argument, NULL, '\252'},
  {"service",     required_argument, NULL, '\253'},
  {"system",      no_argument,       NULL, 'r'},
  {"version",     no_argument,       NULL, 'v'},
  {"usage",       no_argument,       NULL, '\254'},
  {"help",        no_argument,       NULL, '\255'},
  {NULL, 0, NULL, '\0'}
};
static const char *short_options = "D:fg:oP:p:ru:v";

static struct group *
files_getgrent (void)
{
  enum nss_status status;
  static int buflen = 256;
  static char *buffer = NULL;
  static struct group resultbuf;

  if (buffer == NULL)
    buffer = malloc (buflen);

  while ((status = files_getgrent_r (&resultbuf, buffer, buflen, &errno))
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

static struct group *
files_getgrnam (const char *name)
{
  enum nss_status status;
  static int buflen = 256;
  static char *buffer = NULL;
  static struct group resultbuf;

  if (buffer == NULL)
    buffer = malloc (buflen);

  while ((status =
	  files_getgrnam_r (name, &resultbuf, buffer, buflen,
			    &errno)) == NSS_STATUS_TRYAGAIN
	 && errno == ERANGE)
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

static struct group *
files_getgrgid (gid_t gid)
{
  enum nss_status status;
  static int buflen = 256;
  static char *buffer = NULL;
  static struct group resultbuf;

  if (buffer == NULL)
    buffer = malloc (buflen);

  while ((status = files_getgrgid_r (gid, &resultbuf, buffer, buflen, &errno))
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


/* find_free_gid - find the first, free available GID.  */
static gid_t
find_free_gid (int is_system_account, int have_extrapath)
{
  const struct group *grp;
  gid_t groupid, gid_min, gid_max;

  if (is_system_account)
    {
      /* Some special handling for LSB. LSB defines
         the GID range as:
         1 - 99: fix assigned system groups
         100 - 499: dynamic assigned system groups
         If we use -r, try to get a uid from the dynamic
         assigned range.  */
      gid_min = getlogindefs_unum ("SYSTEM_GID_MIN", 100);
      gid_max = getlogindefs_unum ("SYSTEM_GID_MAX", 499);
    }
  else
    {
      gid_min = getlogindefs_unum ("GID_MIN", 500);
      gid_max = getlogindefs_unum ("GID_MAX", 60000);
    }

  groupid = gid_min;

  /* Search the entire group file, looking for the
     largest unused value. If gid_max does already exists,
     skip this.  */
  if (getgrgid (gid_max) == NULL)
    {
      setgrent ();
      while ((grp = getgrent ()))
	{
	  if (grp->gr_gid >= groupid)
	    {
	      if (grp->gr_gid > gid_max)
		continue;
	      groupid = grp->gr_gid + 1;
	    }
	}
      if (have_extrapath && groupid != gid_max + 1)
	{
	  /* If the -P flag is given, not only search in the
	     "official" database, but also in the extra one. */
	  while ((grp = files_getgrent ()))
	    {
	      if (grp->gr_gid >= groupid)
		{
		  if (grp->gr_gid > gid_max)
		    continue;
		  groupid = grp->gr_gid + 1;
		}
	    }
	}
    }
  else
    groupid = gid_max + 1;	/* gid_max exists, so this will be
				   the result of the above loop.  */

  /* If the GID we found is equal to GID_MAX+1, we will step
     through the whole GID_MIN - GID_MAX range and search for
     the first free GID.  */
  if (groupid == gid_max + 1)
    {
      for (groupid = gid_min; groupid < gid_max; groupid++)
	if (getgrgid (groupid) == NULL)
	  {
	    if (have_extrapath)
	      {
		/* The GID is not used  in the normal database, now
		   look in the extra one, too.  */
		if (files_getgrgid (groupid) == NULL)
		  break;
	      }
	    else
	      break;
	  }

      if (groupid == gid_max)
	{
	  fprintf (stderr, _("%s: Can't get unique gid in range %u - %u.\n"),
		   program, gid_min, gid_max);
	  sec_log (program, MSG_NO_FREE_GID, gid_min, gid_max);
	  exit (E_FAILURE);
	}
    }
  return groupid;
}

int
main (int argc, char **argv)
{
  char *use_service = NULL;
#ifdef USE_LDAP
  char *binddn = NULL;
#endif
  char *new_group = NULL;
  char *new_password = NULL;
  int prefer_gid = 0;
  int know_gid = 0;
  gid_t new_gid = 0;
  int system_account = 0;
  int non_unique = 0;
  int have_extrapath = 0;
  int force_add = 0;

#ifdef ENABLE_NLS
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);
#endif

  /* Before going any further, raise the ulimit and ignore
     signals.  */

  init_environment ();

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
        case 'D':
#ifdef USE_LDAP
	  binddn = optarg;
#endif
          break;
	case 'f':
	  fprintf (stderr,
		   _("%s: You are using an undocumented option (-f)!\n"),
		   program);
	  force_add = 1;
	  break;
	case 'g':
	  if (strtoid (optarg, &new_gid) == -1)    /* invalid number */
	    {
	      fprintf (stderr,
		       _("%s: Invalid numeric argument `%s' for Group ID.\n"),
		       program, optarg);
	      return E_BAD_ARG;
	    }
	  know_gid = 1;
	  break;
	case '\252':
	  if (strtoid (optarg, &new_gid) == -1)    /* invalid number */
	    {
	      fprintf (stderr,
		       _("%s: Invalid numeric argument `%s' for Group ID.\n"),
		       program, optarg);
	      return E_BAD_ARG;
	    }
	  prefer_gid = 1;
	  break;
	case 'o':
	  non_unique = 1;
	  break;
	case 'P':
	  files_etc_dir = strdup (optarg);
	  have_extrapath = 1;
	  /* If -P option is used, set use_service to "files" if not
	     already set through an option. If we don't limitate to
	     service files, we can get trouble finding the right
	     source.  */
	  if (!use_service)
	    use_service = "files";
	  break;
	case 'p':		/* set encrypted password */
	  if (strcspn (optarg, ":\n") != strlen (optarg))
	    {
	      fprintf (stderr, _("%s: Invalid characters in password `%s'.\n"),
		       program, optarg);
	      return E_BAD_ARG;
	    }
	  new_password = optarg;
	  break;
	case 'r':
	  system_account = 1;
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
	case 'v':
	  print_version (program, "2008");
	  return 0;
	case '\254':
	  print_usage (stdout, program);
	  return 0;
	default:
	  print_error (program);
	  return E_USAGE;
	}
    }

  if(know_gid && prefer_gid)
    {
      fprintf (stderr, _("%s: You cannot use --gid and --preferred-gid at the same time.\n"),
	       program);
      return E_BAD_ARG;
    }

  if(!know_gid && prefer_gid)
    {
      know_gid = 1;
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
  else if (force_add && non_unique)
    {
      fprintf (stderr, _("%s: You cannot use -f with -o.\n"), program);
      print_usage (stderr, program);
      return E_USAGE;
    }
  else
    {
      int buflen = 256;
      char *buffer = alloca (buflen);
      struct passwd resultbuf;
      struct passwd *pw;

      open_sec_log (program);

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
	  return E_UNKNOWN_USER;
	}

      if (do_authentication ("shadow" /* XXX program */,
			     pw->pw_name, NULL) != 0)
	{
	  sec_log (program, MSG_PERMISSION_DENIED, pw->pw_name,
		   pw->pw_uid, getuid() );
	  return E_NOPERM;
	}
    }

  /* After this, we can start creating the new group.  */
  if (know_gid && !non_unique)
    {
      if (getgrgid (new_gid) != NULL ||
	  (have_extrapath && files_getgrgid (new_gid) != NULL))
	{
	  if (force_add)
	    {
	      /* If -f was given, reset -g option.  */
	      fprintf (stderr,
		       _("%s: GID %u is not unique, using another one.\n"),
		       program, new_gid);
	      know_gid = 0;
	    }
	  else if (prefer_gid)
	    {
	      know_gid = 0;
	    }
	  else
	    {
	      fprintf (stderr, _("%s: GID %u is not unique.\n"),
		       program, new_gid);
	      sec_log (program, MSG_GID_NOT_UNIQUE, new_gid, getuid ());
	      return E_GID_IN_USE;
	    }
	}
    }

  new_group = locale_to_utf8 (argv[0]);
  if (check_name (new_group) != 0)
    {
      fprintf (stderr, _("%s: Invalid group name `%s'.\n"),
	       program, utf8_to_locale (new_group));
      sec_log (program, MSG_GROUP_NAME_INVALID, new_group, getuid())
      return E_BAD_ARG;
    }

  /* Lock group file, so that a concurrent useradd process will not
     add the user a second time or a second user with the same uid.  */
  if ((use_service == NULL || strcmp (use_service, "files") == 0) &&
      lock_database () != 0)
    {
      fputs (_("Cannot lock group file: already locked.\n"), stderr);
      sec_log (program, MSG_GROUP_FILE_ALREADY_LOCKED);
      return E_PWDBUSY;
    }
  else if (getgrnam (new_group) != NULL ||
	   (have_extrapath && files_getgrnam (new_group) != NULL))
    {				/* Group does already exists.  */
      fprintf (stderr, _("%s: Group `%s' already exists.\n"),
	       program, utf8_to_locale (new_group));
      sec_log (program, MSG_GROUP_ALREADY_EXISTS, new_group, getuid ());
      return E_NAME_IN_USE;
    }
  else
    {
      int i;
      group_t gr_data;
      int retval = E_SUCCESS;

      memset (&gr_data, 0, sizeof (gr_data));

      if (use_service)
	{
	  if (strcmp (use_service, "files") == 0)
	    gr_data.service = S_LOCAL;
	  else if (strcmp (use_service, "ldap") == 0)
	    gr_data.service = S_LDAP;
	}
      else
	gr_data.service = S_LOCAL;

      gr_data.todo = DO_CREATE;

      gr_data.gr.gr_name = new_group;
      if (new_password)
	gr_data.gr.gr_passwd = new_password;
      else
	gr_data.gr.gr_passwd = "!";

      gr_data.gr.gr_gid = know_gid ? new_gid : find_free_gid (system_account,
							      have_extrapath);

#ifdef USE_LDAP
      if (gr_data.service == S_LDAP)
	{
	  if (binddn == NULL)
	    {
	      binddn = get_caller_dn ();
	      if (binddn == NULL)
		{
		  fprintf (stderr, _("%s: Cannot add group to LDAP database without DN.\n"),
			   program);
		}
	      else gr_data.binddn = strdup (binddn);
	    }
	  else
	    gr_data.binddn = strdup (binddn);

	  if (gr_data.oldclearpwd == NULL)
	    {
	      char *cp = get_ldap_password (gr_data.binddn);

	      if (cp)
		gr_data.oldclearpwd = strdup (cp);
	      else
		{
		  fprintf (stderr,
			   _("%s: Group not added to LDAP database.\n"),
			   program);
		  return E_FAILURE;
		}
	    }
	}
#endif

      if (write_group_data (&gr_data, 1) != 0)
	{
	  sec_log (program, MSG_ERROR_ADDING_NEW_GROUP, gr_data.gr.gr_name,
		   (unsigned int) gr_data.gr.gr_gid, getuid());
	  return E_FAILURE;
	}
      else
	{
	  sec_log (program, MSG_NEW_GROUP_ADDED, gr_data.gr.gr_name,
		   (unsigned int) gr_data.gr.gr_gid, getuid());
	}

#ifdef HAVE_NSCD_FLUSH_CACHE
      /* flush NSCD cache.  */
      nscd_flush_cache ("group");
#endif

      if (use_service == NULL || strcmp (use_service, "files") == 0)
	ulckpwdf ();

      i = call_script ("GROUPADD_CMD", gr_data.gr.gr_name,
		       gr_data.gr.gr_gid, getuid (), NULL, program);
      if (i != 0)
	{
	  fprintf (stderr, _("%s: GROUPADD_CMD fails with exit code %d.\n"),
		   program, i);
	  retval = E_FAILURE;
	}

      return retval;
    }

  return E_SUCCESS;
}
