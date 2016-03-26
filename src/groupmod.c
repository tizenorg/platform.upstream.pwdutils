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
print_usage (FILE * stream, const char *program)
{
  fprintf (stream, _("Usage: %s [-g gid [-o]] [-n new_name] group\n"), program);
}

static void
print_help (const char *program)
{
  print_usage (stdout, program);
  fprintf (stdout, _("%s - modify a group entry\n\n"), program);

  fputs (_("  -D binddn      Use dn \"binddn\" to bind to the LDAP directory\n"),
	 stdout);
  fputs (_("  -g gid         Change the groupid to the given number\n"),
	 stdout);
  fputs (_("  -k skeldir     Specify an alternative skel directory\n"),
	 stdout);
  fputs (_("  -n name        Change group name.\n"), stdout);
  fputs (_("  -o             Allow duplicate (non-unique) UID\n"), stdout);
  fputs (_("  -P path        Search passwd, shadow and group file in \"path\"\n"),
	 stdout);
  fputs (_("  -p password    Encrypted password as returned by crypt(3)\n"),
	 stdout);
  fputs (_("  -A user        Add the user to the group entry\n"), stdout);
  fputs (_("  -R user        Remove the user from the group entry\n"), stdout);
  fputs (_("  --service srv  Use nameservice 'srv'\n"), stdout);
  fputs (_("      --help     Give this help list\n"), stdout);
  fputs (_("      --usage    Give a short usage message\n"), stdout);
  fputs (_("  -v, --version  Print program version\n"), stdout);
  fputs (_("Valid services are: files, ldap\n"), stdout);
}

static const char *program = "groupmod";

static struct option long_options[] = {
#ifdef USE_LDAP
  {"binddn", required_argument, NULL, 'D'},
#endif
  {"gid", required_argument, NULL, 'g'},
  {"name", required_argument, NULL, 'n'},
  {"non-unique", no_argument, NULL, 'o'},
  {"path", required_argument, NULL, 'P'},
  {"password", required_argument, NULL, 'p'},
  {"add-user", required_argument, NULL, 'A'},
  {"remove-user", required_argument, NULL, 'R'},
  {"version", no_argument, NULL, 'v'},
  {"service", required_argument, NULL, '\253'},
  {"usage", no_argument, NULL, '\254'},
  {"help", no_argument, NULL, '\255'},
  {NULL, 0, NULL, '\0'}
};
static const char *short_options = "A:D:g:n:oP:p:R:v";

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

/* XXX move to libpwdutils.  */
static char **
add_gr_mem (const char *name, char **gr_mem)
{
  char **groups;
  unsigned int i;
  int already_added = 0;

  i = 0;
  while (gr_mem[i])
    {
      if (strcmp (gr_mem[i], name) == 0)
        already_added = 1;
      ++i;
    }
  ++i;                          /* for trailing NULL pointer */

  if (!already_added)
    ++i;

  groups = malloc (i * sizeof (char *));
  i = 0;
  while (gr_mem[i])
    {
      groups[i] = strdup (gr_mem[i]);
      ++i;
    }

  if (!already_added)
    {
      groups[i] = strdup (name);
      ++i;
    }

  groups[i] = NULL;

  return groups;
}

int
main (int argc, char **argv)
{
  char *use_service = NULL;
  group_t *gr_data;
#ifdef USE_LDAP
  char *binddn = NULL;
#endif
  char *modify_group;
  char *new_name = NULL;
  char *new_password = NULL;
  gid_t new_gid = 0;
  char *know_gid = NULL;
  char *remove_user = NULL;
  char *add_user = NULL;
  int non_unique = 0;
  int have_extrapath = 0;
  int retval = E_SUCCESS;

#ifdef ENABLE_NLS
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);
#endif

  open_sec_log (program);

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
	case 'g':
	  if (strtoid (optarg, &new_gid) == -1)	/* invalid number */
	    {
	      fprintf (stderr,
		       _("%s: invalid numeric argument `%s' for Group ID.\n"),
		       program, optarg);
	      return E_BAD_ARG;
	    }
	  know_gid = optarg;
	  break;
	case 'n':
	  new_name = locale_to_utf8 (optarg);
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
	      fprintf (stderr,
		       _("%s: invalid characters in password `%s'.\n"),
		       program, optarg);
	      return E_BAD_ARG;
	    }
	  new_password = optarg;
	  break;
	case 'R':
	  if (remove_user != NULL)
	    {
	      print_usage (stderr, program);
	      return E_BAD_ARG;
	    }
	  remove_user = locale_to_utf8 (optarg);
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
	case 'A':
	  if (add_user != NULL)
	    {
	      print_usage (stderr, program);
	      return E_BAD_ARG;
	    }
	  add_user = locale_to_utf8 (optarg);
	  break;
	case '\255':
	  print_help (program);
	  return 0;
	case 'v':
	  print_version (program, "2005");
	  return 0;
	case '\254':
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
	  return E_UNKNOWN_USER;
	}

      if (do_authentication ("shadow", pw->pw_name, NULL) != 0)
	{
	  sec_log (program, MSG_PERMISSION_DENIED, pw->pw_name,
                   pw->pw_uid, getuid());
	  return E_NOPERM;
	}
    }

  modify_group = locale_to_utf8 (argv[0]);
  /* Check, if the account we should modify exist.  */
  gr_data = find_group_data (modify_group, 0, use_service);
  if (gr_data == NULL || gr_data->service == S_NONE)
    {				/* Group does not exist.  */
      if (use_service)
        fprintf (stderr, _("%s: Group `%s' not found in service `%s'.\n"),
                 program, utf8_to_locale (modify_group), use_service);
      else
        fprintf (stderr, _("%s: Unknown group `%s'.\n"), program,
                 utf8_to_locale (modify_group));

      sec_log (program, MSG_UNKNOWN_GROUP, modify_group, getuid ());

      return E_NOTFOUND;
    }

  /* After this, we can start modifying the existing account.  */
  if (know_gid != NULL && !non_unique)
    {
      if (getgrgid (new_gid) != NULL ||
	  (have_extrapath && files_getgrgid (new_gid) != NULL))
	{
	  fprintf (stderr, _("%s: GID %u is not unique.\n"),
		   program, new_gid);
	  sec_log (program, MSG_GID_NOT_UNIQUE, new_gid, getuid ());
	  return E_GID_IN_USE;
	}
    }

  /* If group should be renamed, check that the new name is valid
     and does not already exist.  */
  if (new_name)
    {
      if (check_name (new_name) != 0)
	{
	  fprintf (stderr, _("%s: Invalid group name `%s'.\n"),
		   program, utf8_to_locale (new_name));
	  sec_log (program, MSG_GROUP_NAME_INVALID, new_name, getuid())
	  return E_BAD_ARG;
	}
      else
	{
	  if (getgrnam (new_name) != NULL ||
	      (have_extrapath && files_getgrnam (new_name) != NULL))
	    {
	      fprintf (stderr, _("%s: Group `%s' already exists.\n"),
		       program, utf8_to_locale (new_name));
	      sec_log (program, MSG_GROUP_ALREADY_EXISTS, new_name, getuid ());
	      return E_NAME_IN_USE;
	    }
	}
    }

  /* Lock passwd file, so that a concurrent useradd process will not
     add the user a second time or a second user with the same uid.  */
  if ((use_service == NULL || strcmp (use_service, "files") == 0) &&
      lock_database () != 0)
    {
      fputs (_("Cannot lock password file: already locked.\n"), stderr);
      sec_log (program, MSG_PASSWD_FILE_ALREADY_LOCKED);
      return E_PWDBUSY;
    }
  else
    {
      gr_data->todo = DO_MODIFY;
      if (new_name)
	gr_data->new_name = strdup (new_name);
      if (new_password)
	gr_data->newpassword = strdup (new_password);
      if (know_gid)
	{
	  gr_data->have_new_gid = 1;
	  gr_data->new_gid = new_gid;
	}

      if (remove_user)
	gr_data->new_gr_mem = remove_gr_mem (remove_user, gr_data->gr.gr_mem);

      if (add_user)
	gr_data->new_gr_mem = add_gr_mem (add_user, gr_data->gr.gr_mem);

#ifdef USE_LDAP
      if (gr_data->service == S_LDAP)
	{
	  if (binddn == NULL)
	    {
	      binddn = get_caller_dn ();
	      if (binddn == NULL)
		{
		  fprintf (stderr,
			   _
			   ("%s: Cannot modify group in LDAP database without DN.\n"),
			   program);
		}
	      else
		gr_data->binddn = strdup (binddn);
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
			   _("%s: Group not modified in LDAP database.\n"),
			   program);
		  return E_FAILURE;
		}
	    }
	}
#endif

      if (write_group_data (gr_data, 1) != 0)
	{
	  sec_log (program, MSG_ERROR_MODIFYING_GROUP,
		   gr_data->gr.gr_name,  gr_data->gr.gr_gid, getuid())
	    return E_FAILURE;
        }
      else
        {
	  if (remove_user)
	    sec_log (program, MSG_USER_REMOVED_FROM_GROUP,
		     remove_user, gr_data->gr.gr_name, gr_data->gr.gr_gid, getuid());
	  if (add_user)
	    sec_log (program, MSG_USER_ADDED_TO_GROUP, add_user, gr_data->gr.gr_name,
		     gr_data->gr.gr_gid, getuid());
	  if (new_name)
	    sec_log (program, MSG_GROUP_NAME_CHANGED, gr_data->new_name,
		     gr_data->gr.gr_name, gr_data->gr.gr_gid, getuid());
	  if (new_password)
	    sec_log (program, MSG_GROUP_PASSWORD_CHANGED, gr_data->gr.gr_name,
		     gr_data->gr.gr_gid, getuid());
	  if (know_gid)
	    sec_log (program, MSG_GROUP_ID_CHANGED, gr_data->gr.gr_name, gr_data->new_gid,
		     gr_data->gr.gr_gid, getuid());
	}

#ifdef HAVE_NSCD_FLUSH_CACHE
      /* flush NSCD cache, else later calls could get obsolete data.  */
      nscd_flush_cache ("group");
#endif
    }

  if (use_service == NULL || strcmp (use_service, "files") == 0)
    ulckpwdf ();

  return retval;
}
