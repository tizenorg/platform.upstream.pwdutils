/* Copyright (C) 2003, 2004, 2005, 2009, 2010 Thorsten Kukuk
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
#include <sys/stat.h>
#include <sys/resource.h>
#ifdef HAVE_LIBNSCD_H
#include <libnscd.h>
#endif

#ifdef USE_LDAP
#include "libldap.h"
#endif

#include "i18n.h"
#include "public.h"
#include "group.h"
#include "logging.h"
#include "logindefs.h"
#include "read-files.h"
#include "error_codes.h"

static void
print_usage (FILE *stream, const char *program)
{
  fprintf (stream, _("Usage: %s [-D binddn] [-P path] [-r [-f]] user\n"), program);
}

static void
print_help (const char *program)
{
  print_usage (stdout, program);
  fprintf (stdout, _("%s - delete a user and related files\n\n"), program);

  fputs (_("  -r             Remove home directory and mail spool\n"),
	 stdout);
  fputs (_("  -f             Force removal of files, even if not owned by user\n"),
	 stdout);
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

static const char *program = "userdel";

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

static int
is_owned_by (const char *path, uid_t uid)
{
  struct stat st;
  if (lstat (path, &st) != 0)
    return -1;
  return (st.st_uid == uid);
}

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

static int
in_use_by_other_users (const char *dir, const char *user,
		       int have_extrapath)
{
  struct passwd *pw;
  size_t dirlen = strlen (dir);
  int retval = 0;

  setpwent ();

  while ((pw = getpwent ()))
    {
      /* don't count ourself.  */
      if (strcmp (pw->pw_name, user) == 0)
	continue;
      /* Another user can have the same directory or a subdirectory
	 of our own directory as home directory.  */
      if ((dirlen < strlen (pw->pw_dir) && strncmp (dir, pw->pw_dir, dirlen) == 0
	   && pw->pw_dir[dirlen] == '/') || strcmp (dir, pw->pw_dir) == 0)
	{
	  fprintf (stderr,
		   _("%s: directory `%s' is in use by `%s'.\n"),
		   program, dir, pw->pw_name);
	  retval = 1;
	}
    }

  endpwent ();

  if (have_extrapath)
    while ((pw = files_getpwent ()))
      {
	/* don't count ourself.  */
	if (strcmp (pw->pw_name, user) == 0)
	  continue;
	/* Another user can have the same directory or a subdirectory
	   of our own directory as home directory.  */
	if (strncmp (dir, pw->pw_dir, dirlen) == 0)
	  {
	    fprintf (stderr,
		     _("%s: directory `%s' is in use by `%s'.\n"),
		     program, dir, pw->pw_name);
	    retval = 1;
	  }
      }

  return retval;
}

static int
remove_from_secondary_groups (user_t *pw_data, int have_extrapath)
{
  struct item_t {
    char *value;
    struct item_t *next;
  } *list = NULL, *item;
  struct group *gr;
  int retval = E_SUCCESS;

  if (have_extrapath)
    {
      while ((gr = files_getgrent ()))
	{
	  unsigned int i;

	  for (i = 0; gr->gr_mem[i]; i++)
	    {
	      if (strcmp (gr->gr_mem[i], pw_data->pw.pw_name) == 0)
		{
		  item = malloc (sizeof (*item));
		  item->value = strdup (gr->gr_name);
		  item->next = list;
		  list = item;
		}
	    }
	}
    }
  else
    {
      setgrent ();

      while ((gr = getgrent ()))
	{
	  unsigned int i;

	  for (i = 0; gr->gr_mem[i]; i++)
	    {
	      if (strcmp (gr->gr_mem[i], pw_data->pw.pw_name) == 0)
		{
		  item = malloc (sizeof (*item));
		  item->value = strdup (gr->gr_name);
		  item->next = list;
		  list = item;
		}
	    }
	}

      endgrent ();
    }

  item = list;
  while (item != NULL)
    {
      group_t *gr_data = find_group_data (item->value, 0, NULL);

      if (gr_data == NULL || gr_data->service == S_NONE)
	{
	  fprintf (stderr,
		   _("%s: ERROR: cannot find group `%s' anymore!\n"),
		   program, item->value);
	  if (retval == E_SUCCESS)
	    retval = E_NOTFOUND;
	}
      else
	{
	  gr_data->todo = DO_MODIFY;

#ifdef USE_LDAP
	  if (gr_data->service == S_LDAP)
	    {
	      if (pw_data->binddn == NULL)
		{
		  pw_data->binddn = get_caller_dn ();
		  if (pw_data->binddn == NULL)
		    {
		      fprintf (stderr, _("%s: Cannot remove user from groups stored in LDAP database without DN.\n"),
			       program);
		    }
		}

	      if (pw_data->binddn == NULL)
		{
		  fprintf (stderr,
			   _("%s: User not removed from LDAP group `%s'.\n"),
			   program, gr_data->gr.gr_name);
		  item = item->next;
		  free_group_t (gr_data);
		  retval = E_GRP_UPDATE;
		  continue;
		}

	      gr_data->binddn = strdup (pw_data->binddn);

	      if (pw_data->oldclearpwd == NULL)
		{
		  char *cp = get_ldap_password (pw_data->binddn);

		  if (cp)
		    pw_data->oldclearpwd = strdup (cp);
		  else
		    {
		      fprintf (stderr,
			       _("%s: User not removed from LDAP group `%s'.\n"),
			       program, gr_data->gr.gr_name);
		      item = item->next;
		      free_group_t (gr_data);
		      retval = E_GRP_UPDATE;
		      continue;
		    }
		}
	    }
#endif
	  if (pw_data->oldclearpwd)
	    gr_data->oldclearpwd = strdup (pw_data->oldclearpwd);

	  gr_data->new_gr_mem = remove_gr_mem (pw_data->pw.pw_name,
					       gr_data->gr.gr_mem);
	  if (write_group_data (gr_data, 1) != 0)
	    {
	      sec_log (program, MSG_ERROR_REMOVE_USER_FROM_GROUP,
		       pw_data->pw.pw_name, pw_data->pw.pw_uid,
		       gr_data->gr.gr_name, gr_data->gr.gr_gid, getuid ());
	      fprintf (stderr,
		       _("%s: User not removed from group `%s'.\n"),
		       program, gr_data->gr.gr_name);
	      retval = E_GRP_UPDATE;
	    }
	  else
	    {
	      sec_log (program, MSG_USER_REMOVED_FROM_GROUP,
		       pw_data->pw.pw_name, gr_data->gr.gr_name,
		       gr_data->gr.gr_gid, getuid ())
	    }
	}

      item = item->next;
      free_group_t (gr_data);
    }
  return retval;
}

/* XXX */
void
init_environment (void)
{
  struct rlimit rlim;

  /* Don't create a core file.  */
  rlim.rlim_cur = rlim.rlim_max = 0;
  setrlimit (RLIMIT_CORE, &rlim);

  /* Set all limits to unlimited to avoid to run in any
     problems later.  */
  rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
  setrlimit (RLIMIT_AS, &rlim);
  setrlimit (RLIMIT_CPU, &rlim);
  setrlimit (RLIMIT_DATA, &rlim);
  setrlimit (RLIMIT_FSIZE, &rlim);
  setrlimit (RLIMIT_NOFILE, &rlim);
  setrlimit (RLIMIT_RSS, &rlim);
  setrlimit (RLIMIT_STACK, &rlim);

  /* Ignore all signals which can make trouble later.  */
  signal (SIGALRM, SIG_IGN);
  signal (SIGXFSZ, SIG_IGN);
  signal (SIGHUP, SIG_IGN);
  /* signal (SIGINT, SIG_IGN); */
  signal (SIGPIPE, SIG_IGN);
  /* signal (SIGQUIT, SIG_IGN); */
  /* signal (SIGTERM, SIG_IGN); */
  signal (SIGTSTP, SIG_IGN);
  signal (SIGTTOU, SIG_IGN);

  umask (077);
}

int
main (int argc, char **argv)
{
  char *use_service = NULL;
#ifdef USE_LDAP
  char *binddn = NULL;
#endif
  char *remove_user;
  int have_extrapath = 0;
  int remove_flag = 0;
  int force_removal = 0;
  user_t *pw_data;
  int retval = E_SUCCESS;
  int i;

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
#ifdef USE_LDAP
	case 'D':
	  binddn = optarg;
	  break;
#endif
	case 'f':
	  force_removal = 1;
	  break;
	case 'P':
	  files_etc_dir = strdup (optarg);
	  have_extrapath = 1;
	  /* If -P option is used, set service to "files" if not already
	     set through an option. If we don't limitate to service files,
	     we can get trouble finding the right source.  */
	  if (!use_service)
	    use_service = "files";
	  break;
	case 'r':
	  remove_flag = 1;
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
	  fprintf (stderr, _("%s: Cannot determine your user name.\n"),
		   program);
	  return E_UNKNOWN_USER;
	}

      if (do_authentication ("shadow", pw->pw_name, NULL) != 0)
	{
	  sec_log (program, MSG_PERMISSION_DENIED, pw->pw_name,
                   pw->pw_uid, getuid ());
	  return E_NOPERM;
	}
    }

  remove_user = argv[0];

  pw_data = do_getpwnam (remove_user, use_service);
  if (pw_data == NULL || pw_data->service == S_NONE)
    {
      sec_log (program, MSG_UNKNOWN_USER, remove_user, getuid ());
      if (use_service)
	fprintf (stderr, _("%s: User `%s' is not known to service `%s'.\n"),
		 program, remove_user, use_service);
      else
	fprintf (stderr, _("%s: Unknown user `%s'.\n"), program,
		 remove_user);
      return E_UNKNOWN_USER;
    }

  if (is_logged_in (remove_user))
    {
      fprintf (stderr, _("%s: account `%s' is currently in use.\n"),
	       program, remove_user);
      return E_USER_BUSY;
    }

#ifdef USE_LDAP
  if (binddn)
    {
      pw_data->binddn = strdup (binddn);
      if (pw_data->service == S_LDAP)
	{
	  char *cp = get_ldap_password (binddn);
	  if (cp)
	    pw_data->oldclearpwd = strdup (cp);
	}
    }
#endif

  i = call_script ("USERDEL_PRECMD", pw_data->pw.pw_name, pw_data->pw.pw_uid,
		   pw_data->pw.pw_gid, pw_data->pw.pw_dir, program);
  if (i != 0)
    {
      fprintf (stderr, _("%s: USERDEL_PRECMD fails with exit code %d.\n"),
	       program, i);
      return E_FAILURE;
    }

  /* Lock passwd file, so that a concurrent useradd process will not
     add the user a second time or a second user with the same uid.  */
  if (pw_data->service == S_LOCAL && lock_database () != 0)
    {
      sec_log (program, MSG_PASSWD_FILE_ALREADY_LOCKED);
      fputs (_("Cannot lock password file: already locked.\n"), stderr);
      return E_PWDBUSY;
    }

  if (remove_flag)
    {
      char *cp;
      int ret;

      if (asprintf (&cp, "%s/%s", _PATH_MAILDIR, pw_data->pw.pw_name) < 1)
	return E_FAILURE;

      /* Remove the mail file only if owned by user or -f was given.  */
      ret = is_owned_by (cp, pw_data->pw.pw_uid);
      if (ret == 0 && !force_removal)
	{
	  sec_log (program, MSG_NOT_OWNED_BY_USER,
		   cp, pw_data->pw.pw_name, pw_data->pw.pw_uid, getuid ());
	  fprintf (stderr, _("%s: `%s' is not owned by `%s', not removed.\n"),
		   program, cp, pw_data->pw.pw_name);
	}
      else if (ret == 1 || (ret == 0 && force_removal))
	{
	  if (unlink (cp) == -1)
	    fprintf (stderr, _("%s: warning: can't remove `%s': %s"),
		     program, cp, strerror (errno));
	}

      /* Remove the home directory only, if owned by the user and
	 not used by any other user or -f was given.  */
      ret = is_owned_by (pw_data->pw.pw_dir, pw_data->pw.pw_uid);
      if (ret == 0 && !force_removal)
	{
	  sec_log (program, MSG_NOT_OWNED_BY_USER,
		   pw_data->pw.pw_dir, pw_data->pw.pw_name,
		   pw_data->pw.pw_uid, getuid ());
	  fprintf (stderr, _("%s: `%s' is not owned by `%s', not removed.\n"),
		   program, pw_data->pw.pw_dir, pw_data->pw.pw_name);
	}
      else if (ret == 1 || (ret == 0 && force_removal))
	{
	  if (!in_use_by_other_users (pw_data->pw.pw_dir,
				      pw_data->pw.pw_name,
				      have_extrapath) || force_removal)
	    {
	      if (remove_dir_rec (pw_data->pw.pw_dir) != 0)
		fprintf (stderr, _("%s: warning: can't remove `%s': %s"),
			 program, pw_data->pw.pw_dir, strerror (errno));
	      else
		{
		  sec_log (program, MSG_HOME_DIR_REMOVED,
			   pw_data->pw.pw_name, pw_data->pw.pw_uid,
			   pw_data->pw.pw_dir, getuid ());
		}
	    }
	  else
	    fprintf (stderr, _("%s: directory `%s' not removed.\n"),
		     program, pw_data->pw.pw_dir);
	}
    }

  retval = remove_from_secondary_groups (pw_data, have_extrapath);

  pw_data->todo = DO_DELETE;
  if (write_user_data (pw_data, 1) != 0)
    {
      sec_log (program, MSG_ERROR_REMOVING_USER,
	       pw_data->pw.pw_name, pw_data->pw.pw_uid, getuid ());
      fprintf (stderr, _("%s: error deleting user `%s'.\n"),
	       program, pw_data->pw.pw_name);
      free_user_t (pw_data);
      return E_FAILURE;
    }
  else
    sec_log (program, MSG_USER_DELETED,
	     pw_data->pw.pw_name, pw_data->pw.pw_uid, getuid ());

#ifdef HAVE_NSCD_FLUSH_CACHE
  /* flush NSCD cache to remove user really from the system.  */
  nscd_flush_cache ("passwd");
  nscd_flush_cache ("group");
#endif

  if (pw_data->service == S_LOCAL)
    ulckpwdf ();

  i = call_script ("USERDEL_POSTCMD", pw_data->pw.pw_name, pw_data->pw.pw_uid,
		   pw_data->pw.pw_gid, pw_data->pw.pw_dir, program);
  if (i != 0)
    {
      fprintf (stderr, _("%s: USERDEL_POSTCMD fails with exit code %d.\n"),
	       program, i);
      return E_FAILURE;
    }

  free_user_t (pw_data);

  return retval;
}
