/* Copyright (C) 2003, 2004, 2005, 2006, 2010 Thorsten Kukuk
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
#include "utf8conv.h"
#include "logindefs.h"
#include "read-files.h"
#include "error_codes.h"

static void
print_usage (FILE * stream, const char *program)
{
  fprintf (stream, _("Usage: %s ...\n"), program);
}

static void
print_help (const char *program)
{
  print_usage (stdout, program);
  fprintf (stdout, _("%s - modify a user account\n\n"), program);

  fputs (_("  -c comment     Set the GECOS field for the new account\n"),
	 stdout);
  fputs (_
	 ("  -D binddn      Use dn \"binddn\" to bind to the LDAP directory\n"),
 stdout);
  fputs (_("  -d homedir     Home directory for the new user\n"), stdout);
  fputs (_("  -e expire      Date on which the new account will be disabled\n"),
	 stdout);
  fputs (_("  -f inactive    Days after a password expires until account is \
disabled\n"), stdout);
  fputs (_("  -G group,...   List of supplementary groups\n"), stdout);
  fputs (_("  -g gid         Name/number of the users primary group\n"),
	 stdout);
  fputs (_("  -l login       Change login name.\n"), stdout);
  fputs (_("  -m             Move home directory to the new path\n"), stdout);
  fputs (_("  -o             Allow duplicate (non-unique) UID\n"), stdout);
  fputs (_("  -A group,...   List of groups the user should be added to\n"),
	 stdout);
  fputs (_("  -R group,...   List of groups the user should be removed from\n"),
	 stdout);
  fputs (_("  -P path        Search passwd, shadow and group file in \"path\"\n"),
	 stdout);
  fputs (_("  -p password    Encrypted password as returned by crypt(3)\n"),
	 stdout);
  fputs (_("  -s shell       Name of the user's login shell\n"), stdout);
  fputs (_("  -u uid         Change the userid to the given number\n"),
	 stdout);
  fputs (_("  --service srv  Use nameservice 'srv'\n"), stdout);
  fputs (_("  -L             Locks the password entry for \"user\"\n"),
	 stdout);
  fputs (_("  -U             Try to unlock the password entry for \"user\"\n"),
	 stdout);
  fputs (_("      --help     Give this help list\n"), stdout);
  fputs (_("      --usage    Give a short usage message\n"), stdout);
  fputs (_("  -v, --version  Print program version\n"), stdout);
  fputs (_("Valid services are: files, ldap\n"), stdout);
}

static const char *program = "usermod";

static struct option long_options[] = {
  {"comment", required_argument, NULL, 'c'},
  {"gecos", required_argument, NULL, 'c'},
#ifdef USE_LDAP
  {"binddn", required_argument, NULL, 'D'},
#endif
  {"home", required_argument, NULL, 'd'},
  {"expire", required_argument, NULL, 'e'},
  {"inactive", required_argument, NULL, 'f'},
  {"groups", required_argument, NULL, 'G'},
  {"add-to-groups", required_argument, NULL, 'A'},
  {"remove-from-groups", required_argument, NULL, 'R'},
  {"gid", required_argument, NULL, 'g'},
  {"login", required_argument, NULL, 'l'},
  {"lock", required_argument, NULL, 'L'},
  {"move-home", no_argument, NULL, 'm'},
  {"non-unique", no_argument, NULL, 'o'},
  {"path", required_argument, NULL, 'P'},
  {"password", required_argument, NULL, 'p'},
  {"shell", required_argument, NULL, 's'},
  {"uid", required_argument, NULL, 'u'},
  {"unlock", required_argument, NULL, 'U'},
  {"version", no_argument, NULL, 'v'},
  {"service", required_argument, NULL, '\253'},
  {"usage", no_argument, NULL, '\254'},
  {"help", no_argument, NULL, '\255'},
  {NULL, 0, NULL, '\0'}
};
static const char *short_options = "A:c:D:d:e:f:G:g:l:LmoP:p:R:s:u:Uv";

/* This function converts a comma seperated list of groups
   (a group can be a groupname or a group id) into a table
   of group ids. It returns 0 on success.  */
static int
convert_grpopt_to_name (const char *arg, char **grouplist, gid_t *groupid,
			const char *use_service)
{
  group_t *gr_data;

  if (isdigit (*arg))
    {
      gid_t gid;

      if (strtoid (arg, &gid) == -1)	/* invalid number */
	{
	  fprintf (stderr, _("%s: Invalid numeric argument `%s'.\n"),
		   program, arg);
	  return E_BAD_ARG;
	}
      gr_data = find_group_data (NULL, gid, use_service);

      if (gr_data == NULL || gr_data->service == S_NONE)
	{
	  if (use_service)
	    {
	      fprintf (stderr,
		       _("%s: Group `%u' not found in service `%s'.\n"),
		       program, gid, use_service);
	      return E_NOTFOUND;
	    }
	  else
	    {
	      fprintf (stderr, _("%s: Unknown group `%u'.\n"), program, gid);
	      return E_BAD_ARG;
	    }
	}
    }
  else
    {
      gr_data = find_group_data (arg, 0, use_service);
      if (gr_data == NULL || gr_data->service == S_NONE)
	{
	  if (use_service)
	    {
	      fprintf (stderr,
		       _("%s: Group `%s' not found in service `%s'.\n"),
		       program, utf8_to_locale (arg), use_service);
	      return E_NOTFOUND;
	    }
	  else
	    {
	      fprintf (stderr, _("%s: Unknown group `%s'.\n"), program,
		       utf8_to_locale (arg));
	      return E_BAD_ARG;
	    }
	}
    }


  if (grouplist)
    *grouplist = strdup (gr_data->gr.gr_name);
  if (groupid)
    *groupid = gr_data->gr.gr_gid;
  return 0;
}

static struct passwd *
files_getpwnam (const char *name)
{
  enum nss_status status;
  static int buflen = 256;
  static char *buffer = NULL;
  static struct passwd resultbuf;

  if (buffer == NULL)
    buffer = malloc (buflen);

  while ((status =
	  files_getpwnam_r (name, &resultbuf, buffer, buflen,
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

static struct passwd *
files_getpwuid (uid_t uid)
{
  enum nss_status status;
  static int buflen = 256;
  static char *buffer = NULL;
  static struct passwd resultbuf;

  if (buffer == NULL)
    buffer = malloc (buflen);

  while ((status = files_getpwuid_r (uid, &resultbuf, buffer, buflen, &errno))
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
  ++i;				/* for trailing NULL pointer */

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

static char **
rename_gr_mem (const char *name, char **gr_mem, const char *new_name)
{
  char **groups;
  unsigned int i;

  for (i = 0; gr_mem[i]; i++) ;
  ++i;                          /* for trailing NULL pointer */

  groups = malloc ((i + 1) * sizeof (char *));
  if (groups == NULL)
    return NULL;

  for (i = 0; gr_mem[i]; i++)
    {
      if (strcmp (name, gr_mem[i]) != 0)
	groups[i] = strdup (gr_mem[i]);
      else
	groups[i] = strdup (new_name);
    }

  groups[i] = NULL;

  return groups;
}

static int
rename_in_secondary_groups (user_t *pw_data, int have_extrapath)
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
                   _("%s: ERROR: Cannot find group `%s' anymore!\n"),
                   program, utf8_to_locale (item->value));
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
		  sec_log (program, MSG_ERROR_RENAME_USER_IN_GROUP,
			   pw_data->pw.pw_name, pw_data->pw.pw_uid,
			   gr_data->gr.gr_name,
			   gr_data->gr.gr_gid, getuid ());
                  fprintf (stderr,
                           _("%s: User not renamed in LDAP group `%s'.\n"),
                           program, utf8_to_locale (gr_data->gr.gr_name));
                  item = item->next;
                  free_group_t (gr_data);
                  retval = E_GRP_UPDATE;
                  continue;
                }

              gr_data->binddn = strdup (pw_data->binddn);

              if (pw_data->oldclearpwd == NULL)
                {
		  sec_log (program, MSG_ERROR_RENAME_USER_IN_GROUP,
			   pw_data->pw.pw_name,
			   pw_data->pw.pw_uid, gr_data->gr.gr_name,
			   gr_data->gr.gr_gid, getuid ());
		  fprintf (stderr,
			   _("%s: User not renamed from LDAP group `%s'.\n"),
			   program, utf8_to_locale (gr_data->gr.gr_name));
		  item = item->next;
		  free_group_t (gr_data);
		  retval = E_GRP_UPDATE;
		  continue;
		}
            }
#endif
          if (pw_data->oldclearpwd)
            gr_data->oldclearpwd = strdup (pw_data->oldclearpwd);

          gr_data->new_gr_mem = rename_gr_mem (pw_data->pw.pw_name,
                                               gr_data->gr.gr_mem,
					       pw_data->new_name);
          if (write_group_data (gr_data, 1) != 0)
            {
	      sec_log (program, MSG_ERROR_RENAME_USER_IN_GROUP,
		       pw_data->pw.pw_name,
		       pw_data->pw.pw_uid, gr_data->gr.gr_name,
		       gr_data->gr.gr_gid, getuid ());
              fprintf (stderr,
                       _("%s: User not renamed in group `%s'.\n"),
                       program, utf8_to_locale (gr_data->gr.gr_name));
              retval = E_GRP_UPDATE;
            }
	  else
	    {
	      sec_log (program, MSG_USER_RENAMED_IN_GROUP,
		       pw_data->new_name, pw_data->pw.pw_name,
		       pw_data->pw.pw_uid, gr_data->gr.gr_name,
		       gr_data->gr.gr_gid, getuid ());
	    }

          item = item->next;
        }

      free_group_t (gr_data);
    }

  return retval;
}

/* Move the users home directory to new location.  */
static int
move_home_directory (const char *oldhome, const char *newhome)
{
  struct stat st;

  if (oldhome == NULL || *oldhome == '\0' ||
      newhome == NULL || *newhome == '\0')
    return E_HOMEDIR;

  /* Does the old directory exist?  */
  if (stat (oldhome, &st) < 0)
    return 0; /* No old homedirectory, but no error, too.  */

  /* Don't try to move it if it is not a directory.
     Some admins have the bad idea to use a file as home
     directory.  */
  if (!S_ISDIR (st.st_mode))
    return E_HOMEDIR;

  if (access (newhome, F_OK) == 0)
    return E_HOMEDIR;
  else
    {
      char path[strlen (newhome) + 2];
      char *bhome, *cp;

      path[0] = '\0';
      bhome = strdup (newhome);
      ++bhome;

      /* Check for every part of the path, if the directory
         exists. If not, create it with permissions 755 and
         owner root:root.  */
      cp = strtok (bhome, "/");
      while (cp)
	{
	  strcat (path, "/");
	  strcat (path, cp);
	  if (access (path, F_OK) != 0)
	    {
	      if (mkdir (path, 0) != 0)
		{
		  fprintf (stderr,
			   _("%s: Cannot create directory `%s'.\n"),
			   program, path);
		  return E_HOMEDIR;
		}
              if (chown (path, 0, 0) < 0)
                fprintf (stderr, _("%s: Warning: chown on `%s' failed: %m\n"),
                         program, path);
              if (chmod (path, 0755) < 0)
                fprintf (stderr, _("%s: Warning: chmod on `%s' failed: %m\n"),
                         program, path);
	    }
	  cp = strtok (NULL, "/");
	}
      /* we have this created to much, remove it again.  */
      rmdir (newhome);
    }

  if (rename (oldhome, newhome) == -1)
    {
      if (errno == EXDEV)
	{
	  if (mkdir (newhome, st.st_mode & 0777))
	    {
	      fprintf (stderr, _("Can't create `%s': %m\n"),
		       newhome);
	      return E_HOMEDIR;
	    }
	  if (chown (newhome, st.st_uid, st.st_gid))
	    {
	      fprintf (stderr, _("%s: Warning: chown on `%s' failed: %m\n"),
		       program, newhome);
	      rmdir (newhome);
	      return E_HOMEDIR;
	    }
	  if (copy_dir_rec (oldhome, newhome, 1, 0, 0) == 0)
	    remove_dir_rec (oldhome); /* only remove if no error occured. */
	  else
	    {
	      fprintf (stderr, _("%s: Cannot copy directory %s to %s.\n"),
		       program, oldhome, newhome);
	      return E_HOMEDIR;
	    }
	}
      else
	{
	  fprintf (stderr, _("%s: Cannot rename directory %s to %s.\n"),
		   program, oldhome, newhome);
	  return E_HOMEDIR;
	}
    }

  return 0;
}

/* XXX Make this generic and put it into libpwdutils.  */
static int
remove_from_secondary_groups (user_t *pw_data, int have_extrapath,
			      const char *name)
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
              if (strcmp (gr->gr_mem[i], name) == 0)
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
              if (strcmp (gr->gr_mem[i], name) == 0)
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
                   _("%s: ERROR: Cannot find group `%s' anymore!\n"),
                   program, utf8_to_locale (item->value));
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
		  sec_log (program, MSG_ERROR_REMOVE_USER_FROM_GROUP,
			   pw_data->pw.pw_name, pw_data->pw.pw_uid,
			   gr_data->gr.gr_name,
			   gr_data->gr.gr_gid, getuid ());
                  fprintf (stderr,
                           _("%s: User not removed from LDAP group `%s'.\n"),
                           program, utf8_to_locale (gr_data->gr.gr_name));
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
		      sec_log (program, MSG_ERROR_REMOVE_USER_FROM_GROUP,
			       pw_data->pw.pw_name, pw_data->pw.pw_uid,
			       gr_data->gr.gr_name,
			       gr_data->gr.gr_gid, getuid ());
                      fprintf (stderr,
                               _("%s: User not removed from LDAP group `%s'.\n"),
                               program, utf8_to_locale (gr_data->gr.gr_name));
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

          gr_data->new_gr_mem = remove_gr_mem (name,
                                               gr_data->gr.gr_mem);
          if (write_group_data (gr_data, 1) != 0)
            {
	      sec_log (program, MSG_ERROR_REMOVE_USER_FROM_GROUP,
		       pw_data->pw.pw_name, pw_data->pw.pw_uid,
		       gr_data->gr.gr_name,
		       gr_data->gr.gr_gid, getuid ());
              fprintf (stderr,
                       _("%s: User not removed from group `%s'.\n"),
                       program, utf8_to_locale (gr_data->gr.gr_name));
              retval = E_GRP_UPDATE;
            }
	  else
	    {
	      sec_log (program, MSG_USER_REMOVED_FROM_GROUP,
		       pw_data->pw.pw_name, gr_data->gr.gr_name,
		       gr_data->gr.gr_gid, getuid ());
	    }

          item = item->next;
        }

      free_group_t (gr_data);
    }

  return retval;
}


int
main (int argc, char **argv)
{
  char *use_service = NULL;
  user_t *pw_data;
#ifdef USE_LDAP
  char *binddn = NULL;
#endif
  char *modify_account;
  char *new_group = NULL;
  gid_t new_gid = 0;
  char *new_comment = NULL;
  char *new_home = NULL;
  char *old_home = NULL;
  char *new_shell = NULL;
  char *new_login = NULL;
  char *new_password = NULL;
  char *new_groups_arg = NULL;
  char *add_groups_arg = NULL;
  char *remove_groups_arg = NULL;
  char **new_groups = NULL;
  unsigned int new_groupscnt = 0;
  char **del_groups = NULL;
  unsigned int del_groupscnt = 0;
  uid_t new_uid = 0;
  char *know_uid = NULL;
  int non_unique = 0;
  int have_extrapath = 0;
  int move_homedir = 0;
  long int new_expire = -1;
  int know_expire = 0;
  long int new_inactive = -1;
  int know_inactive = 0;
  int retval = E_SUCCESS;
  int lock_password = 0;
  int unlock_password = 0;
  int a_flg = 0;

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
	case 'a':
	  a_flg = 1;
	  break;
	case 'c':
	  if (strcspn (optarg, ":\n") != strlen (optarg))
	    {
	      fprintf (stderr, _("%s: Invalid comment `%s'.\n"),
		       program, optarg);
	      return E_BAD_ARG;
	    }
	  new_comment = locale_to_utf8 (optarg);
	  break;
	case 'D':
#ifdef USE_LDAP
	  binddn = optarg;
#endif
	  break;
	case 'd':
	  if (check_home (optarg) == -1)
	    {
	      fprintf (stderr, _("%s: Invalid home directory `%s'.\n"),
		       program, optarg);
	      return E_BAD_ARG;
	    }
	  new_home = locale_to_utf8 (optarg);
	  break;
	case 'e':
	  if (strcmp (optarg, "1969-12-31") == 0)
	    {
	      new_expire = -1;
	      know_expire = 1;
	    }
	  else
	    {
	      long int expire;
	      char *cp;

	      expire = str2date (optarg);
	      if (expire == -1)
		{
		  if (((expire = strtol (optarg, &cp, 10)) == 0 && *cp) ||
		      expire < -1)
		    {
		      fprintf (stderr,
			       _("%s: Expiredate `%s' is no date and no integer value >= -1.\n"),
			       program, optarg);
		      return E_BAD_ARG;
		    }
		}
	      new_expire = expire;
	      know_expire = 1;
	    }
	  break;
	case 'f':
	  {
	    long int inactive;
	    char *cp;

	    inactive = strtol (optarg, &cp, 10);
	    if (*cp != '\0')	/* invalid number */
	      {
		fprintf (stderr, _("%s: Invalid numeric argument `%s'.\n"),
			 program, optarg);
		return E_BAD_ARG;
	      }
	    new_inactive = inactive;
	    know_inactive = 1;
	  }
	  break;
	case 'G':
	  if (add_groups_arg || remove_groups_arg)
	    {
	      print_usage (stderr, program);
	      return E_BAD_ARG;
	    }
	  /* Only save the arguments for later checking. We can find a
	     -P <path> option later.  */
	  new_groups_arg = locale_to_utf8 (optarg);
	  break;
	case 'A':
	  if (new_groups_arg)
	    {
	      print_usage (stderr, program);
	      return E_BAD_ARG;
	    }
	  /* Only save the arguments for later checking. We can find a
	     -P <path> option later.  */
	  add_groups_arg = locale_to_utf8 (optarg);
	  break;
	case 'R':
	  if (new_groups_arg)
	    {
	      print_usage (stderr, program);
	      return E_BAD_ARG;
	    }
	  /* Only save the arguments for later checking. We can find a
	     -P <path> option later.  */
	  remove_groups_arg = locale_to_utf8 (optarg);
	  break;
	case 'g':
	  new_group = locale_to_utf8 (optarg);
	  break;
	case 'l':
	  new_login = locale_to_utf8 (optarg);
	  break;
	case 'L':
	  if (unlock_password)
	    {
	      print_usage (stderr, program);
	      return E_BAD_ARG;
	    }
	  lock_password = 1;
	  break;
	case 'm':
	  move_homedir = 1;
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
		       _("%s: Invalid characters in password `%s'.\n"),
		       program, optarg);
	      return E_BAD_ARG;
	    }
	  new_password = optarg;
	  break;
	case 's':
	  if (strcspn (optarg, ",=\":*\n") != strlen (optarg) ||
	      *optarg != '/')
	    {
	      fprintf (stderr, _("%s: Invalid shell `%s'.\n"),
		       program, optarg);
	      return E_BAD_ARG;
	    }
	  new_shell = optarg;
	  break;
	case 'u':
	  {
	    char *cp;

	    new_uid = strtoul (optarg, &cp, 10);
	    if (*cp != '\0')	/* invalid number */
	      {
		fprintf (stderr, _("%s: Invalid numeric argument `%s'.\n"),
			 program, optarg);
		return E_BAD_ARG;
	      }
	    know_uid = optarg;
	  }
	  break;
	case 'U':
	  if (lock_password)
	    {
	      print_usage (stderr, program);
	      return E_BAD_ARG;
	    }
	  unlock_password = 1;
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
	  print_version (program, "2006");
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

  if (a_flg) /* -a -G is identical to -A */
    {
      if (add_groups_arg)
	{
	  print_usage (stderr, program);
	  return E_BAD_ARG;
	}
      add_groups_arg = new_groups_arg;
      new_groups_arg = NULL;
    }

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
  else if (move_homedir && !new_home)
    {
      print_usage (stderr, program);
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
                   pw->pw_uid, getuid ());
	  return E_NOPERM;
	}
    }

  modify_account = locale_to_utf8 (argv[0]);
  /* Check, if the account we should modify exist.  */
  pw_data = do_getpwnam (modify_account, use_service);
  if (pw_data == NULL || pw_data->service == S_NONE)
    {				/* User does not exist.  */
      sec_log (program, MSG_UNKNOWN_USER, modify_account, getuid ());
      fprintf (stderr, _("%s: Account `%s' does not exist.\n"),
	       program, utf8_to_locale (modify_account));
      return E_NOTFOUND;
    }

  old_home = strdupa (pw_data->pw.pw_dir);

  /* -L, -U and -p are exclusive. */
  if ((lock_password + unlock_password > 1) ||
      ((lock_password + unlock_password) && new_password))
    {
      print_error (program);
      return E_USAGE;
    }


  if (lock_password)
    {
      const char *pwdp;

      if (pw_data->use_shadow)
	pwdp = pw_data->sp.sp_pwdp;
      else
	pwdp = pw_data->pw.pw_passwd;

      if (pwdp == NULL)
	pw_data->newpassword = strdup ("!");
      else if (pwdp[0] != '!')
	{
	  pw_data->newpassword = malloc (strlen (pwdp) + 2);
	  if (pw_data->newpassword == NULL)
	    return E_FAILURE;
	  strcpy (&pw_data->newpassword[1], pwdp);
	  pw_data->newpassword[0] = '!';
	}
      else
	{
	  fprintf (stderr, _("Password for `%s' is already locked!\n"),
		   pw_data->pw.pw_name);
	  free_user_t (pw_data);
	  return E_FAILURE;
	}
    }

  if (unlock_password)
    {
      const char *pwdp;

      if (pw_data->use_shadow)
	pwdp = pw_data->sp.sp_pwdp;
      else
	pwdp = pw_data->pw.pw_passwd;

      /* If the password is only "!", don't unlock it.  */
      if (pwdp && pwdp[0] == '!' && strlen (pwdp) > 1)
	pw_data->newpassword = strdup (&pwdp[1]);
      else
	{
	  fprintf (stderr, _("Cannot unlock the password for `%s'!\n"),
		   pw_data->pw.pw_name);
	  free_user_t (pw_data);
	  return E_FAILURE;
	}
    }

  if (new_group)
    {
      if ((retval = convert_grpopt_to_name (new_group, NULL,
					    &new_gid, use_service)) != 0)
	return retval;
    }

  if (new_groups_arg)
    {
      char *arg = new_groups_arg;
      unsigned int errors = 0, i, j;

      j = 1;
      for (i = 0; i < strlen (arg); i++)
	if (arg[i] == ',')
	  ++j;

      new_groups = malloc (sizeof (char *) * j);
      new_groupscnt = 0;

      do
	{
	  char *cp = strchr (arg, ',');
	  if (cp)
	    *cp++ = '\0';

	  if (arg && *arg)
	    {
	      gid_t gid;

	      if (convert_grpopt_to_name (arg,
					  &new_groups[new_groupscnt],
					  &gid, use_service) != 0)
		++errors;
	      else
		{
		  /* If this group is the primary group, print error
		     message and ignore it. Don't exit with an error,
		     this would break too many existing scripts.  */
		  if ((new_group &&
		       strcmp (new_group, new_groups[new_groupscnt]) == 0) ||
		      (gid == pw_data->pw.pw_gid))
		    {
		      fprintf (stderr, _("%s: `%s' is primary group name.\n"),
			       program,
			       utf8_to_locale (new_groups[new_groupscnt]));
		      /* return E_BAD_ARG; */
		    }
		  else
		    {
		      new_groupscnt++;
		      if (new_groupscnt > j)
			abort ();
		    }
		}
	    }
	  arg = cp;
	}
      while (arg);

      if (errors)
	{
	  /* This is more a guess than something else.  */
	  if (files_etc_dir)
	    return E_NOTFOUND;
	  else
	    return E_BAD_ARG;
	}
    }

  /* Create list of groups, to which we should add this account. -A option.  */
  /* XXX merge with new_groups_arg above.  */
  if (add_groups_arg)
    {
      char *arg = add_groups_arg;
      unsigned int errors = 0, i, j;

      j = 1;
      for (i = 0; i < strlen (arg); i++)
	if (arg[i] == ',')
	  ++j;

      new_groups = malloc (sizeof (char *) * j);
      new_groupscnt = 0;

      do
	{
	  char *cp = strchr (arg, ',');
	  if (cp)
	    *cp++ = '\0';

	  if (arg && *arg)
	    {
	      gid_t gid;

	      if (convert_grpopt_to_name (arg,
					  &new_groups[new_groupscnt],
					  &gid, use_service) != 0)
		++errors;
	      else
		{
		  /* If this group is the primary group, print error
		     message and ignore it. Don't exit with an error,
		     this would break too many existing scripts.  */
		  if ((new_group &&
		       strcmp (new_group, new_groups[new_groupscnt]) == 0) ||
		      (gid == pw_data->pw.pw_gid))
		    {
		      fprintf (stderr, _("%s: `%s' is primary group name.\n"),
			       program,
			       utf8_to_locale (new_groups[new_groupscnt]));
		      /* return E_BAD_ARG; */
		    }
		  else
		    {
		      new_groupscnt++;
		      if (new_groupscnt > j)
			abort ();
		    }
		}
	    }
	  arg = cp;
	}
      while (arg);

      if (errors)
	{
	  /* This is more a guess than something else.  */
	  if (files_etc_dir)
	    return E_NOTFOUND;
	  else
	    return E_BAD_ARG;
	}
    }

  /* Create list of groups, to which we should add this account. -R option.  */
  /* XXX merge with new_groups_arg above.  */
  if (remove_groups_arg)
    {
      char *arg = remove_groups_arg;
      unsigned int errors = 0, i, j;

      j = 1;
      for (i = 0; i < strlen (arg); i++)
	if (arg[i] == ',')
	  ++j;

      del_groups = malloc (sizeof (char *) * j);
      del_groupscnt = 0;

      do
	{
	  char *cp = strchr (arg, ',');
	  if (cp)
	    *cp++ = '\0';

	  if (arg && *arg)
	    {
	      gid_t gid;

	      if (convert_grpopt_to_name (arg,
					  &del_groups[del_groupscnt],
					  &gid, use_service) != 0)
		++errors;
	      else
		{
		  del_groupscnt++;
		  if (del_groupscnt > j)
		    abort ();
		}
	    }
	  arg = cp;
	}
      while (arg);

      if (errors)
	{
	  /* This is more a guess than something else.  */
	  if (files_etc_dir)
	    return E_NOTFOUND;
	  else
	    return E_BAD_ARG;
	}
    }

  /* Check if user is logged in.  */
  if ((new_login || know_uid || new_home) &&
      is_logged_in (modify_account))
    {
      sec_log (program, MSG_ACCOUNT_IN_USE, modify_account,
	       pw_data->pw.pw_uid, getuid ());
      fprintf (stderr, _("%s: Account `%s' is currently in use.\n"),
	       program, utf8_to_locale (modify_account));
      return E_USER_BUSY;
    }

  /* After this, we can start modifying the existing account.  */
  if (know_uid != NULL && !non_unique)
    {
      if (getpwuid (new_uid) != NULL ||
	  (have_extrapath && files_getpwuid (new_uid) != NULL))
	{
	  sec_log (program, MSG_UID_NOT_UNIQUE, new_uid, getuid ());
	  fprintf (stderr, _("%s: UID %u is not unique.\n"),
		   program, new_uid);
	  return E_UID_IN_USE;
	}
    }

  /* If account should be renamed, check that the new name is valid
     and does not already exist.  */
  if (new_login)
    {
      if (check_name (new_login) != 0)
	{
	  sec_log (program, MSG_USER_NAME_INVALID,
		   new_login, getuid ());
	  fprintf (stderr, _("%s: Invalid account name `%s'.\n"),
		   program, utf8_to_locale (new_login));
	  return E_BAD_ARG;
	}
      else
	{
	  if (getpwnam (new_login) != NULL ||
	      (have_extrapath && files_getpwnam (new_login) != NULL))
	    {
	      sec_log (program, MSG_USER_ALREADY_EXISTS,
		       new_login, getuid ());
	      fprintf (stderr, _("%s: Account `%s' already exists.\n"),
		       program, utf8_to_locale (new_login));
	      return E_NAME_IN_USE;
	    }
	}
    }

  /* Lock passwd file, so that a concurrent usermod process will not
     add the user a second time or a second user with the same uid.  */
  if ((use_service == NULL || strcmp (use_service, "files") == 0) &&
      lock_database () != 0)
    {
      sec_log (program, MSG_PASSWD_FILE_ALREADY_LOCKED);
      fputs (_("Cannot lock password file: already locked.\n"), stderr);
      return E_PWDBUSY;
    }
  else if (new_login || new_password || know_uid || new_group ||
	   new_comment || new_home || new_shell || know_inactive ||
	   know_expire || lock_password || unlock_password)
    {
      /* Only change passwd/shadow file if there are really changes.  */

      pw_data->todo = DO_MODIFY;
      if (new_login)
	pw_data->new_name = strdup (new_login);
      if (know_uid)
	{
	  pw_data->have_new_uid = 1;
	  pw_data->new_uid = new_uid;
	}
      if (new_group)
	{
	  pw_data->have_new_gid = 1;
	  pw_data->new_gid = new_gid;
	}
      if (new_comment)
	pw_data->new_gecos = strdup (new_comment);
      if (new_home)
	pw_data->new_home = strdup (new_home);
      if (new_shell)
	pw_data->new_shell = strdup (new_shell);

      if (know_inactive || know_expire)
	{
	  if (pw_data->use_shadow)
	    {
	      pw_data->spn = pw_data->sp;
	      pw_data->sp_changed = 1;

	      if (know_inactive)
		pw_data->spn.sp_inact = new_inactive;

	      if (know_expire)
		pw_data->spn.sp_expire = new_expire;
	    }
	  else
	    {
	      fprintf (stderr,
		       _("%s: Shadow passwords required for -e and -f.\n"),
		       program);
	      return E_NO_SHADOW;
	    }
	}

      if (new_password)
	{
	  pw_data->newpassword = strdup (new_password);
	  if (pw_data->use_shadow)
	    {
	      pw_data->spn.sp_lstchg = time ((time_t *) 0) / SCALE;
	      pw_data->sp_changed = 1;
	    }
	}

#ifdef USE_LDAP
      if (pw_data->service == S_LDAP)
	{
	  if (binddn == NULL)
	    {
	      binddn = get_caller_dn ();
	      if (binddn == NULL)
		{
		  fprintf (stderr,
			   _("%s: Cannot modify user in LDAP database without DN.\n"),
			   program);
		}
	      else
		pw_data->binddn = strdup (binddn);
	    }
	  else
	    pw_data->binddn = strdup (binddn);

	  if (pw_data->oldclearpwd == NULL)
	    {
	      char *cp = get_ldap_password (pw_data->binddn);

	      if (cp)
		pw_data->oldclearpwd = strdup (cp);
	      else
		{
		  fprintf (stderr,
			   _("%s: User not modified in LDAP database.\n"),
			   program);
		  return E_FAILURE;
		}
	    }
	}
#endif

      if (write_user_data (pw_data, 1) != 0)
	{
	  sec_log (program, MSG_ERROR_MODIFYING_USER,
		   pw_data->pw.pw_name, pw_data->pw.pw_uid,
		   getuid())
	    return E_FAILURE;
	}
      else
	{
	  if (new_login)
	    sec_log (program, MSG_USER_NAME_CHANGED,
		     pw_data->new_name, pw_data->pw.pw_name,
		     pw_data->pw.pw_uid, getuid ());
	  if (new_password)
	    sec_log (program, MSG_PASSWORD_CHANGED,
		     pw_data->pw.pw_name, pw_data->pw.pw_uid, getuid ());
	  if (pw_data->new_uid)
	    sec_log (program, MSG_USER_ID_CHANGED,
		     pw_data->pw.pw_name, pw_data->new_uid,
		     pw_data->pw.pw_uid, getuid ());
	  if (new_comment)
	    sec_log (program, MSG_GECOS_CHANGED,
		     pw_data->pw.pw_name, pw_data->pw.pw_uid,
		     pw_data->new_gecos, pw_data->pw.pw_gecos, getuid ());
	  if (new_group)
	    sec_log (program, MSG_PRIMARY_GROUP_CHANGED,
		     pw_data->pw.pw_name, pw_data->pw.pw_uid, pw_data->new_gid,
		     pw_data->pw.pw_gid , getuid ());
	  if (new_home)
	    sec_log (program, MSG_HOME_DIR_CHANGED,
		     pw_data->pw.pw_name, pw_data->pw.pw_uid,
		     pw_data->new_home, pw_data->pw.pw_dir, getuid ());
	  if (new_shell)
	    sec_log (program, MSG_SHELL_CHANGED,
		     pw_data->pw.pw_name, pw_data->pw.pw_uid,
		     pw_data->new_shell, pw_data->pw.pw_shell, getuid ());
	  if (know_inactive)
	    sec_log (program, MSG_INACTIVE_DAYS_CHANGED,
		     pw_data->pw.pw_name, pw_data->pw.pw_uid,
		     pw_data->spn.sp_inact, pw_data->sp.sp_inact, getuid ());
	  if (know_expire)
	    sec_log (program, MSG_EXPIRE_DATE_CHANGED,
		     pw_data->pw.pw_name, pw_data->pw.pw_uid,
		     date2str(DAY*pw_data->spn.sp_expire),
		     date2str(DAY*pw_data->sp.sp_expire), getuid ());
        }

#ifdef HAVE_NSCD_FLUSH_CACHE
      /* flush NSCD cache, else later calls could get obsolete data.  */
      nscd_flush_cache ("passwd");
#endif
    }

  /* Change the login name in group entries, too.
     But only, if we don't need to remove them all later.  */
  if (new_login && (new_groups_arg == NULL || new_groupscnt == 0))
    {
      if (rename_in_secondary_groups (pw_data, have_extrapath) != 0)
	retval = E_FAILURE;

      /* Make sure, written group changes will be active now.  */
#ifdef HAVE_NSCD_FLUSH_CACHE
      nscd_flush_cache ("group");
#endif
    }

  /* Now we need to change the group file (-G/-A option).  */
  if (new_groups_arg || add_groups_arg)
    {
      unsigned int i;
      int ret;

      if (new_groups_arg)
	{
	  /* Remove user from all groups. */
	  if (new_login)
	    ret = remove_from_secondary_groups (pw_data, have_extrapath,
						new_login);
	  else
	    ret = remove_from_secondary_groups (pw_data, have_extrapath,
						pw_data->pw.pw_name);
	  if (ret != 0)
	    retval = ret;
	}

      for (i = 0; i < new_groupscnt; i++)
	{
	  group_t *gr_data = find_group_data (new_groups[i], 0, use_service);


	  if (gr_data == NULL || gr_data->service == S_NONE)
	    {
	      if (use_service == NULL)
		fprintf (stderr,
			 _("%s: ERROR: Cannot find group `%s' anymore!\n"),
			 program, utf8_to_locale (new_groups[i]));
	      else
		fprintf (stderr,
			 _("%s: Cannot find group `%s' in service `%s', ignored.\n"),
			 program, utf8_to_locale (new_groups[i]), use_service);
	      retval = E_NOTFOUND;
	    }
	  else
	    {
	      gr_data->todo = DO_MODIFY;
#ifdef USE_LDAP
	      if (gr_data->service == S_LDAP)
		{
		  if (binddn == NULL)
		    {
		      binddn = get_caller_dn ();
		      if (binddn == NULL)
			{
			  fprintf (stderr,
				   _("%s: Cannot add user to groups stored in LDAP database without DN.\n"),
				   program);
			}
		    }

		  if (binddn == NULL)
		    {
		      fprintf (stderr,
			       _("%s: User not added to LDAP group `%s'.\n"),
			       program,
			       utf8_to_locale (gr_data->gr.gr_name));
		      free_group_t (gr_data);
		      retval = E_GRP_UPDATE;
		      continue;
		    }

		  gr_data->binddn = strdup (binddn);

		  if (pw_data->oldclearpwd == NULL)
		    {
		      char *cp = get_ldap_password (binddn);

		      if (cp)
			pw_data->oldclearpwd = strdup (cp);
		      else
			{
			  fprintf (stderr,
				   _("%s: User not added to LDAP group `%s'.\n"),
				   program,
				   utf8_to_locale (gr_data->gr.gr_name));
			  free_group_t (gr_data);
			  retval = E_GRP_UPDATE;
			  continue;
			}
		    }

		  if (pw_data->oldclearpwd)
		    gr_data->oldclearpwd = strdup (pw_data->oldclearpwd);
		}
#endif
	      gr_data->new_gr_mem = add_gr_mem (modify_account,
						gr_data->gr.gr_mem);
	      if (write_group_data (gr_data, 1) != 0)
		{
		  fprintf (stderr,
			   _("%s: User not added to LDAP group `%s'.\n"),
			   program,
			   utf8_to_locale (gr_data->gr.gr_name));
		  retval = E_GRP_UPDATE;
		}
	      else
		{
		  sec_log (program, MSG_USER_ADDED_TO_GROUP,
                           pw_data->pw.pw_name, gr_data->gr.gr_name,
                           gr_data->gr.gr_gid, getuid ());
		}
	      /* Make sure, written group changes will be active now.  */
#ifdef HAVE_NSCD_FLUSH_CACHE
	      nscd_flush_cache ("group");
#endif
	    }
	  free_group_t (gr_data);
	}
    }

  /* Now we need to change the group file (-R option).  */
  /* XXX merge with above.  */
  if (remove_groups_arg)
    {
      unsigned int i;

      for (i = 0; i < del_groupscnt; i++)
	{
	  group_t *gr_data = find_group_data (del_groups[i], 0, use_service);


	  if (gr_data == NULL || gr_data->service == S_NONE)
	    {
	      if (use_service == NULL)
		fprintf (stderr,
			 _("%s: ERROR: cannot find group `%s' anymore!\n"),
			 program, utf8_to_locale (del_groups[i]));
	      else
		fprintf (stderr,
			 _("%s: Cannot find group `%s' in service `%s', ignored.\n"),
			 program, utf8_to_locale (del_groups[i]), use_service);
	      retval = E_NOTFOUND;
	    }
	  else
	    {
	      gr_data->todo = DO_MODIFY;
#ifdef USE_LDAP
	      if (gr_data->service == S_LDAP)
		{
		  if (binddn == NULL)
		    {
		      binddn = get_caller_dn ();
		      if (binddn == NULL)
			{
			  fprintf (stderr,
				   _("%s: Cannot remove user from groups stored in LDAP database without DN.\n"),
				   program);
			}
		    }

		  if (binddn == NULL)
		    {
		      fprintf (stderr,
			       _("%s: User not removed from LDAP group `%s'.\n"),
			       program,
			       utf8_to_locale (gr_data->gr.gr_name));
		      free_group_t (gr_data);
		      retval = E_GRP_UPDATE;
		      continue;
		    }

		  gr_data->binddn = strdup (binddn);

		  if (pw_data->oldclearpwd == NULL)
		    {
		      char *cp = get_ldap_password (binddn);

		      if (cp)
			pw_data->oldclearpwd = strdup (cp);
		      else
			{
			  fprintf (stderr,
				   _("%s: User not removed from LDAP group `%s'.\n"),
				   program,
				   utf8_to_locale (gr_data->gr.gr_name));
			  free_group_t (gr_data);
			  retval = E_GRP_UPDATE;
			  continue;
			}
		    }

		  if (pw_data->oldclearpwd)
		    gr_data->oldclearpwd = strdup (pw_data->oldclearpwd);
		}
#endif
	      gr_data->new_gr_mem = remove_gr_mem (modify_account,
						   gr_data->gr.gr_mem);
	      if (write_group_data (gr_data, 1) != 0)
		{
		  fprintf (stderr,
			   _("%s: User not removed from LDAP group `%s'.\n"),
			   program,
			   utf8_to_locale (gr_data->gr.gr_name));
		  retval = E_GRP_UPDATE;
		}
	      else
		{
		  sec_log (program, MSG_USER_ADDED_TO_GROUP,
                           pw_data->pw.pw_name, gr_data->gr.gr_name,
                           gr_data->gr.gr_gid, getuid ());
		}
	      /* Make sure, written group changes will be active now.  */
#ifdef HAVE_NSCD_FLUSH_CACHE
	      nscd_flush_cache ("group");
#endif
	    }
	  free_group_t (gr_data);
	}
    }

  if (move_homedir)
    if (move_home_directory (old_home, new_home) != 0)
      retval = E_FAILURE;

  /* If UID has changed, change the UID of the homedirectory, too.  */
  if (know_uid)
    {
      int fd;
      int ret;
      char *home = new_home ? new_home : old_home;

      /* Only change the UID of the home directory, if it exist.
	 Else ignore it.  */
      if (access (home, F_OK) == 0)
	{
	  /* If know_uid is set, change UID on filesystem of file
	     in the home directory.  */
	  ret = chown_dir_rec (home, pw_data->pw.pw_uid, new_uid,
			       pw_data->pw.pw_gid,
			       new_group ? new_gid : pw_data->pw.pw_gid);
	  if (ret != 0)
	    retval = E_FAILURE;
	}

      /* Relocate the "lastlog/faillog" entries for the user. */
      if ((fd = open ("/var/log/faillog", O_RDWR)) >= 0)
	{
	  struct faillog fl;

	  if (lseek (fd, (off_t) sizeof (fl) * pw_data->pw.pw_uid, SEEK_SET)
	      == (off_t) -1)
	    {
	      fprintf (stderr, _("%s: Error: Cannot copy faillog entry: %s\n"),
		       program, strerror (errno));
	      retval = E_FAILURE;
	    }
	  else
	    if (read (fd, &fl, sizeof (fl)) == sizeof (fl))
	      {
		if ((lseek (fd, (off_t) sizeof (fl) * new_uid, SEEK_SET)
		     == (off_t) -1) || (write (fd, &fl, sizeof (fl)) == -1))
		  {
		    fprintf (stderr,
			     _("%s: Error: Cannot copy faillog entry: %s\n"),
			    program, strerror (errno));
		    retval = E_FAILURE;
		  }
	      }
	  close (fd);
	}

      if ((fd = open (_PATH_LASTLOG, O_RDWR, 0)) >= 0)
	{
	  struct lastlog ll;

	  if (lseek (fd, (off_t) sizeof (ll) * pw_data->pw.pw_uid, SEEK_SET)
	      == (off_t) -1)
	    {
	      fprintf (stderr, _("%s: Error: Cannot copy lastlog entry: %s\n"),
		       program, strerror (errno));
	      retval = E_FAILURE;
	    }
	  else
	    if (read (fd, &ll, sizeof ll) == sizeof ll)
	      {
		if ((lseek (fd, (off_t) sizeof (ll) * new_uid, SEEK_SET)
		     == (off_t) -1) || (write (fd, &ll, sizeof (ll)) == -1))
		  {
		    fprintf (stderr,
			     _("%s: Error: Cannot copy faillog entry: %s\n"),
			     program, strerror (errno));
		    retval = E_FAILURE;
		  }
	      }
	  close (fd);
	}
    }
  if (use_service == NULL || strcmp (use_service, "files") == 0)
    ulckpwdf ();

  return retval;
}
