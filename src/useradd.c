/* Copyright (C) 2003, 2004, 2005, 2008, 2010 Thorsten Kukuk
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
#include "group.h"
#include "public.h"
#include "logging.h"
#include "logindefs.h"
#include "read-files.h"
#include "error_codes.h"

static void
print_usage (FILE *stream, const char *program)
{
  fprintf (stream, _("Usage: %s ...\n"), program);
}

static void
print_help (const char *program)
{
  print_usage (stdout, program);
  fprintf (stdout, _("%s - create a new user\n\n"), program);

  fputs (_("  -c comment     Set the GECOS field for the new account\n"),
	 stdout);
  fputs (_(" --show-defaults Print default values\n"), stdout);
  fputs (_(" --save-defaults Save modified default values\n"), stdout);
  fputs (_("  -D binddn      Use dn \"binddn\" to bind to the LDAP directory\n"), stdout);
  fputs (_("  -d homedir     Home directory for the new user\n"), stdout);
  fputs (_("  -e expire      Date on which the new account will be disabled\n"),
	 stdout);
  fputs (_("  -f inactive    Days after a password expires until account is \
disabled\n"), stdout);
  fputs (_("  -G group,...   List of supplementary groups\n"), stdout);
  fputs (_("  -g gid         Name/number of the users primary group\n"),
	 stdout);
  fputs (_("  -k skeldir     Specify an alternative skel directory\n"),
	 stdout);
  fputs (_("  -m             Create home directory for the new user\n"),
	 stdout);
  fputs (_("  -o             Allow duplicate (non-unique) UID\n"), stdout);
  fputs (_("  -P path        Search passwd, shadow and group file in \"path\"\n"),
	 stdout);
  fputs (_("  -p password    Encrypted password as returned by crypt(3)\n"),
	 stdout);
  fputs (_("  -u uid         Force the new userid to be the given number\n"),
	 stdout);
  fputs (_("  -U umask       Umask value used for creating home directory\n"),
	 stdout);
  fputs (_("  -r, --system   Create a system account\n"), stdout);
  fputs (_("  -s shell       Name of the user's login shell\n"), stdout);
  fputs (_(" --service srv   Add account to nameservice 'srv'\n"), stdout);
  fputs (_("      --help     Give this help list\n"), stdout);
  fputs (_("      --usage    Give a short usage message\n"), stdout);
  fputs (_("  -v, --version  Print program version\n"), stdout);
  fputs (_("Valid services for --service are: files, ldap\n"), stdout);
}

static const char *program = "useradd";

static const char *useradd_default_file = "/etc/default/useradd";

static struct option long_options_all[] = {
  {"comment",     required_argument, NULL, 'c'},
  {"gecos",       required_argument, NULL, 'c'},
#ifdef USE_LDAP
  {"binddn",      required_argument, NULL, 'D'},
#endif
  {"home",        required_argument, NULL, 'd'},
  {"expire",      required_argument, NULL, 'e'},
  {"inactive",    required_argument, NULL, 'f'},
  {"groups",      required_argument, NULL, 'G'},
  {"gid",         required_argument, NULL, 'g'},
  {"skel",        required_argument, NULL, 'k'},
  {"create-home", no_argument, NULL, 'm'},
  {"non-unique",  no_argument, NULL, 'o'},
  {"path",        required_argument, NULL, 'P'},
  {"password",    required_argument, NULL, 'p'},
  {"preferred-uid", required_argument, NULL, '\247'},
  {"save-defaults", no_argument,     NULL, '\251'},
  {"show-defaults", no_argument,     NULL, '\252'},
  {"service",     required_argument, NULL, '\253'},
  {"system",      no_argument,       NULL, 'r'},
  {"shell",       required_argument, NULL, 's'},
  {"uid",         required_argument, NULL, 'u'},
  {"umask",       required_argument, NULL, 'U'},
  {"version",     no_argument,       NULL, 'v'},
  {"usage",       no_argument,       NULL, '\254'},
  {"help",        no_argument,       NULL, '\255'},
  {NULL, 0, NULL, '\0'}
};
static const char *short_options_all = "c:D:d:e:f:G:g:k:MmoP:p:rs:u:U:v";

static struct option long_options_D[] = {
  {"home", required_argument, NULL, 'b'},
#ifdef  USE_LDAP
  {"binddn", required_argument, NULL, '\250'},
#endif
  {"home", required_argument, NULL, 'd'},
  {"expire", required_argument, NULL, 'e'},
  {"inactive", required_argument, NULL, 'f'},
  {"groups", required_argument, NULL, 'G'},
  {"gid", required_argument, NULL, 'g'},
  {"skel", required_argument, NULL, 'k'},
  {"shell", required_argument, NULL, 's'},
  {"version", no_argument, NULL, 'v'},
  {"save-defaults", no_argument,       NULL, '\251'},
  {"show-defaults", no_argument,       NULL, '\252'},
  {"service",       required_argument, NULL, '\253'},
  {"usage",         no_argument,       NULL, '\254'},
  {"help",          no_argument,       NULL, '\255'},
  {NULL, 0, NULL, '\0'}
};
static const char *short_options_D = "b:Dd:e:f:G:g:k:s:v";

struct default_t
{
  gid_t group;
  char *home;
  long int inactive;
  long int expire;
  char *shell;
  char *skel;
  unsigned int groupscnt;
  char **groups;
  int create_mail_spool;
  int umask;
};

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
      int err = strtoid (arg, &gid);

      if (err == -1)		/* invalid number */
	{
	  fprintf (stderr,
		   _("%s: Invalid numeric argument `%s' for group ID.\n"),
		   program, arg);
	  return E_BAD_ARG;
	}
      gr_data = find_group_data (NULL, gid, use_service);

      if (gr_data == NULL || gr_data->service == S_NONE)
	{
	  if (use_service)
	    {
	      fprintf (stderr, _("%s: Group `%u' not found in service `%s'.\n"),
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
	      fprintf (stderr, _("%s: Group `%s' not found in service `%s'.\n"),
		       program, arg, use_service);
	      return E_NOTFOUND;
	    }
	  else
	    {
	      fprintf (stderr, _("%s: Unknown group `%s'.\n"), program, arg);
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

/* Load the config file (/etc/default/useradd)  */
static int
load_defaults (const char *configfile, struct default_t *data)
{
  FILE *fp;
  char *buf = NULL;
  size_t buflen = 0;
  int errors = 0;

  fp = fopen (configfile, "r");
  if (NULL == fp)
    return -1;


  data->umask = -1;

  while (!feof (fp))
    {
      char *tmp, *cp;
#if defined(HAVE_GETLINE)
      ssize_t n = getline (&buf, &buflen, fp);
#elif defined (HAVE_GETDELIM)
      ssize_t n = getdelim (&buf, &buflen, '\n', fp);
#else
      ssize_t n;

      if (buf == NULL)
	{
	  buflen = 8096;
	  buf = malloc (buflen);
	}
      buf[0] = '\0';
      fgets (buf, buflen - 1, fp);
      if (buf != NULL)
	n = strlen (buf);
      else
	n = 0;
#endif /* HAVE_GETLINE / HAVE_GETDELIM */
      cp = buf;

      if (n < 1)
	break;

      tmp = strchr (cp, '#');	/* remove comments */
      if (tmp)
	*tmp = '\0';
      while (isspace ((int) *cp))	/* remove spaces and tabs */
	++cp;
      if (*cp == '\0')		/* ignore empty lines */
	continue;

      if (cp[strlen (cp) - 1] == '\n')
	cp[strlen (cp) - 1] = '\0';

      if (strncasecmp (cp, "GROUP=", 6) == 0)
	{
	  struct group *grp;
	  gid_t grpid;

	  if (cp[6] != '\0' && strtoid (&cp[6], &grpid) == 0)
	    /* GID in numeric form */
	    data->group = grpid;
	  else if ((grp = getgrnam (&cp[6])) != NULL)
	    data->group = grp->gr_gid;
	  else
	    {
	      ++errors;
	      fprintf (stderr, _("%s: Unknown group `%s' in %s.\n"),
		       program, cp, configfile);
	    }

	  continue;
	}
      else if (strncasecmp (cp, "HOME=", 5) == 0)
	{
	  char *home;

	  home = &cp[5];

	  if (strcspn (home, ":\n") != strlen (home) || *home != '/')
	    {
	      ++errors;
	      fprintf (stderr, _("%s: Invalid home directory `%s' in %s.\n"),
		       program, home, configfile);
	    }
	  else
	    data->home = strdup (home);

	  continue;
	}
      else if (strncasecmp (cp, "INACTIVE=", 9) == 0)
	{
	  long int inactive;
	  char *ep;

	  inactive = strtol (&cp[9], &ep, 10);
	  if (*ep != '\0' ||
	      ((inactive == LONG_MAX || inactive == LONG_MIN)
	       && errno == ERANGE))	/* invalid number */
	    {
	      ++errors;
	      fprintf (stderr, _("%s: Invalid numeric argument `%s' for `INACTIVE' in %s.\n"),
		       program, &cp[9], configfile);
	    }
	  else
	    data->inactive = inactive;
	  continue;
	}
      else if (strncasecmp (cp, "EXPIRE=", 7) == 0)
	{
	  if (cp[7] == '\0' || strcmp (&cp[7], "1969-12-31") == 0)
	    data->expire = -1;
	  else
	    {
	      long int expire;
	      char *ep;

	      expire = str2date (&cp[7]);
	      if (expire == -1)
		{
		  if (((expire = strtol (&cp[7], &ep, 10)) == 0 && *ep) ||
		      expire < -1)
		    {
		      fprintf (stderr,
			       _("%s: Expiredate `%s' is no date and no integer value >= -1 in %s.\n"),
			       program, &cp[7], configfile);
		      ++errors;
		    }
		}
	      else
		data->expire = expire;
	    }
	  continue;
	}
      else if (strncasecmp (cp, "SHELL=", 6) == 0)
	{
	  if (strcspn (&cp[6], ",=\":*\n") != strlen (&cp[6]) ||
	      *&cp[6] != '/')
	    {
	      ++errors;
	      fprintf (stderr, _("%s: Invalid shell `%s' in %s.\n"),
		       program, &cp[6], configfile);
	    }
	  else
	    data->shell = strdup (&cp[6]);

	  continue;
	}
      else if (strncasecmp (cp, "SKEL=", 5) == 0)
	{
	  if (access (&cp[5], F_OK) != 0)
	    {
	      ++errors;
	      fprintf (stderr,
		       _("%s: Skel directory \"%s\" in %s does not exist.\n"),
		       program, &cp[5], configfile);
	    }
	  else
	    data->skel = strdup (&cp[5]);
	  continue;
	}
      else if (strncasecmp (cp, "GROUPS=", 7) == 0)
	{
	  char *arg = strdupa (&cp[7]);
	  unsigned int err = 0, i, j;

	  j = 1;
	  for (i = 0; i < strlen (arg); i++)
	    if (arg[i] == ',')
	      ++j;

	  data->groups = malloc (sizeof (char *) * j);
	  data->groupscnt = 0;

	  do
	    {
	      char *c = strchr (arg, ',');
	      if (c)
		*c++ = '\0';

	      if (arg && *arg)
		{
		  if (convert_grpopt_to_name (arg,
					      &data->groups[data->groupscnt],
					      NULL, NULL) != 0)
		    ++err;
		  else
		    {
		      data->groupscnt++;
		      if (data->groupscnt > j)
			abort ();
		    }
		}
	      arg = c;
	    }
	  while (arg);

	  if (err)
	    {
	      data->groupscnt = 0;
	      free (data->groups);
	      data->groups = NULL;
	      ++errors;
	    }
	  continue;
        }
      else if (strncasecmp (cp, "CREATE_MAIL_SPOOL=", 18) == 0)
        {
	  if (strcasecmp (&cp[18], "yes") == 0)
            data->create_mail_spool = 1;
          else if (strcasecmp (&cp[18], "no") == 0)
            data->create_mail_spool = 0;
          else
            {
              ++errors;
              fprintf (stderr, _("%s: Invalid value `%s' for option CREATE_MAIL_SPOOL in %s.\n"),
                       program, &cp[18], configfile);
            }
          continue;
        }
      else if (strncasecmp (cp, "UMASK=", 6) == 0)
	{
	  long int myumask;
	  char *ep;

	  myumask = strtol (&cp[6], &ep, 0);
	  if (*ep != '\0' ||
	      ((myumask == LONG_MAX || myumask == LONG_MIN)
	       && errno == ERANGE))	/* invalid number */
	    {
	      ++errors;
	      fprintf (stderr, _("%s: Invalid numeric argument `%s' for `UMASK' in %s.\n"),
		       program, &cp[6], configfile);
	    }
	  else
	    data->umask = myumask;
	  continue;
	}
    }
  fclose (fp);

  if (buf)
    free (buf);

  /* If we don't had an UMASK= entry, try to get the UMASK value
     from /etc/login.defs */
  if (data->umask == -1)
    data->umask = getlogindefs_num ("UMASK", 077);

  return errors;
}

static void
print_defaults (const struct default_t *data)
{
  unsigned int i;

  printf ("GROUP=%u\n", (unsigned int) data->group);
  printf ("HOME=%s\n", data->home);
  printf ("INACTIVE=%li\n", data->inactive);
  if (data->expire == -1)
    fputs ("EXPIRE=\n", stdout);
  else
    printf ("EXPIRE=%s\n", date2str (data->expire * SCALE));
  printf ("SHELL=%s\n", data->shell);
  printf ("SKEL=%s\n", data->skel);
  printf ("GROUPS=");

  for (i = 0; i < data->groupscnt; i++)
    {
      if (i != 0)
	printf (",");
      printf ("%s", data->groups[i]);
    }
  printf ("\n");

  printf ("CREATE_MAIL_SPOOL=%s\n", data->create_mail_spool?"yes":"no");
  printf ("UMASK=0%o\n", data->umask);
}

/* Write the config file (/etc/default/useradd)  */
static int
write_defaults (const char *configfile, struct default_t *data)
{
  const char *tmpsuffix = ".tmpXXXXXX";
  FILE *fp, *new_fp;
  char *buf = NULL, *cp;
  size_t buflen = 0;
  char tmpname[strlen (configfile) + strlen (tmpsuffix) + 1];
  struct stat oldmode;
  int new_fd, ret;
  int group_written = 0, home_written = 0, inactive_written = 0;
  int expire_written = 0, shell_written = 0, groups_written = 0;
  int skel_written = 0, create_mail_spool_written = 0, umask_written = 0;

  fp = fopen (configfile, "r");
  if (NULL == fp)
    return -1;

  cp = stpcpy (tmpname, configfile);
  strcpy (cp, tmpsuffix);

  if (fstat (fileno (fp), &oldmode) < 0)
    {
      fprintf (stderr, _("Can't stat `%s': %m\n"), configfile);
      fclose (fp);
      return -1;
    }

  /* Open a temp file */
  new_fd = mkstemp (tmpname);
  if (new_fd == -1)
    {
      fprintf (stderr, _("Can't create `%s': %m\n"), tmpname);
      fclose (fp);
      return -1;
    }
  if (fchmod (new_fd, oldmode.st_mode) < 0)
    {
      fprintf (stderr,
	       _("Cannot change permissions for `%s': %s\n"),
	       tmpname, strerror (errno));
      fclose (fp);
      close (new_fd);
      unlink (tmpname);
      return -1;
    }
  if (fchown (new_fd, oldmode.st_uid, oldmode.st_gid) < 0)
    {
      fprintf (stderr,
	       _("Cannot change owner/group for `%s': %s\n"),
	       tmpname, strerror (errno));
      fclose (fp);
      close (new_fd);
      unlink (tmpname);
      return -1;
    }
  if (copy_xattr (configfile, tmpname) != 0)
    {
      fclose (fp);
      close (new_fd);
      unlink (tmpname);
      return -1;
    }

  new_fp = fdopen (new_fd, "w+");
  if (new_fp == NULL)
    {
      fprintf (stderr, _("Can't open `%s': %m\n"), configfile);
      fclose (fp);
      close (new_fd);
      unlink (tmpname);
      return -1;
    }

  while (!feof (fp))
    {
      char *tmp;
#if defined(HAVE_GETLINE)
      ssize_t n = getline (&buf, &buflen, fp);
#elif defined (HAVE_GETDELIM)
      ssize_t n = getdelim (&buf, &buflen, '\n', fp);
#else
      ssize_t n;

      if (buf == NULL)
	{
	  buflen = 8096;
	  buf = malloc (buflen);
	}
      buf[0] = '\0';
      fgets (buf, buflen - 1, fp);
      if (buf != NULL)
	n = strlen (buf);
      else
	n = 0;
#endif /* HAVE_GETLINE / HAVE_GETDELIM */

      if (n < 1)
	break;

      cp = strdupa (buf);

      tmp = strchr (cp, '#');	/* remove comments */
      if (tmp)
	*tmp = '\0';
      while (isspace ((int) *cp))	/* remove spaces and tabs */
	++cp;
      if (*cp == '\0')		/* ignore empty lines */
	{
	  fputs (buf, new_fp);
	  continue;
	}
      if (cp[strlen (cp) - 1] == '\n')
	cp[strlen (cp) - 1] = '\0';

      if (strncasecmp (cp, "GROUP=", 6) == 0)
	{
	  fprintf (new_fp, "GROUP=%u\n", data->group);
	  group_written = 1;
	  continue;
	}
      else if (strncasecmp (cp, "HOME=", 5) == 0)
	{
	  fprintf (new_fp, "HOME=%s\n", data->home);
	  home_written = 1;
	  continue;
	}
      else if (strncasecmp (cp, "INACTIVE=", 9) == 0)
	{
	  fprintf (new_fp, "INACTIVE=%li\n", data->inactive);
	  inactive_written = 1;
	  continue;
	}
      else if (strncasecmp (cp, "EXPIRE=", 7) == 0)
	{
	  if (data->expire < 0)
	    fputs ("EXPIRE=\n", new_fp);
	  else
	    fprintf (new_fp, "EXPIRE=%s\n", date2str (data->expire * SCALE));
	  expire_written = 1;
	  continue;
	}
      else if (strncasecmp (cp, "SHELL=", 6) == 0)
	{
	  fprintf (new_fp, "SHELL=%s\n", data->shell);
	  shell_written = 1;
	  continue;
	}
      else if (strncasecmp (cp, "SKEL=", 5) == 0)
	{
	  fprintf (new_fp, "SKEL=%s\n", data->skel);
	  skel_written = 1;
	  continue;
	}
      else if (strncasecmp (cp, "GROUPS=", 7) == 0)
	{
	  unsigned int i;

	  fputs ("GROUPS=", new_fp);

	  for (i = 0; i < data->groupscnt; i++)
	    {
	      if (i != 0)
		fputs (",", new_fp);
	      fputs (data->groups[i], new_fp);
	    }
	  fputs ("\n", new_fp);
	  groups_written = 1;
	  continue;
	}
      else if (strncasecmp (cp, "CREATE_MAIL_SPOOL=", 18) == 0)
        {
          fprintf (new_fp, "CREATE_MAIL_SPOOL=%s\n",
		   data->create_mail_spool?"yes":"no");
          create_mail_spool_written = 1;
          continue;
        }
      else if (strncasecmp (cp, "UMASK=", 6) == 0)
	{
	  fprintf (new_fp, "UMASK=0%o\n", data->umask);
	  umask_written = 1;
	  continue;
	}

      fputs (buf, new_fp);
    }

  /* Now write all entries, for which we didn't had alredy
     an entry in the default useradd file.  */
  if (!group_written)
    fprintf (new_fp, "GROUP=%u\n", data->group);
  if (!home_written)
    fprintf (new_fp, "HOME=%s\n", data->home);
  if (!inactive_written)
    fprintf (new_fp, "INACTIVE=%li\n", data->inactive);
  if (!expire_written)
    {
      if (data->expire < 0)
	fputs ("EXPIRE=\n", new_fp);
      else
	fprintf (new_fp, "EXPIRE=%s\n", date2str (data->expire * SCALE));
    }
  if (!shell_written)
    fprintf (new_fp, "SHELL=%s\n", data->shell);
  if (!skel_written)
    fprintf (new_fp, "SKEL=%s\n", data->skel);
  if (!groups_written)
    {
      unsigned int i;

      fputs ("GROUPS=", new_fp);

      for (i = 0; i < data->groupscnt; i++)
	{
	  if (i != 0)
	    fputs (",", new_fp);
	  fputs (data->groups[i], new_fp);
	}
      fputs ("\n", new_fp);
    }
  if (!create_mail_spool_written)
    fprintf (new_fp, "CREATE_MAIL_SPOOL=%s\n",
	     data->create_mail_spool?"yes":"no");
  if (!umask_written)
    fprintf (new_fp, "UMASK=0%o\n", data->umask);

  /* Close files.  */
  fclose (fp);
  fclose (new_fp);

  /* Rename temporary file back to config file name.  */
  ret = rename (tmpname, configfile);
  unlink (tmpname);

  if (buf)
    free (buf);

  /* return return value of rename, if rename succeds, everything
     is ok, else we have an error.  */
  return ret;
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

/* find_free_uid - find the first, free available UID.  */
static uid_t
find_free_uid (int is_system_account, int have_extrapath)
{
  const struct passwd *pwd;
  uid_t userid, uid_min, uid_max;

  if (is_system_account)
    {
      /* Some special handling for LSB. LSB defines
         the UID range as:
         1 - 99: fix assigned system accounts
         100 - 499: dynamic assigned system accounts
         If we use -r, try to get a uid from the dynamic
         assigned range.  */
      uid_min = getlogindefs_unum ("SYSTEM_UID_MIN", 100);
      uid_max = getlogindefs_unum ("SYSTEM_UID_MAX", 499);
    }
  else
    {
      uid_min = getlogindefs_unum ("UID_MIN", 500);
      uid_max = getlogindefs_unum ("UID_MAX", 60000);
    }

  userid = uid_min;

  /* Search the entire password file, looking for the
     largest unused value. If uid_max does already exists,
     skip this.  */
  if (getpwuid (uid_max) == NULL)
    {
      setpwent ();
      while ((pwd = getpwent ()))
	{
	  if (pwd->pw_uid >= userid)
	    {
	      if (pwd->pw_uid > uid_max)
		continue;
	      userid = pwd->pw_uid + 1;
	    }
	}
      if (have_extrapath && userid != uid_max + 1)
	{
	  /* If the -P flag is given, not only search in the
	     "official" database, but also in the extra one. */
	  while ((pwd = files_getpwent ()))
	    {
	      if (pwd->pw_uid >= userid)
		{
		  if (pwd->pw_uid > uid_max)
		    continue;
		  userid = pwd->pw_uid + 1;
		}
	    }
	}
    }
  else
    userid = uid_max + 1;	/* uid_max exists, so this will be
				   the result of the above loop.  */

  /* If the UID we found is equal to UID_MAX+1, we will step
     through the whole UID_MIN - UID_MAX range and search for
     the first free UID.  */
  if (userid == uid_max + 1)
    {
      for (userid = uid_min; userid < uid_max; userid++)
	if (getpwuid (userid) == NULL)
	  {
	    if (have_extrapath)
	      {
		/* The UID is not used  in the normal database, now
		   look in the extra one, too.  */
		if (files_getpwuid (userid) == NULL)
		  break;
	      }
	    else
	      break;
	  }

      if (userid == uid_max)
	{
	  sec_log (program, MSG_NO_FREE_UID, uid_min, uid_max);
	  fprintf (stderr, _("%s: Can't get unique uid in range %u - %u.\n"),
		   program, uid_min, uid_max);
	  exit (E_FAILURE);
	}
    }
  return userid;
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

/* Create the users mail spool file if it does not exist. The
   permissions we be 600, if the mail directory is worldwide writeable,
   else 660 onwed by the user and group 'mail'. */
static int
create_mail_file (const char *user, uid_t uid, gid_t user_gid)
{
  int mode = 0600;
  gid_t gid = user_gid;
  int fd;
  char *fname;
  struct stat st;
  char *cp;

  if ((fname = malloc (strlen (user) +
		       strlen (_PATH_MAILDIR) + 2)) == NULL)
    {
      fputs ("running out of memory!\n", stderr);
      return E_MAIL_SPOOL;
    }
  cp = stpcpy (fname, _PATH_MAILDIR);
  *cp++ = '/';
  strcpy (cp, user);

  if (access (fname, R_OK) == 0)
    return 0;

  if (stat (_PATH_MAILDIR, &st) == -1)
    {
      fprintf (stderr, _("%s: Can't stat `%s': %m\n"),
	       program, _PATH_MAILDIR);
      free (fname);
      return E_MAIL_SPOOL;
    }

  /* if directory is not worldwide writeable, the new file needs
     write permissions for group 'mail'.  */
  if ((st.st_mode & S_IWOTH) != S_IWOTH)
    {
      int buflen = 256;
      char *buffer = alloca (buflen);
      struct group resultbuf;
      struct group *gr;

      while (getgrnam_r ("mail", &resultbuf, buffer, buflen, &gr) != 0
	     && errno == ERANGE)
	{
	  errno = 0;
	  buflen += 256;
	  buffer = alloca (buflen);
	}

      /* Only writeable for group 'mail', if this group exists.  */
      if (gr)
	{
	  gid = gr->gr_gid;
	  mode = 0660;
	}
      else
	fprintf (stderr,
		 _("%s: No group named \"mail\" exists, creating mail spool with mode 0600.\n"),
		 program);
    }

  fd = open (fname, O_CREAT|O_EXCL|O_WRONLY|O_TRUNC, 0);
  if (fd == -1)
    {
      fprintf (stderr,
	       _("%s: Can't create mail spool for user %s.\n"),
	       program, user);
      free (fname);
      return E_MAIL_SPOOL;
    }
  else
    {
      if (fchown (fd, uid, gid) < 0)
	{
	  fprintf (stderr,
		   _("Cannot change owner/group for `%s': %s\n"),
		   fname, strerror (errno));
	  unlink (fname);
	  free (fname);
	  close (fd);
	  return E_MAIL_SPOOL;
	}
      if (fchmod (fd, mode) < 0)
	{
	  fprintf (stderr,
		   _("Cannot change permissions for `%s': %s\n"),
		   fname, strerror (errno));
	  unlink (fname);
	  free (fname);
	  close (fd);
	  return E_MAIL_SPOOL;
	}
      close (fd);
    }

  free (fname);

  return 0;
}


/* Create the users home directory if it does not exist. The
   permissions will be calculated from UMASK in /etc/default/useradd.  */
static int
create_home_directory (const char *home, uid_t uid, gid_t gid,
		       const char *skeldir, int home_umask)
{
  int retval = 0;

  if (home == NULL || *home == '\0')
    return E_HOMEDIR;

  if (access (home, F_OK) != 0)
    {
      char path[strlen (home) + 2];
      char *bhome, *cp;

      path[0] = '\0';
      bhome = strdup (home);
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
      if (chown (home, uid, gid) < 0)
	{
	  fprintf (stderr,
		   _("Cannot change owner/group for `%s': %s\n"),
		   home, strerror (errno));
	  retval = E_HOMEDIR;
	}
      if (chmod (home, 0777 & ~home_umask) < 0)
	{
	  fprintf (stderr, _("Cannot change permissions for `%s': %s\n"),
		   home, strerror (errno));
	  retval = E_HOMEDIR;
	}

      if (skeldir != NULL && *skeldir != '\0' && access (skeldir, F_OK) == 0)
	{
	  if (copy_dir_rec (skeldir, home, 0, uid, gid) != 0)
	    {
	      fprintf (stderr, _("%s: Copying of skel directory failed.\n"),
		       program);
	      retval = E_HOMEDIR;
	    }
	}
    }
  else if (skeldir != NULL && *skeldir != '\0')
    {
      /* Home directory already exits, don't copy skel directory again.  */
      fprintf (stderr,
	       _("%s: Warning: home directory already exists, not modifying it.\n"),
	       program);
    }

  return retval;
}

int
main (int argc, char **argv)
{
  struct default_t dflt =
    { 100, "/home", -1, -1, "/bin/bash", "/etc/skel", 0, NULL, 0, 077};
  struct option *long_options = long_options_all;
  const char *short_options = short_options_all;
  char *use_service = NULL;
#ifdef USE_LDAP
  char *binddn = NULL;
#endif
  char *skeldir = NULL;
  char *new_account;
  char *new_group = NULL;
  char *new_comment = "";
  char *new_home = NULL;
  char *new_shell = NULL;
  char *new_password = NULL;
  char *new_groups_arg = NULL;
  char **new_groups = NULL;
  unsigned int new_groupscnt = 0;
  uid_t new_uid = 0;
  int prefer_uid = 0;
  int know_uid = 0;
  int system_account = 0;
  int non_unique = 0;
  int have_extrapath = 0;
  int create_homedir = 0;
  int modify_defaults = 0;
  int broken_default_useradd = 0;

#ifdef ENABLE_NLS
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);
#endif

  open_sec_log (program);

  /* Before going any further, raise the ulimit and ignore
     signals.  */

  init_environment ();
  broken_default_useradd = load_defaults (useradd_default_file, &dflt);

  /* If the first argument is "-D" and next one also starts with "-",
     go into edit mode.  */
  if ((argc == 2 && (strncmp (argv[1], "--show", 6) == 0 ||
		     strcmp (argv[1], "-D") == 0)) ||
      (argc > 2 && (strncmp (argv[1], "--save", 6) == 0 ||
		    strcmp (argv[1], "-D") == 0) && argv[2][0] == '-'))
    {
      if (broken_default_useradd)
	{
	  fprintf (stderr, _("%s: Reading of `%s' was not successful.\n"),
		   program, useradd_default_file);
	  return E_LOGIN_DEFS;
	}

      if (argc == 2)
	{
	  print_defaults (&dflt);
	  return E_SUCCESS;
	}
      short_options = short_options_D;
      long_options = long_options_D;
      modify_defaults = 1;
    }

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
	case 'c':
	  if (strcspn (optarg, ":\n") != strlen (optarg))
	    {
	      fprintf (stderr, _("%s: Invalid comment `%s'.\n"),
		       program, optarg);
	      return E_BAD_ARG;
	    }
	  new_comment = optarg;
	  break;
	case '\250':
        case 'D':
#ifdef USE_LDAP
	  if (!modify_defaults)
	    binddn = optarg;
#endif
          break;
	case 'b':		/* for compatibility with shadow useradd.  */
	case 'd':
	  if (check_home (optarg) == -1)
	    {
	      fprintf (stderr, _("%s: Invalid home directory `%s'.\n"),
		       program, optarg);
	      return E_BAD_ARG;
	    }
	  new_home = optarg;
	  break;
	case 'e':
	  if (strcmp (optarg, "1969-12-31") == 0)
	    dflt.expire = -1;
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
	      dflt.expire = expire;
	    }
	  break;
	case 'f':
	  {
	    long int inactive;
	    char *cp;

	    inactive = strtol (optarg, &cp, 10);
	    if (*cp != '\0')	/* invalid number */
	      {
		fprintf (stderr, _("%s: Invalid numeric argument `%s' for `-f'.\n"),
			 program, optarg);
		return E_BAD_ARG;
	      }
	    dflt.inactive = inactive;
	  }
	  break;
	case 'G':
	  /* Only save the arguments for later checking. We can find a
	     -P <path> option later.  */
	  new_groups_arg = optarg;
	  break;
	case 'g':
	  new_group = optarg;
	  break;
	case 'k':
	  if (access (optarg, F_OK) != 0)
	    {
	      fprintf (stderr,
		       _("%s: Skel directory `%s' does not exist.\n"),
		       program, optarg);
	      return E_BAD_ARG;
	    }
	  skeldir = strdup (optarg);
	  break;
	case 'M':
	  /* This is the default: don't create users home dir.
	     Ignored for RedHat/PLD useradd compatibility. */
	  break;
	case 'm':
	  create_homedir = 1;
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
	  if (strtoid (optarg, &new_uid) == -1)	/* invalid number */
	    {
	      fprintf (stderr, _("%s: Invalid numeric argument `%s' for User ID.\n"),
		       program, optarg);
	      return E_BAD_ARG;
	    }
	  know_uid = 1;
	  break;
	case 'U':
	  {
	    long int myumask;
	    char *cp;

	    myumask = strtol (optarg, &cp, 0);
	    if (*cp != '\0')	/* invalid number */
	      {
		fprintf (stderr, _("%s: Invalid numeric argument `%s' for `-U'.\n"),
			 program, optarg);
		return E_BAD_ARG;
	      }
	    dflt.umask = myumask;
	  }
	  break;
	case '\247':
	  if (strtoid (optarg, &new_uid) == -1)	/* invalid number */
	    {
	      fprintf (stderr, _("%s: Invalid numeric argument `%s' for User ID.\n"),
		       program, optarg);
	      return E_BAD_ARG;
	    }
	  prefer_uid = 1;
	  break;
	case '\251':
	case '\252':
	  if (!modify_defaults)
	    {
	      print_error (program);
	      return E_USAGE;
	    }
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

  if(know_uid && prefer_uid)
    {
      fprintf (stderr, _("%s: You cannot use --uid and --preferred-uid at the same time.\n"),
	       program);
      return E_BAD_ARG;
    }

  if(!know_uid && prefer_uid)
    {
      know_uid = 1;
    }

  if (new_group)
    {
      int retval;
      gid_t gid;

      if ((retval = convert_grpopt_to_name (new_group, NULL,
					    &gid, use_service)) != 0)
	return retval;
      dflt.group = gid;
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
	      if (convert_grpopt_to_name (arg,
					  &new_groups[new_groupscnt],
					  NULL, use_service) != 0)
		++errors;
	      else
		{
		  new_groupscnt++;
		  if (new_groupscnt > j)
		    abort ();
		}
	    }
	  arg = cp;
	}
      while (arg);

      if (errors)
	{
	  /* XXX This is more a guess than something else.  */
	  if (files_etc_dir)
	    return E_NOTFOUND;
	  else
	    return E_BAD_ARG;
	}
      if (modify_defaults)
	{
	  dflt.groupscnt = new_groupscnt;
	  dflt.groups = new_groups;
	}
    }

  argc -= optind;
  argv += optind;


  if (new_password == NULL)
    {
      if (system_account)
	new_password = "*";
      else
	new_password = "!";
    }

  if (argc > 1)
    {
      fprintf (stderr, _("%s: Too many arguments.\n"), program);
      print_error (program);
      return E_USAGE;
    }
  else if (argc == 0 && !modify_defaults)
    {
      fprintf (stderr, _("%s: Too few arguments.\n"), program);
      print_error (program);
      return E_USAGE;
    }
  else if (skeldir && !(create_homedir || modify_defaults))
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

      if (do_authentication (program, pw->pw_name, NULL) != 0)
	{
	  sec_log (program, MSG_PERMISSION_DENIED, pw->pw_name,
                   pw->pw_uid, getuid ());
	  return E_NOPERM;
	}
    }

  if (modify_defaults)
    {
      /* -D option was given and we plan to modify
         entries in /etc/default/useradd.  */

      if (new_home)
	dflt.home = new_home;

      if (new_shell)
	dflt.shell = new_shell;

      if (skeldir)
	dflt.skel = skeldir;

      if (write_defaults (useradd_default_file, &dflt) != 0)
	{
	  sec_log (program, MSG_UPDATING_DEFAULT_CONFIG_FAILED,
		   useradd_default_file, getuid ());
	  fprintf (stderr, _("%s: Writing of `%s' was not successful.\n"),
		   program, useradd_default_file);
	  return E_LOGIN_DEFS;
	}

      sec_log (program, MSG_CONFIG_DEFAULTS_CHANGED,
	       dflt.group, new_home, dflt.shell, dflt.inactive,
	       date2str(DAY*dflt.expire), getuid ());

      return E_SUCCESS;
    }


  /* After this, we can start creating the new account.  */
  if (know_uid && !non_unique)
    {
      if (getpwuid (new_uid) != NULL ||
	  (have_extrapath && files_getpwuid (new_uid) != NULL))
	{
	  if(prefer_uid)
	    {
	      /* the specified uid is a preferred one so we can just
	       * pick another one */
	      know_uid = 0;
	    }
	  else
	    {
	      sec_log (program, MSG_UID_NOT_UNIQUE, new_uid, getuid ());
	      fprintf (stderr, _("%s: UID %u is not unique.\n"),
		  program, new_uid);
	      return E_UID_IN_USE;
	    }
	}
    }

  new_account = argv[0];
  if (check_name (new_account) != 0)
    {
      sec_log (program, MSG_USER_NAME_INVALID,
	       new_account, getuid ());
      fprintf (stderr, _("%s: Invalid account name `%s'.\n"),
	       program, new_account);
      return E_BAD_ARG;
    }

  if (system_account && new_shell == NULL)
    new_shell = "/bin/false";

  /* Lock passwd file, so that a concurrent useradd process will not
     add the user a second time or a second user with the same uid.  */
  if ((use_service == NULL || strcmp (use_service, "files") == 0) &&
      lock_database () != 0)
    {
      sec_log (program, MSG_PASSWD_FILE_ALREADY_LOCKED);
      fputs (_("Cannot lock password file: already locked.\n"), stderr);
      return E_PWDBUSY;
    }
  else if (getpwnam (new_account) != NULL ||
	   (have_extrapath && files_getpwnam (new_account) != NULL))
    {				/* User does already exists.  */
      sec_log (program, MSG_USER_ALREADY_EXISTS, new_account, getuid ());
      fprintf (stderr, _("%s: Account `%s' already exists.\n"),
	       program, new_account);
      return E_NAME_IN_USE;
    }
  else
    {
      user_t pw_data;
      char homebuf[strlen (dflt.home) + strlen (new_account) + 2];
      char shadowfile[strlen (files_etc_dir) + 8];
      char *cp;
      unsigned int i;
      int retval = E_SUCCESS;

      memset (&pw_data, 0, sizeof (pw_data));

      /* check if we have shadow support.  */
      cp = stpcpy (shadowfile, files_etc_dir);
      strcpy (cp, "/shadow");
      pw_data.use_shadow = (access (shadowfile, F_OK) == 0);
      if (use_service)
	{
	  if (strcmp (use_service, "files") == 0)
	    pw_data.service = S_LOCAL;
	  else if (strcmp (use_service, "ldap") == 0)
	    pw_data.service = S_LDAP;
	}
      else
	pw_data.service = S_LOCAL;

      pw_data.todo = DO_CREATE;

      if (new_home == NULL)
	{
	  snprintf (homebuf, sizeof (homebuf), "%s/%s", dflt.home,
		    new_account);
	  new_home = homebuf;
	}

      pw_data.pw.pw_name = new_account;
      if (pw_data.use_shadow)
	pw_data.pw.pw_passwd = "x";
      else
	pw_data.pw.pw_passwd = new_password;

      pw_data.pw.pw_uid = know_uid ? new_uid : find_free_uid (system_account,
							      have_extrapath);
      pw_data.pw.pw_gid = dflt.group;
      pw_data.pw.pw_gecos = new_comment;
      pw_data.pw.pw_dir = new_home;
      pw_data.pw.pw_shell = new_shell ? : dflt.shell;

      if (pw_data.use_shadow)
	{
	  pw_data.sp.sp_namp = new_account;
	  pw_data.sp.sp_pwdp = new_password;
	  pw_data.sp.sp_lstchg = time ((time_t *) 0) / (24L * 3600L);
	  pw_data.sp.sp_min = getlogindefs_num ("PASS_MIN_DAYS", -1);
	  pw_data.sp.sp_max = getlogindefs_num ("PASS_MAX_DAYS", -1);
	  pw_data.sp.sp_warn = getlogindefs_num ("PASS_WARN_AGE", -1);
	  pw_data.sp.sp_inact = dflt.inactive;
	  pw_data.sp.sp_expire = dflt.expire;
	  pw_data.sp.sp_flag = -1;
	}

      sec_log (program, MSG_NEW_USER_ADDED,
	       pw_data.pw.pw_name, (unsigned int) pw_data.pw.pw_uid,
	       (unsigned int) pw_data.pw.pw_gid, pw_data.pw.pw_dir,
	       pw_data.pw.pw_shell, getuid ());

      /* Clear old log entries, but only if this UID is not shared
         with another account.  */
      if (getpwuid (pw_data.pw.pw_uid) == NULL &&
	  (!have_extrapath || files_getpwuid (pw_data.pw.pw_uid) == NULL))
	{
	  int fd;

	  if ((fd = open ("/var/log/faillog", O_RDWR)) >= 0)
	    {
	      struct faillog fl;

	      memset (&fl, 0, sizeof (fl));
	      if ((lseek (fd, (off_t) sizeof (fl) * pw_data.pw.pw_uid, SEEK_SET)
		   == (off_t)-1) || (write (fd, &fl, sizeof (fl)) == -1))
		fprintf (stderr,
			 _("%s: Error: Cannot clear old faillog entry: %s\n"),
			 program, strerror (errno));
	      close (fd);
	    }

	  if ((fd = open (_PATH_LASTLOG, O_RDWR, 0)) >= 0)
	    {
	      struct lastlog ll;

	      memset (&ll, 0, sizeof (ll));
	      if ((lseek (fd, (off_t) sizeof (ll) * pw_data.pw.pw_uid, SEEK_SET)
		   == (off_t)-1) || (write (fd, &ll, sizeof (ll)) == -1))
		fprintf (stderr,
			 _("%s: Error: Cannot clear old lastlog entry: %s\n"),
			 program, strerror (errno));
	      close (fd);
	    }
	}

#ifdef USE_LDAP
      if (pw_data.service == S_LDAP)
	{
	  if (binddn == NULL)
	    {
	      binddn = get_caller_dn ();
	      if (binddn == NULL)
		{
		  fprintf (stderr, _("%s: Cannot add user to LDAP database without DN.\n"),
			   program);
		}
	      else pw_data.binddn = strdup (binddn);
	    }
	  else
	    pw_data.binddn = strdup (binddn);

	  if (pw_data.oldclearpwd == NULL)
	    {
	      cp = get_ldap_password (pw_data.binddn);

	      if (cp)
		pw_data.oldclearpwd = strdup (cp);
	      else
		{
		  fprintf (stderr,
			   _("%s: User not added to LDAP database.\n"),
			   program);
		  return E_FAILURE;
		}
	    }
	}
#endif

      if (write_user_data (&pw_data, 1) != 0)
	return E_FAILURE;

      /* If user does not specify extra secondary groups, add the
         default one. With one exception: Don't add default extra
         groups to system accounts.  */
      if (new_groups == NULL && !system_account)
	{
	  new_groupscnt = dflt.groupscnt;
	  new_groups = dflt.groups;
	}

      for (i = 0; i < new_groupscnt; i++)
	{
	  group_t *gr_data = find_group_data (new_groups[i], 0, use_service);

	  if (gr_data == NULL || gr_data->service == S_NONE)
	    {
	      if (use_service == NULL)
		fprintf (stderr,
			 _("%s: ERROR: Cannot find group `%s' anymore!\n"),
			 program, new_groups[i]);
	      else
		fprintf (stderr,
			 _("%s: Cannot find group `%s' in service `%s', ignored.\n"),
			 program, new_groups[i], use_service);
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
			       program, gr_data->gr.gr_name);
		      free_group_t (gr_data);
		      retval = E_GRP_UPDATE;
		      continue;
		    }

		   gr_data->binddn = strdup (binddn);

		  if (pw_data.oldclearpwd == NULL)
		    {
		      cp = get_ldap_password (binddn);

		      if (cp)
			pw_data.oldclearpwd = strdup (cp);
		      else
			{
			  fprintf (stderr,
				   _("%s: User not added to LDAP group `%s'.\n"),
				   program, gr_data->gr.gr_name);
			  free_group_t (gr_data);
			  retval = E_GRP_UPDATE;
			  continue;
			}
		    }

		  if (pw_data.oldclearpwd)
		    gr_data->oldclearpwd = strdup (pw_data.oldclearpwd);
		}
#endif
	      gr_data->new_gr_mem = add_gr_mem (pw_data.pw.pw_name,
						gr_data->gr.gr_mem);
	      if (write_group_data (gr_data, 1) != 0)
		{
		  fprintf (stderr,
			   _("%s: User not added to LDAP group `%s'.\n"),
			   program, gr_data->gr.gr_name);
		  retval = E_GRP_UPDATE;
		}
	      else
		{
		  sec_log (program, MSG_USER_ADDED_TO_GROUP,
			   pw_data.pw.pw_name, gr_data->gr.gr_name,
			   gr_data->gr.gr_gid, getuid ());
		}
	    }
	  free_group_t (gr_data);
	}

#ifdef HAVE_NSCD_FLUSH_CACHE
      /* flush NSCD cache, else creating of home directory could fail
         because of unknown user.  */
      nscd_flush_cache ("passwd");
      nscd_flush_cache ("group");
#endif

      if (use_service == NULL || strcmp (use_service, "files") == 0)
	ulckpwdf ();

      if (dflt.create_mail_spool)
	{
	  int ret = create_mail_file (pw_data.pw.pw_name,
				      pw_data.pw.pw_uid,
				      pw_data.pw.pw_gid);
	  if (ret != 0)
	    return ret;
	  sec_log (program, MSG_MAIL_FILE_CREATED,
		   pw_data.pw.pw_name, getuid ());
	}

      if (create_homedir)
	{
	  int ret = create_home_directory (new_home, pw_data.pw.pw_uid,
					   pw_data.pw.pw_gid,
					   skeldir ? : dflt.skel, dflt.umask);
	  if (ret != 0)
	    return ret;

	  sec_log (program, MSG_HOME_DIR_CREATED,
		   pw_data.pw.pw_name, pw_data.pw.pw_uid, new_home,
		   getuid ());
	}

      i = call_script ("USERADD_CMD", pw_data.pw.pw_name, pw_data.pw.pw_uid,
		       pw_data.pw.pw_gid, pw_data.pw.pw_dir, program);
      if (i != 0)
	{
	  fprintf (stderr, _("%s: USERADD_CMD fails with exit code %d.\n"),
		   program, i);
	  retval = E_FAILURE;
	}

      return retval;
    }

  return E_SUCCESS;
}
