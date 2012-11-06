/* Copyright (C) 2004, 2005, 2006, 2007, 2009 Thorsten Kukuk
   Author: Thorsten Kukuk <kukuk@suse.de>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pwd.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>
#ifdef HAVE_LIBNSCD_H
#include <libnscd.h>
#endif

#include "i18n.h"
#include "public.h"
#include "logindefs.h"
#include "read-files.h"
#include "error_codes.h"

static void
print_usage (FILE *stream, const char *program)
{
  fprintf (stream, _("Usage: %s\n"), program);
}

static void
print_help (const char *program)
{
  print_usage (stdout, program);
  fprintf (stdout, _("%s - convert to shadow account\n\n"),
	   program);

  fputs (_("  -P path        Search passwd and shadow file in \"path\"\n"),
         stdout);
  fputs (_("      --help     Give this help list\n"), stdout);
  fputs (_("  -u, --usage    Give a short usage message\n"), stdout);
  fputs (_("  -v, --version  Print program version\n"), stdout);
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

static struct spwd *
files_getspent (void)
{
  enum nss_status status;
  static int buflen = 256;
  static char *buffer = NULL;
  static struct spwd resultbuf;

  if (buffer == NULL)
    buffer = malloc (buflen);

  while ((status = files_getspent_r (&resultbuf, buffer, buflen, &errno))
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

int
main (int argc, char *argv[])
{
  struct passwd *pw;
  struct spwd *sp;
  char *program;
  char *cp;
  char *tmpshadow = NULL;
  char *tmppasswd = NULL;


#ifdef ENABLE_NLS
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  /* determine name of binary, which specifies edit mode.  */
  program = ((cp = strrchr (*argv, '/')) ? cp + 1 : *argv);

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] = {
	{"path",    required_argument, NULL, 'P'},
        {"version", no_argument, NULL, 'v' },
        {"usage",   no_argument, NULL, 'u' },
        {"help",    no_argument, NULL, '\255' },
        {NULL,      0,           NULL, '\0'}
      };

      c = getopt_long (argc, argv, "vuP:",
                       long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
	{
        case 'P':
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
	  return E_USAGE;
	}
    }

  argc -= optind;
  argv += optind;

  if (argc > 0)
    {
      fprintf (stderr, _("%s: Too many arguments.\n"), program);
      print_error (program);
      return E_USAGE;
    }
  else
    {
      /* Check, if /etc/shadow file exist. If not, create one.  */
      char *path;
      struct stat st;

      if (asprintf (&path, "%s/shadow", files_etc_dir) < 0)
        {
          fputs ("running out of memory!\n", stderr);
	  free (path);
          return E_FAILURE;
        }

      if (lstat (path, &st) < 0)
	{
	  /* ENOENT means, the file does not exist and we have
	     to create it. Else report an error and abort.  */
	  if (errno == ENOENT)
	    {
	      int fd = creat (path, S_IRUSR|S_IWUSR);
	      struct group *shadow_grp = getgrnam ("shadow");

	      if (fd < 0)
		{
		  fprintf (stderr, _("Can't create `%s': %m\n"), path);
		  free (path);
		  return E_FAILURE;
		}

	      if (chown (path, 0, shadow_grp ? shadow_grp->gr_gid : 0) < 0)
		{
		  fprintf (stderr,
			   _("Cannot change owner/group for `%s': %s\n"),
			   path, strerror (errno));
		  unlink (path);
		  free (path);
		  return E_FAILURE;
		}
	      if (chmod (path, S_IRUSR|S_IWUSR|S_IRGRP) < 0)
		{
		  fprintf (stderr,
			   _("Cannot change permissions for `%s': %s\n"),
			   path, strerror (errno));
		  unlink (path);
		  free (path);
		  return E_FAILURE;
		}
	    }
	  else
	    {
	      fprintf (stderr, _("Can't stat `%s': %m\n"), path);
	      free (path);
	      return E_FAILURE;
	    }
	}
      else
	{
	  /* else file exist, create a backup copy.  */
	  if (asprintf (&tmpshadow, "%s/shadow.pwconv", files_etc_dir) < 0)
	    {
	      fputs ("running out of memory!\n", stderr);
	      free (tmpshadow);
	      free (path);
	      return E_FAILURE;
	    }
	  /* remove old stale files */
	  unlink (tmpshadow);
	  if (link (path, tmpshadow) < 0)
	    {
	      fprintf (stderr, _("Cannot create backup file `%s': %m\n"),
		       tmpshadow);
	      free (tmpshadow);
	      free (path);
	      return E_FAILURE;
	    }
	}
      free (path);

      /* Now create a copy of the original passwd file.  */
      if (asprintf (&path, "%s/passwd", files_etc_dir) < 0)
	{
	  fputs ("running out of memory!\n", stderr);
	  unlink (tmpshadow);
	  return E_FAILURE;
	}
      if (asprintf (&tmppasswd, "%s/passwd.pwconv", files_etc_dir) < 0)
	{
	  fputs ("running out of memory!\n", stderr);
	  unlink (tmpshadow);
	  return E_FAILURE;
	}
      if (link (path, tmppasswd) < 0)
	{
	  fprintf (stderr, _("Cannot create backup file `%s': %m\n"),
		   tmppasswd);
	  unlink (tmpshadow);
	  if (tmpshadow)
	    free (tmpshadow);
	  free (tmppasswd);
	  return E_FAILURE;
	}
      free (path);
    }


  /* Remove accounts from /etc/shadow, which have no entry in
     /etc/passwd.  */
  while ((sp = files_getspent ()) != NULL)
    {
      user_t *pw_data;

      if (sp->sp_namp[0] == '-' || sp->sp_namp[0] == '+')
	{
	  if (sp->sp_namp[1] == '@' || sp->sp_namp[1] == '\0')
	    continue; /* we cannot check netgroups */
	  else
	    pw_data = do_getpwnam (&sp->sp_namp[1], NULL);
	}
      else
	pw_data = do_getpwnam (sp->sp_namp, NULL);

      if (pw_data == NULL || pw_data->service == S_NONE)
	{
	  user_t *sp_data = calloc (1, sizeof (user_t));

	  if (sp_data == NULL)
	    {
	      fputs ("running out of memory!\n", stderr);
	      unlink (tmpshadow);
	      unlink (tmppasswd);
	      return E_FAILURE;
	    }
	  fprintf (stdout,
		   _("Orphaned entry '%s' removed from shadow database.\n"),
		   sp->sp_namp);
	  sp_data->service = S_LOCAL;
	  sp_data->todo = DO_DELETE_SHADOW;
	  sp_data->use_shadow = 1;
	  sp_data->pw.pw_name = sp->sp_namp;
	  if (write_user_data (sp_data, 0) != 0)
	    {
	      fprintf (stderr,
		       _("Error while deleting `%s' shadow account.\n"),
		       sp_data->pw.pw_name);
	      free (sp_data);
	      unlink (tmpshadow);
	      unlink (tmppasswd);
	      return E_FAILURE;
	    }
	  free (sp_data);
	}
      free_user_t (pw_data);
    }

  /* For all accounts in /etc/passwd: If the passwd entry contains
     a password and a shadow entry exist, update the shadow entry.
     If no shadow entry exist, create one.  */

  while ((pw = files_getpwent ()) != NULL)
    {
      user_t *pw_data = do_getpwnam (pw->pw_name, "files");

      if (pw_data == NULL || pw_data->service == S_NONE)
        {
	  /* Ignore NIS entries */
	  if (pw->pw_name[0] == '-' || pw->pw_name[0] == '+')
	    continue;

	  fprintf (stderr,
		   _("%s: Error trying to get data for `%s'\n"),
		   program, pw->pw_name);
	  unlink (tmpshadow);
	  unlink (tmppasswd);
	  return E_FAILURE;
	}

      /* This user does not have a shadow entry. Create one.  */
      if (!pw_data->use_shadow)
	{
	  int rc;

	  /* Backup original password and replace it with a "x"
	     in local files. Report error*/
	  pw_data->todo = DO_MODIFY;
	  pw_data->sp.sp_pwdp = pw_data->pw.pw_passwd;
	  pw_data->newpassword = strdup ("x");
	  rc = write_user_data (pw_data, 0);

	  if (rc != 0)
	    {
	      fprintf (stderr,
		       _("Error while converting `%s' to shadow account.\n"),
		       pw_data->pw.pw_name);
	      free_user_t (pw_data);
	      unlink (tmpshadow);
	      unlink (tmppasswd);
	      return E_FAILURE;
	    }

	  pw_data->use_shadow = 1;
	  pw_data->todo = DO_CREATE_SHADOW;
	  free (pw_data->newpassword);
	  pw_data->newpassword = strdup (pw_data->pw.pw_passwd);
	  pw_data->sp.sp_namp = pw_data->pw.pw_name;
	  pw_data->sp.sp_lstchg = time ((time_t *) 0) / (24L * 3600L);
	  pw_data->sp.sp_min = getlogindefs_num ("PASS_MIN_DAYS", -1);
	  pw_data->sp.sp_max = getlogindefs_num ("PASS_MAX_DAYS", -1);
	  pw_data->sp.sp_warn = getlogindefs_num ("PASS_WARN_AGE", -1);
	  pw_data->sp.sp_inact = -1;
	  pw_data->sp.sp_expire = -1;

	  if (write_user_data (pw_data, 0) != 0)
	    {
	      fprintf (stderr,
		       _("Error while converting `%s' to shadow account.\n"),
		       pw_data->pw.pw_name);
	      free_user_t (pw_data);
	      unlink (tmpshadow);
	      unlink (tmppasswd);
	      return E_FAILURE;
	    }
#ifdef HAVE_NSCD_FLUSH_CACHE
	  else
	    nscd_flush_cache ("passwd");
#endif
	}
      else if (strcmp (pw_data->pw.pw_passwd, "x") != 0)
	{
	  /* The user has a shadow account and an entry in
	     /etc/passwd.  */

	  /* Backup original password and replace it with a "x"
	     in local passwd file. Report error*/
	  int rc;
	  char *oldpassword = pw_data->pw.pw_passwd;

	  pw_data->todo = DO_MODIFY;
	  pw_data->newpassword = strdup ("x");
	  pw_data->use_shadow = 0;
	  rc = write_user_data (pw_data, 0);
	  pw_data->use_shadow = 1;

	  if (rc != 0)
	    {
	      fprintf (stderr,
		       _("Error while converting `%s' to shadow account.\n"),
		       pw_data->pw.pw_name);
	      free_user_t (pw_data);
	      unlink (tmpshadow);
	      unlink (tmppasswd);
	      return E_FAILURE;
	    }

	  pw_data->spn = pw_data->sp;
	  pw_data->spn.sp_lstchg = time ((time_t *) 0) / (24L * 3600L);
	  pw_data->sp_changed = 1;
	  free (pw_data->newpassword);
	  pw_data->newpassword = strdup (oldpassword);
	  if (write_user_data (pw_data, 0) != 0)
	    {
	      fprintf (stderr,
		       _("Error while converting `%s' to shadow account.\n"),
		       pw_data->pw.pw_name);
	      free_user_t (pw_data);
	      unlink (tmpshadow);
	      unlink (tmppasswd);
	      return E_FAILURE;
	    }
#ifdef HAVE_NSCD_FLUSH_CACHE
	  else
	    nscd_flush_cache ("passwd");
#endif
	}

      free_user_t (pw_data);
    }

  /* Rename our own copy to shadow.old. As result, /etc/shadow.old
     will have the contents of /etc/shadow when starting this program.  */
  if (tmpshadow)
    {
      char *oldshadow;

      if (asprintf (&oldshadow, "%s/shadow.old", files_etc_dir) < 0)
	{
	  fputs ("running out of memory!\n", stderr);
	  return E_FAILURE;
	}
      unlink (oldshadow);
      if (rename (tmpshadow, oldshadow) < 0)
	{
	  fprintf (stderr,
		   _("Error while renaming temporary shadow file: %m\n"));
	  unlink (tmpshadow);
	  unlink (tmppasswd);
	  return E_FAILURE;
	}
      free (oldshadow);
      free (tmpshadow);
    }

  /* Rename our own copy to passwd.old. As result, /etc/passwd.old
     will have the contents of /etc/passwd when starting this program.  */
  if (tmppasswd)
    {
      char *oldpasswd;

      if (asprintf (&oldpasswd, "%s/passwd.old", files_etc_dir) < 0)
	{
	  fputs ("running out of memory!\n", stderr);
	  unlink (tmppasswd);
	  return E_FAILURE;
	}
      unlink (oldpasswd);
      if (rename (tmppasswd, oldpasswd) < 0)
	{
	  fprintf (stderr,
		   _("Error while renaming temporary password file: %m\n"));
	  unlink (tmppasswd);
	  return E_FAILURE;
	}
      free (oldpasswd);
      free (tmppasswd);
    }

  return E_SUCCESS;
}
