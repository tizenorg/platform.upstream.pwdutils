/* Copyright (C) 2004, 2005 Thorsten Kukuk
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
  fprintf (stdout, _("%s - convert from shadow account\n\n"),
	   program);

  fputs (_("  -P path        Search passwd and shadow file in \"path\"\n"),
         stdout);
  fputs (_("      --help     Give this help list\n"), stdout);
  fputs (_("  -u, --usage    Give a short usage message\n"), stdout);
  fputs (_("  -v, --version  Print program version\n"), stdout);
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
  struct spwd *sp;
  char *program;
  char *cp;
  char *tmppasswd = NULL;
  char *shadow_path;

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
      /* Check, if /etc/shadow file exist. If not, exit.  */
      char *path;
      struct stat st;

      if (asprintf (&shadow_path, "%s/shadow", files_etc_dir) < 0)
        {
          fputs ("running out of memory!\n", stderr);
          return E_FAILURE;
        }

      if (lstat (shadow_path, &st) < 0)
	{
	  /* ENOENT means, the file does not exist and we have
	     to create it. Else report an error and abort.  */
	  if (errno == ENOENT)
	    {
	      fprintf (stderr, _("%s: No shadow file found.\n"),
		       program);
	      return E_FAILURE;
	    }
	  else
	    {
	      fprintf (stderr, _("Can't stat `%s': %m\n"), shadow_path);
	      return E_FAILURE;
	    }
	}

      /* Now create a copy of the original passwd file.  */
      if (asprintf (&path, "%s/passwd", files_etc_dir) < 0)
	{
	  fputs ("running out of memory!\n", stderr);
	  return E_FAILURE;
	}
      if (asprintf (&tmppasswd, "%s/passwd.pwunconv", files_etc_dir) < 0)
	{
	  fputs ("running out of memory!\n", stderr);
	  return E_FAILURE;
	}
      if (link (path, tmppasswd) < 0)
	{
	  fprintf (stderr, _("Cannot create backup file `%s': %m\n"),
		   tmppasswd);
	  return E_FAILURE;
	}
      free (path);
    }


  /* Step through /etc/shadow and move the password into the passwd
     file.  */
  while ((sp = files_getspent ()) != NULL)
    {
      user_t *pw_data = do_getpwnam (sp->sp_namp, NULL);
      /* Only change password in passwd file, if we have a
	 corresponding passwd entry and this is 'x'.  */
      if (pw_data != NULL && pw_data->service != S_NONE &&
	  strcmp (pw_data->pw.pw_passwd, "x") == 0)
	{
	  /* Tell backend to ignore shadow file.  */
	  pw_data->use_shadow = 0;
	  pw_data->newpassword = strdup (sp->sp_pwdp);
	  if (write_user_data (pw_data, 0) != 0)
	    {
	      fprintf (stderr,
		       _("Error while moving password for `%s'.\n"),
		       pw_data->pw.pw_name);
	      free (pw_data);
	      return E_FAILURE;
	    }
	}
      free_user_t (pw_data);
    }
#ifdef HAVE_NSCD_FLUSH_CACHE
  nscd_flush_cache ("passwd");
#endif

  /* Rename original shadow file to shadow.old.  */
  {
    char *oldshadow;
    if (asprintf (&oldshadow, "%s/shadow.old", files_etc_dir) < 0)
      {
	fputs ("running out of memory!\n", stderr);
	return E_FAILURE;
      }
    unlink (oldshadow);
    rename (shadow_path, oldshadow);
    free (oldshadow);
    free (shadow_path);
  }

  /* Rename our own copy to passwd.old. As result, /etc/passwd.old
     will have the contents of /etc/passwd when starting this program.  */
  if (tmppasswd)
    {
      char *oldpasswd;

      if (asprintf (&oldpasswd, "%s/passwd.old", files_etc_dir) < 0)
	{
	  fputs ("running out of memory!\n", stderr);
	  return E_FAILURE;
	}
      unlink (oldpasswd);
      rename (tmppasswd, oldpasswd);
      free (oldpasswd);
      free (tmppasswd);
    }

  return E_SUCCESS;
}
