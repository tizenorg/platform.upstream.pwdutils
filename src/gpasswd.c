/* Copyright (C) 2002, 2003, 2004, 2005, 2006, 2011 Thorsten Kukuk
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

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <grp.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sys/resource.h>
#if defined(HAVE_XCRYPT_H)
#include <xcrypt.h>
#elif defined(HAVE_CRYPT_H)
#include <crypt.h>
#endif
#ifdef HAVE_LIBNSCD_H
#include <libnscd.h>
#endif

#include "i18n.h"
#include "group.h"
#include "logging.h"
#include "logindefs.h"
#include "read-files.h"
#include "error_codes.h"
#include "parse_crypt_arg.h"

#define MAX_PASSWD_TRIES 3

char *
getpass_from_stdin (const char *prompt)
{
  static char password[160]; /* 127 is the longest with current crypt */
  char *ptr;

  password[0] = '\0';
  fprintf (stdout, "%s", prompt);
  fflush (stdout);
  if (fgets (password, sizeof (password), stdin) == NULL)
    {
      fprintf (stderr, "\n");
      fprintf (stderr, _("%s: error reading from stdin!\n"),
	       "gpasswd");
      return NULL;
    }
  fprintf (stdout, "\n");

  /* Remove trailing \n.  */
  ptr = strchr (password, '\n');
  if (ptr)
    *ptr = 0;

  return password;
}

static void
print_usage (FILE *stream, const char *program)
{
  fprintf (stream, _("Usage: %s [-r|-l|-u] group\n"), program);
}

static void
print_help (const char *program)
{
  print_usage (stdout, program);
  fprintf (stdout, _("%s - change group password\n\n"), program);
  fputs (_("  -r             Remove the password for this group\n"), stdout);
  fputs (_("  -l             Locks the password entry for \"group\"\n"),
	 stdout);
  fputs (_("  -u             Try to unlock the password entry for \"group\"\n"),
	 stdout);
  fputs (_("  --service srv  Use nameservice 'srv'\n"), stdout);
  fputs (_("  -D binddn      Use dn \"binddn\" to bind to the LDAP directory\n"),
	 stdout);
  fputs (_("  -P path        Search group file in \"path\"\n"),
	 stdout);
  fputs (_("  --help         Give this help list\n"), stdout);
  fputs (_("  --usage        Give a short usage message\n"), stdout);
  fputs (_("  --version      Print program version\n"), stdout);
  fputs (_("  --stdin        Receive input from stdin instead of /dev/tty\n"), stdout);
  fputs (_("Valid services for -r are: files, nis, nisplus, ldap\n"), stdout);
}

int
main (int argc, char **argv)
{
  const char *program = "gpasswd";
  char *group;
  const char *crypt_str;
  crypt_t use_crypt;
  int remove_password = 0;
  int lock_password = 0;
  int unlock_password = 0;
  char *binddn = NULL;
  int P_flag = 0;
  group_t *gr_data;
  char *use_service = NULL;
  int stdin_flag = 0;

#ifdef ENABLE_NLS
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  open_sec_log (program);

  /* Before going any further, raise the ulimit and ignore
     signals.  */
  init_environment ();

  crypt_str = getlogindefs_str ("GROUP_CRYPT", NULL);
  if (crypt_str == NULL)
    crypt_str = getlogindefs_str ("CRYPT", "des");
  use_crypt = parse_crypt_arg (crypt_str);

  /* Parse program arguments */
  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
	{
	  {"remove", required_argument, NULL, 'r'},
	  {"lock", required_argument, NULL, 'l'},
	  {"unlock", required_argument, NULL, 'u'},
	  {"binddn", required_argument, NULL, 'D'},
	  {"path", required_argument, NULL, 'P'},
	  {"stdin", no_argument, NULL, '\251'},
	  {"service", required_argument, NULL, '\252'},
	  {"version", no_argument, NULL, '\255'},
	  {"usage", no_argument, NULL, '\254'},
	  {"help", no_argument, NULL, '\253'},
	  {NULL, 0, NULL, '\0'}
	};

      c = getopt_long (argc, argv, "rluD:P:", long_options,
                       &option_index);
      if (c == EOF)
        break;
      switch (c)
	{
        case 'D':
          binddn = optarg;
          break;
        case 'r':
	  remove_password = 1;
          break;
	case 'l':
	  lock_password = 1;
	  break;
	case 'u':
	  unlock_password = 1;
	  break;
        case '\252':
          if (use_service != NULL)
            {
              print_error (program);
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
	case 'P':
	  P_flag = 1;
	  files_etc_dir = strdup (optarg);
	  break;
	case '\253':
          print_help (program);
          return 0;
        case '\255':
          print_version (program, "2006");
          return 0;
        case '\254':
          print_usage (stdout, program);
          return E_USAGE;
	case '\251':
	  stdin_flag = 1;
	  break;
        default:
          print_error (program);
          return E_BAD_ARG;
        }
    }

  argc -= optind;
  argv += optind;

  /* We have more than one groupname. */
  if (argc > 1)
    {
      fprintf (stderr, _("%s: Too many arguments.\n"), program);
      print_error (program);
      return E_USAGE;
    }

  /* We need a group name.  */
  if (argc == 0)
    {
      fprintf (stderr, _("%s: Group argument missing.\n"), program);
      print_error (program);
      return E_USAGE;
    }
  else if (remove_password + lock_password + unlock_password > 1)
    {
      print_error (program);
      return E_USAGE;
    }
  else
    {
      group = argv[0];
      gr_data = find_group_data (group, 0, use_service);
      if (gr_data == NULL || gr_data->service == S_NONE)
        {
          if (use_service)
            fprintf (stderr,
		     _("%s: Group `%s' is not known to service `%s'.\n"),
                     program, group, use_service);
          else
            fprintf (stderr, _("%s: Unknown group `%s'.\n"), program,
		     group);

	  sec_log (program, MSG_UNKNOWN_GROUP, group, getuid ());

          return E_NOPERM;
        }
    }

  /* Only root is allowed to change password for local groups. */
  if ((gr_data->service == S_LOCAL && getuid () != 0) ||
      (gr_data->service == S_LDAP && binddn == NULL) ||
      (gr_data->service != S_LOCAL && gr_data->service != S_LDAP))
    {
      sec_log (program, MSG_PERMISSION_DENIED,
	       gr_data->gr.gr_name, gr_data->gr.gr_gid, getuid ());
      fprintf (stderr, _("%s: Permission denied.\n"), program);
      free_group_t (gr_data);
      return E_NOPERM;
    }

  if (remove_password)
    {
      gr_data->newpassword = strdup ("");
    }
  else if (unlock_password)
    {
      /* If the password is only "!", don't unlock it.  */
      if (gr_data->gr.gr_passwd &&
	  gr_data->gr.gr_passwd[0] == '!' &&
	  strlen (gr_data->gr.gr_passwd) > 1)
        gr_data->newpassword = strdup (&gr_data->gr.gr_passwd[1]);
      else
        {
          fprintf (stderr, _("Cannot unlock the password for `%s'!\n"),
                   gr_data->gr.gr_name);
          free_group_t (gr_data);
          return E_FAILURE;
        }

    }
  else if (lock_password)
    {
      if (gr_data->gr.gr_passwd == NULL)
	gr_data->newpassword = strdup ("!");
      else if (gr_data->gr.gr_passwd[0] != '!')
        {
          gr_data->newpassword =
	    malloc (strlen (gr_data->gr.gr_passwd) + 2);
          if (gr_data->newpassword == NULL)
            return E_FAILURE;
          strcpy (&gr_data->newpassword[1], gr_data->gr.gr_passwd);
          gr_data->newpassword[0] = '!';
        }
      else
        {
          fprintf (stderr, _("Password for `%s' is already locked!\n"),
                   gr_data->gr.gr_name);
          free_group_t (gr_data);
          return E_FAILURE;
        }
    }
  else
    {
      char *p1;
      int try;

      sec_log (program, MSG_CHANGING_GROUP_PASSWORD, group, getuid ());
      fprintf (stdout, _("Changing the password for group %s.\n"), group);

      for (try = 0; try < MAX_PASSWD_TRIES; try++)
	{
	  const char *p2;

	  if(stdin_flag)
	    p1 = getpass_from_stdin (_("New Password: "));
	  else
	    p1 = getpass (_("New Password: "));

	  if (p1 == NULL || *p1 == '\0')
	    {
	      fputs ("\n", stderr);
	    abort_change:
	      sec_log (program, MSG_PASSWORD_CHANGE_ABORTED,
		       group, getuid ());

	      fprintf (stderr, _("Password change aborted.\n"));
	      return E_FAILURE;
	    }

	  /* We need a copy of p1. */
	  p1 = strdup (p1);
	  if (p1 == NULL)
	    {
	      fputs ("running out of memory!\n", stderr);
	      return E_FAILURE;
	    }

	  if(stdin_flag)
	    p2 = getpass_from_stdin(_("Re-enter new password: "));
	  else
	    p2 = getpass (_("Re-enter new password: "));

	  if (p2 == NULL || *p2 == '\0')
	    {
	      fputs ("\n", stderr);
	      free (p1);
	      goto abort_change;
	    }

	  if (strcmp (p1, p2) != 0)
	    {
	      fprintf (stderr, _("Sorry, passwords do not match.\n"));
	      free (p1);
	    }
	  else
	    break;
	}
      if (try == MAX_PASSWD_TRIES)
	{
	  fprintf (stderr, _("%s: Try again later.\n"), program);
	  sec_log (program, MSG_MAX_GROUP_PASSWD_TRIES, group, getuid ());
	  free (p1);
	  goto abort_change;
        }
      else
	{
	  char *salt;
          struct crypt_data output;
          memset (&output, 0, sizeof (output));


          switch (use_crypt)
            {
            case DES:
              /* If we don't support passwords longer 8 characters,
                 truncate them */
              if (strlen (p1) > 8)
                p1[8] = '\0';
              salt =  make_crypt_salt ("", 0);
              if (salt != NULL)
                gr_data->newpassword = strdup (crypt_r (p1, salt, &output));
              else
                {
		  free (p1);
                  fprintf (stderr, _("Cannot create salt for standard crypt"));
		  goto abort_change;
                }
              free (salt);
              break;
            case BLOWFISH:
#if defined(HAVE_XCRYPT_GENSALT_R)
	      /* blowfish has a limit of 72 characters */
	      if (use_crypt == BLOWFISH && strlen (p1) > 72)
		p1[72] = '\0';
              salt = make_crypt_salt ("$2a$", 0 /* XXX crypt_rounds */);
              if (salt != NULL)
                gr_data->newpassword = strdup (crypt_r (p1, salt, &output));
              else
                {
		  free (p1);
                  fprintf (stderr, _("Cannot create salt for blowfish crypt"));
		  goto abort_change;
                }
              free (salt);
              break;
#else
	      fprintf (stderr,
		       _("No support for blowfish compiled in. Using MD5\n"));
#endif
            case MD5:
              /* MD5 has a limit of 127 characters */
              if (strlen (p1) > 127)
                p1[127] = '\0';
              salt = make_crypt_salt ("$1$", 0);
              if (salt != NULL)
                gr_data->newpassword = strdup (crypt_r (p1, salt, &output));
              else
                {
		  free (p1);
                  fprintf (stderr, _("Cannot create salt for MD5 crypt"));
		  goto abort_change;
                }
              free (salt);
              break;
            default:
              abort();
            }
	  free (p1);
        }
    }

  gr_data->todo = DO_MODIFY;
  if (write_group_data (gr_data, 0) != 0)
    {
      fprintf (stderr, _("%s: Error changing password.\n"),
               program);
      sec_log (program, MSG_ERROR_CHANGE_GROUP_PASSWORD, group, getuid ());
      free_group_t (gr_data);
      return E_FAILURE;
    }

  if (strcmp(gr_data->newpassword,"") == 0)
    {
      printf (_("Password removed.\n"));
      sec_log (program, MSG_GROUP_PASSWORD_REMOVED, group,
               gr_data->gr.gr_gid, getuid ());
    }
  else
    {
      printf (_("Password changed.\n"));
      sec_log (program, MSG_GROUP_PASSWORD_CHANGED,
               group, gr_data->gr.gr_gid, getuid ());
    }

#ifdef HAVE_NSCD_FLUSH_CACHE
  nscd_flush_cache ("group");
#endif

  free_group_t (gr_data);

  return E_SUCCESS;
}
