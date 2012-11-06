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
#include <config.h>
#endif

#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#if defined(HAVE_XCRYPT_H)
#include <xcrypt.h>
#elif defined(HAVE_CRYPT_H)
#include <crypt.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#ifdef HAVE_LIBNSCD_H
#include <libnscd.h>
#endif

#include "i18n.h"
#include "public.h"
#include "logging.h"
#include "logindefs.h"
#include "read-files.h"
#include "error_codes.h"
#include "parse_crypt_arg.h"

#ifdef USE_LDAP
#include "libldap.h"
#endif /* USE_LDAP */

#ifndef _
#define _(String) gettext (String)
#endif

static void
print_usage (FILE *stream, const char *program)
{
  fprintf (stream, _("Usage: %s [-D binddn] [-P path] [-e] [-c des|md5|blowfish] [file]\n"),
           program);
}

static void
print_help (const char *program)
{
  print_usage (stdout, program);
  fprintf (stdout, _("%s - update password entries in batch\n\n"), program);

#ifdef USE_LDAP
  fputs (_("  -D binddn      Use dn \"binddn\" to bind to the LDAP directory\n"),
         stdout);
#endif
  fputs (_("  -P path        Search passwd and shadow file in \"path\"\n"),
         stdout);
  fputs (_("  -c, --crypt    Password should be encrypted with DES, MD5 or blowfish\n"),
	 stdout);
  fputs (_("  -e, --encrypted The passwords are in encrypted form\n"),
	 stdout);
  fputs (_("  --service srv  Use nameservice 'srv'\n"), stdout);
  fputs (_("      --help     Give this help list\n"), stdout);
  fputs (_("  -u, --usage    Give a short usage message\n"), stdout);
  fputs (_("  -v, --version  Print program version\n"), stdout);
  fputs (_("Valid services are: files, nis, nisplus, ldap\n"), stdout);
}

int
main (int argc, char *argv[])
{
  FILE *input = NULL;
  const char *program = "chpasswd";
  crypt_t use_crypt;
  int encrypted = 0;
  char *buf = NULL;
  size_t buflen = 0;
  unsigned long line = 0, errors = 0;
  char *use_service = NULL;
#ifdef USE_LDAP
  char *oldclearpwd = NULL;
  char *binddn = NULL;
#endif

#ifdef ENABLE_NLS
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  open_sec_log (program);

  use_crypt = parse_crypt_arg (getlogindefs_str ("CRYPT", "des"));

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] = {
#ifdef USE_LDAP
        {"binddn",  required_argument, NULL, 'D' },
#endif
        {"path",    required_argument, NULL, 'P' },
        {"crypt",   no_argument, NULL, 'c' },
        {"md5",     no_argument, NULL, 'm' },
        {"encrypt", no_argument, NULL, 'e' },
        {"service", required_argument, NULL, '\254' },
        {"version", no_argument, NULL, 'v' },
        {"usage",   no_argument, NULL, 'u' },
        {"help",    no_argument, NULL, '\255' },
        {NULL,      0,           NULL, '\0'}
      };

      c = getopt_long (argc, argv, "D:P:c:mevu",
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
          break;
	case 'c':
	  use_crypt = parse_crypt_arg (optarg);
	  break;
	case 'm':
	  use_crypt = MD5;
	  break;
	case 'e':
	  ++encrypted;
	  break;
        case '\254':
          if (use_service != NULL)
            {
              print_usage (stderr, program);
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

  if (argc == 0)
    input = stdin;
  else if (argc == 1)
    {
      input = fopen (argv[0], "r");
      if (input == NULL)
	{
	  fprintf (stderr, "%s: %s: %s\n", program, argv[0],
		   strerror (errno));
	  return E_BAD_ARG;
	}
    }
  else if (argc > 1)
    {
      fprintf (stderr, _("%s: Too many arguments.\n"), program);
      print_error (program);
      return E_USAGE;
    }

#ifdef USE_LDAP
  if (binddn)
    {
      /* A user tries to change data stored in a LDAP database and
	 knows the Manager dn, now we need the password from him.  */
      ldap_session_t *session = create_ldap_session (LDAP_PATH_CONF);
      char *cp;

      if (session == NULL)
	return E_FAILURE;

      cp = getpass (_("Enter LDAP Password:"));

      if (open_ldap_session (session) != 0)
	return E_FAILURE;

      if (ldap_authentication (session, NULL, binddn, cp) != 0)
	return E_NOPERM;

      close_ldap_session (session);

      oldclearpwd = strdup (cp);
    }
#endif /* USE_LDAP */

  /* Read each line, separating login from the password. The password
     entry for each user will be looked up in the appropriate place,
     defined through the search order in /etc/nsswitch.conf.  */

  while (!feof (input))
    {
      char *tmp, *cp;
      user_t *pw_data;
      time_t now;
#if defined(HAVE_GETLINE)
      ssize_t n = getline (&buf, &buflen, input);
#elif defined (HAVE_GETDELIM)
      ssize_t n = getdelim (&buf, &buflen, '\n', input);
#else
      ssize_t n;

      if (buf == NULL)
        {
          buflen = 8096;
          buf = malloc (buflen);
        }
      buf[0] = '\0';
      fgets (buf, buflen - 1, input);
      if (buf != NULL)
        n = strlen (buf);
      else
        n = 0;
#endif /* HAVE_GETLINE / HAVE_GETDELIM */

      ++line;
      cp = buf;

      if (n < 1)
	break;

      tmp = strchr (cp, ':');
      if (tmp)
	*tmp = '\0';
      else
	{
	  fprintf (stderr,_("%s: line %ld: missing new password\n"),
		   program, line);
	  ++errors;
	  continue;
	}

      pw_data = do_getpwnam (cp, use_service);
      if (pw_data == NULL || pw_data->service == S_NONE)
	{
	  fprintf (stderr, _("%s: line %ld: unknown user %s\n"),
		   program, line, cp);
	  ++errors;
	  continue;
	}

      cp = tmp+1;
      tmp = strchr (cp, '\n');
      if (tmp)
	*tmp = '\0';

      if (encrypted)
	pw_data->newpassword = strdup (cp);
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
	      if (strlen (cp) > 8)
		cp[8] = '\0';
	      salt =  make_crypt_salt ("", 0);
	      if (salt != NULL)
	        pw_data->newpassword = strdup (crypt_r (cp, salt, &output));
	      else
		{
		  fprintf (stderr, _("Cannot create salt for standard crypt"));
		  ++errors;
		  continue;
		}
	      free (salt);
	      break;

	    case MD5:
	      /* MD5 has a limit of 127 characters */
	      if (strlen (cp) > 127)
		cp[127] = '\0';
	      salt = make_crypt_salt ("$1$", 0);
	      if (salt != NULL)
		pw_data->newpassword = strdup (crypt_r (cp, salt, &output));
	      else
		{
		  fprintf (stderr, _("Cannot create salt for MD5 crypt"));
		  ++errors;
		  continue;
		}
	      free (salt);
	      break;
	    case BLOWFISH:
#if defined(HAVE_XCRYPT_GENSALT_R)
	      /* blowfish has a limit of 72 characters */
	      if (use_crypt == BLOWFISH && strlen (cp) > 72)
		cp[72] = '\0';
	      salt = make_crypt_salt ("$2a$", 0 /* XXX crypt_rounds */);
	      if (salt != NULL)
		pw_data->newpassword = strdup (crypt_r (cp, salt, &output));
	      else
		{
		  fprintf (stderr, _("Cannot create salt for blowfish crypt"));
		  ++errors;
		  continue;
		}
	      free (salt);
#endif
	      break;
	    default:
	      abort();
	    }
	}
      time (&now);
      pw_data->spn.sp_lstchg = (long int)now / (24L*3600L);
      pw_data->sp_changed = TRUE;

#ifdef USE_LDAP
      /* Add binddn data if user is stored in LDAP database and
	 we know the binddn.  */
      if (pw_data->service == S_LDAP)
	{
	  if (binddn)
	    pw_data->binddn = strdup (binddn);
	  if (oldclearpwd)
	    pw_data->oldclearpwd = strdup (oldclearpwd);
	}
#endif

      if (write_user_data (pw_data, 0) != 0)
	{
	  fprintf (stderr,
		   _("%s: line %ld: cannot update password entry\n"),
		   program, line);
	  ++errors;
	  continue;
	}

      free_user_t (pw_data);
    }

#ifdef HAVE_NSCD_FLUSH_CACHE
  nscd_flush_cache ("passwd");
#endif

  if (errors)
    {
      fprintf (stderr, _("%s: errors occurred, %ld passwords not updated\n"),
	       program, errors);
    }

  if (input != stdin)
    fclose (input);

  return E_SUCCESS;
}
