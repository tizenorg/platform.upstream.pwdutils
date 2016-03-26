/* Copyright (C) 2003, 2004, 2005, 2006, 2012 Thorsten Kukuk
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

#include <pwd.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <shadow.h>
#include <unistd.h>
#include <getopt.h>
#include <syslog.h>
#include <sys/stat.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#include <selinux/av_permissions.h>
#endif
#ifdef HAVE_LIBNSCD_H
#include <libnscd.h>
#endif
#ifdef HAVE_BIOAPI_H
#include <bioapi.h>
#ifdef HAVE_BIOAPI_UTIL_H
#include <bioapi_util.h>
#endif
#endif

#include "i18n.h"
#include "public.h"
#include "logging.h"
#include "logindefs.h"
#include "read-files.h"
#include "error_codes.h"

#ifndef GPASSWD_PROGRAM
#define GPASSWD_PROGRAM "gpasswd"
#endif

#ifndef CHFN_PROGRAM
#define CHFN_PROGRAM "chfn"
#endif

#ifndef CHSH_PROGRAM
#define CHSH_PROGRAM "chsh"
#endif

/* How often should we try to lock the passwd database ?  */
#define MAX_LOCK_RETRIES 3

static struct pam_conv conv = {
  misc_conv,
  NULL
};

static long
conv2long (const char *param)
{
  long val;
  char *cp;

  val = strtol (param, &cp, 10);
  if (*cp)
    return -2;
  return val;
}

static const char *
pw_status (const char *pass)
{
  if (*pass == '\0')
    return "NP";
  if (*pass == '*' || *pass == '!' || strcmp (pass, "x") == 0)
    return "LK";
  return "PS";
}

static char *
date_to_str (time_t t)
{
  static char buf[80];
  struct tm *tm;

  tm = gmtime (&t);
  strftime (buf, sizeof buf, "%m/%d/%Y", tm);
  return buf;
}

static void
display_pw (const struct passwd *pw)
{
  struct spwd *sp;

#define DAY (24L*3600L)
#define SCALE DAY

  sp = getspnam (pw->pw_name);
  if (sp)
    {
      printf ("%s %s %s %ld %ld %ld %ld\n",
              sp->sp_namp,
              pw_status (sp->sp_pwdp),
              date_to_str (sp->sp_lstchg * SCALE),
              (sp->sp_min * SCALE) / DAY,
              (sp->sp_max * SCALE) / DAY,
              (sp->sp_warn * SCALE) / DAY,
              (sp->sp_inact * SCALE) / DAY);
    }
  else
    printf ("%s %s\n", pw->pw_name, pw_status (pw->pw_passwd));
}

/* A conversation function which uses an internally-stored value for
 * the responses. */
static int
stdin_conv (int num_msg, const struct pam_message **msgm,
	    struct pam_response **response, void *appdata_ptr)
{
  struct pam_response *reply;
  int count;

  /* Sanity test. */
  if (num_msg <= 0)
    return PAM_CONV_ERR;

  /* Allocate memory for the responses. */
  reply = calloc (num_msg, sizeof (struct pam_response));
  if (reply == NULL)
    return PAM_CONV_ERR;

  /* Each prompt elicits the same response. */
  for (count = 0; count < num_msg; ++count)
    {
      reply[count].resp_retcode = 0;
      reply[count].resp = strdup (appdata_ptr);
    }

  /* Set the pointers in the response structure and return. */
  *response = reply;
  return PAM_SUCCESS;
}

#ifdef HAVE_BIOAPI_H

static const char *birDbPath = "/etc/bioapi/pam";

static char *
get_uuid_string ()
{
  return strdup ("{5550454b-2054-464d-2f45-535320425350}");
}

static int
bioapi_delete (const char *user)
{
  char *uuidString = get_uuid_string ();
  char *filename;
  int ret;

  if (asprintf (&filename, "%s/%s/%s.bir", birDbPath,
		uuidString, user) < 0)
    {
      fputs ("running out of memory!\n", stderr);
      free (uuidString);
      return E_FAILURE;
    }
  free (uuidString);

  unlink (filename);
  free (filename);

  return E_SUCCESS;
}

static int
bioapi_chauthtok (const char *user)
{
  static const struct bioapi_version version = { 1, 10 };
  BioAPI_RETURN bret;
  char *uuidString = get_uuid_string ();
  BioAPI_UUID tempUuid;
  const BioAPI_UUID *uuid;
  BioAPI_HANDLE bspHandle;
  BioAPI_BIR_HANDLE bir;

  bret = BioAPI_Init (&version, 0, NULL, 0, NULL);
  if (bret != BioAPI_OK)
    {
      fprintf (stderr,
	       _("Unable to initialize BioAPI framework, BioAPI error #:%x.\n"),
	       bret);
      free (uuidString);
      return E_FAILURE;
    }

  bret = BioAPI_GetStructuredUUID (uuidString, &tempUuid);
  if (bret != BioAPI_OK)
    {
      fprintf (stderr,
	       _("Unable to parse UUID (BioAPI error #:%x) : %s\n"),
	       bret, uuidString);
      BioAPI_Terminate ();
      free (uuidString);
      return E_FAILURE;
    }

  uuid = (const BioAPI_UUID *) malloc (sizeof(BioAPI_UUID));
  if (uuid == 0)
    {
      fputs ("running out of memory!\n", stderr);
      BioAPI_Terminate ();
      free (uuidString);
      return E_FAILURE;
    }

  memcpy (uuid, tempUuid, sizeof(BioAPI_UUID));
  bret = BioAPI_ModuleLoad (uuid, 0, NULL, NULL);
  if (bret != BioAPI_OK)
    {
      fprintf (stderr,
	       _("Unable to load BioAPI BSP with UUID of %s, BioAPI error #%x.\n"),
	       uuidString, bret);
      BioAPI_Terminate ();
      return E_FAILURE;
    }

  bret = BioAPI_ModuleAttach (uuid, &version, &BioAPIMemoryFuncs,
			      0, 0, 0, 0, NULL, 0, NULL, &bspHandle);
  if (bret != BioAPI_OK)
    {
      fprintf (stderr,
	       _("Unable to attach default device to BioAPI BSP with UUID of %s, BioAPI error #%x.\n"),
	       uuidString, bret);
      BioAPI_ModuleUnload (uuid, NULL, NULL);
      free (uuid);
      BioAPI_Terminate ();
      return E_FAILURE;
    }

  bret = BioAPI_Enroll (bspHandle,
			BioAPI_PURPOSE_ENROLL_FOR_VERIFICATION_ONLY,
			NULL, &bir, NULL, -1, NULL);
  if (bret == BioAPI_OK)
    {
      FILE *outputFile;
      char *filename = malloc (strlen(birDbPath) + 1 +
			       strlen (uuidString) + 1 +
			       strlen (user) + 4 + 1);
      struct stat status;
      BioAPI_BIR_PTR birData;

      strcpy (filename, birDbPath);
      stat (filename, &status);
      /* Does the birDb directory exist? If not, create it.  */
      if (errno == ENOENT && mkdir (filename, S_IRWXU | S_IRWXG) == -1)
	{
	  fprintf (stderr,
		   _("Unable to create BIR database directory, \"%s\"\n"),
		   filename);
	  free (filename);
	  return E_FAILURE;
	}
      strcat (filename, "/");
      strcat (filename, uuidString);
      stat (filename, &status);
      /* Does the BSP specific directory exist? If not, create it.  */
      if (errno == ENOENT &&
	  mkdir (filename, S_IRWXU | S_IRWXG) == -1)
	{
	  fprintf (stderr,
		   _("Unable to create BSP-specific subdirectory in BIR database directory, \"%s\"\n"),
		   filename);
	  free (filename);
	  return E_FAILURE;
	}

      strcat (filename, "/");
      strcat (filename, user);
      strcat (filename, ".bir");

      birData = NULL;
      if ((bret = BioAPI_GetBIRFromHandle (bspHandle, bir, &birData))
	  != BioAPI_OK)
	{
	  fprintf (stderr,
		   _("Unable to write biometric identification record, \"%s\": BioAPI error #%x\n"),
		   filename, bret);
	  free (filename);
	  return E_FAILURE;
	}

      outputFile = fopen (filename, "w+");
      free (filename);

      if (outputFile == NULL)
	{
	  fprintf (stderr,
		   _("Unable to open BIR for writing, \"%s\"\n"),
		   filename);
	  return E_FAILURE;
	}
      fwrite (&(birData->Header), sizeof (BioAPI_BIR_HEADER),
	      1, outputFile);
      fwrite (birData->BiometricData,
	      birData->Header.Length - sizeof(BioAPI_BIR_HEADER),
	      1, outputFile);

      if (birData->Signature)
	{
	  fwrite (&(birData->Signature->Length), 4, 1, outputFile);
	  fwrite (birData->Signature->Data,
		  (size_t)birData->Signature->Length, 1,
		  outputFile);
	}

      fclose (outputFile);
      free (birData->BiometricData);

      if (birData->Signature)
	{
	  free (birData->Signature->Data);
	  free (birData->Signature);
	}
      free (birData);
    }
  else
    {
      fprintf (stderr,
	       _("Unable to enroll user %s using BSP with UUID of %s, BioAPI error #%x.\n"),
	       user, uuidString, bret);
    }
  BioAPI_ModuleDetach (bspHandle);
  BioAPI_ModuleUnload (uuid, NULL, NULL);
  free (uuid);
  BioAPI_Terminate ();
  if (bret != BioAPI_OK)
    return E_FAILURE;

  return E_SUCCESS;
}
#endif


static void
print_usage (FILE *stream, const char *program)
{
  fprintf (stream, _("Usage: %s [-f|-g|-s|-k[-q]] [account]\n"), program);
  fprintf (stream, _("       %s [-D binddn] [-n min] [-x max] [-w warn] [-i inact] account\n"), program);
  fprintf (stream, _("       %s {-l|-u|-d|-S[-a]|-e} account\n"), program);
#ifdef HAVE_BIOAPI_H
  fprintf (stream, _("       %s --bioapi [account]\n"), program);
#endif
  fprintf (stream, _("       %s --stdin [account]\n"), program);
}

static void
print_help (const char *program)
{
  print_usage (stdout, program);
  fprintf (stdout, _("%s - change password information\n\n"), program);

  fputs (_("  -f             Change the finger (GECOS) information\n"),
         stdout);
  fputs (_("  -s             Change the login shell\n"), stdout);
  fputs (_("  -g             Change the group password\n"), stdout);
  fputs (_("  -k             Change the password only if expired\n"), stdout);
  fputs (_("  -q             Try to be quiet\n"), stdout);
  fputs (_("  -S             Show the password attributes\n"), stdout);
  fputs (_("  -a             Only with -S, show for all accounts\n"), stdout);
  fputs (_("  -d             Delete the password for the named account\n"), stdout);
  fputs (_("  -l             Locks the password entry for \"account\"\n"), stdout);
  fputs (_("  -u             Try to unlock the password entry for \"account\"\n"), stdout);
  fputs (_("  -e             Force the user to change password at next login\n"), stdout);
  fputs (_("  -n min         Set minimum field for \"account\"\n"), stdout);
  fputs (_("  -x max         Set maximum field for \"account\"\n"), stdout);
  fputs (_("  -w warn        Set warn field for \"account\"\n"), stdout);
#ifdef HAVE_BIOAPI_H
  fputs (_("  --bioapi       Authentication token is handled via BioAPI\n"), stdout);
#endif
  fputs (_("  --service srv  Use nameservice 'srv'\n"), stdout);
  fputs (_("  -D binddn      Use dn \"binddn\" to bind to the LDAP directory\n"),
	 stdout);
  fputs (_("  -P path        Search passwd and shadow file in \"path\"\n"),
	 stdout);
  fputs (_("  --stdin        Read new password from stdin (root only)\n"), stdout);
  fputs (_("  --help         Give this help list\n"), stdout);
  fputs (_("  --usage        Give a short usage message\n"), stdout);
  fputs (_("  --version      Print program version\n"), stdout);
  fputs (_("Valid services are: files, nis, nisplus, ldap\n"), stdout);
}

static int
passwd_main (const char *program, int argc, char **argv)
{
  int buflen = 256;
  char *buffer = alloca (buflen);
  struct passwd resultbuf;
  struct passwd *pw = NULL;
  int admin_only = 0;
  int silent = 0;
  uid_t uid = getuid ();
  user_t *pw_data = NULL;
  char *caller_name = NULL;
  char *use_service = NULL;
  char *binddn = NULL;
  int k_flag = 0, a_flag = 0, d_flag = 0, e_flag = 0,
    i_flag = 0, l_flag = 0, n_flag = 0, u_flag = 0, x_flag = 0,
#ifdef HAVE_BIOAPI_H
    bioapi_flag = 0,
#endif
    S_flag = 0, w_flag = 0, P_flag = 0, stdin_flag = 0;

  long inact = 0, age_min = 0, age_max = 0, warn = 0;

  /* Parse program arguments */
  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
	{
	  {"binddn", required_argument, NULL, 'D'},
	  {"path", required_argument, NULL, 'P'},
	  {"version", no_argument, NULL, '\255'},
	  {"usage", no_argument, NULL, '\254'},
	  {"help", no_argument, NULL, '\253'},
	  {"stdin", no_argument, NULL, '\252'},
	  {"service", required_argument, NULL, '\251'},
#ifdef HAVE_BIOAPI_H
	  {"bioapi", no_argument, NULL, '\250'},
#endif
	  {NULL, 0, NULL, '\0'}
	};

      c = getopt_long (argc, argv, "adD:lquSekn:x:i:w:P:", long_options,
                       &option_index);
      if (c == EOF)
        break;
      switch (c)
	{
	case 'a':
	  a_flag = 1;
	  break;
        case 'd':
          d_flag = 1;
          admin_only = 1;
          break;
	case 'D':
	  binddn = optarg;
	  break;
        case 'e':
          e_flag = 1;
          admin_only = 1;
          break;
        case 'i':
	  i_flag = 1;
          inact = conv2long (optarg);
          if (inact <= -2)
	    {
	      print_error (program);
	      return E_BAD_ARG;
	    }
	  admin_only = 1;
          break;
        case 'k':
          k_flag = 1;  /* ok for users */
          break;
        case 'l':
          l_flag = 1;
          admin_only = 1;
          break;
        case 'n':
	  n_flag = 1;
          age_min = conv2long (optarg);
	  if (age_min <= -2)
	    {
	      print_error (program);
	      return E_BAD_ARG;
	    }
          admin_only = 1;
          break;
        case 'q':
          silent = 1;  /* ok for users */
          break;
        case '\251':
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
	  else if (strcasecmp (optarg, "ldap") == 0)
	    use_service = "ldap";
          else
            {
              fprintf (stderr, _("Service `%s' not supported.\n"), optarg);
              print_usage (stderr, program);
              return E_BAD_ARG;
            }
          break;
        case 'x':
	  x_flag = 1;
          age_max = conv2long (optarg);
	  if (age_max <= -2)
	    {
	      print_error (program);
	      return E_BAD_ARG;
	    }
	  admin_only = 1;
          break;
        case 'S':
          S_flag = 1;  /* ok for users */
          break;
        case 'u':
          u_flag = 1;
          admin_only = 1;
          break;
        case 'w':
	  w_flag = 1;
          warn = conv2long (optarg);
          if (warn <= -2)
	    {
	      print_error (program);
	      return E_BAD_ARG;
	    }
          admin_only = 1;
          break;
	case 'P':
	  P_flag = 1;
	  files_etc_dir = strdup (optarg);
	  break;
#ifdef HAVE_BIOAPI_H
	case '\250':
	  bioapi_flag = 1;
	  break;
#endif
	case '\252':
	  stdin_flag = 1;
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
        default:
          print_error (program);
          return E_BAD_ARG;
        }
    }

  argc -= optind;
  argv += optind;

  /* We have more than one username or we have -S -a with a
     username */
  if (argc > 1|| (a_flag && S_flag && argc != 0))
    {
      fprintf (stderr, _("%s: Too many arguments.\n"), program);
      print_error (program);
      return E_USAGE;
    }

  /* For admin only commands we need a user name */
  if (argc == 0 && admin_only)
    {
      fprintf (stderr, _("%s: User argument missing\n"), program);
      print_error (program);
      return E_USAGE;
    }

  /* Print a list of all users with status informations.
     The -a flag requires -S, no other flags, no username, and
     you must be root.  */
  if (a_flag)
    {
      if (admin_only || !S_flag || (argc != 0))
	{
	  print_error (program);
	  return E_USAGE;
	}
      if (uid != 0)
        {
          fprintf (stderr, _("%s: Permission denied.\n"), program);
	  sec_log (program, MSG_PASSWORD_STATUS_FOR_ALL_DENIED, uid);
          return E_NOPERM;
        }
      sec_log (program, MSG_DISPLAY_PASSWORD_STATUS_FOR_ALL, uid);
      setpwent ();
      while ((pw = getpwent ()))
        display_pw (pw);
      endpwent ();
      return E_SUCCESS;
    }

  if (stdin_flag && uid != 0)
    {
      fprintf (stderr, _("%s: Permission denied.\n"), program);
      sec_log (program, MSG_STDIN_FOR_NONROOT_DENIED, uid);
      return E_NOPERM;
    }

  if (S_flag && (admin_only || k_flag))
    {
      print_error (program);
      return E_USAGE;
    }
  else if (d_flag + u_flag + l_flag > 1)
    {
      print_error (program);
      return E_USAGE;
    }
  else
    {
      /* Determine our own user name for PAM authentication.  */
      while (getpwuid_r (uid, &resultbuf, buffer, buflen, &pw) != 0
	     && errno == ERANGE)
	{
	  errno = 0;
	  buflen += 256;
	  buffer = alloca (buflen);
	}
      if (!pw)
	{
          sec_log (program, MSG_NO_ACCOUNT_FOUND, uid);
	  fprintf (stderr, _("%s: Cannot determine your user name.\n"),
		   program);
	  return E_NOPERM;
	}
      caller_name = strdupa (pw->pw_name);

      /* We change the passwd information for another user, get that
         data, too.  */
      if (argc == 1)
        {
          while (getpwnam_r (argv[0], &resultbuf, buffer, buflen, &pw) != 0
                 && errno == ERANGE)
            {
              errno = 0;
              buflen += 256;
              buffer = alloca (buflen);
            }
          if (!pw)
            {
              fprintf (stderr, _("%s: Unknown user `%s'.\n"),
		       program, argv[0]);
              return E_NOPERM;
            }
        }

      pw_data = do_getpwnam (pw->pw_name, use_service);
      if (pw_data == NULL || pw_data->service == S_NONE)
	{
	  sec_log (program, MSG_UNKNOWN_USER, pw->pw_name, uid);
	  /* Only print error, if we need the pw_data informations
	     later. Else ignore it and let PAM do it.  */
	  if (use_service)
	    {
	      fprintf (stderr,
		       _("%s: User `%s' is not known to service `%s'\n"),
		       program, pw->pw_name, use_service);
	      return E_FAILURE;
	    }
	  else if (admin_only)
	    {
	      fprintf (stderr, _("%s: Unknown user `%s'.\n"), program,
		       pw->pw_name);
	      return E_FAILURE;
	    }
	}
    }

#ifdef WITH_SELINUX
  if (is_selinux_enabled () > 0)
    {
      if ((uid == 0) &&
	  (selinux_check_access (pw->pw_name, PASSWD__PASSWD) != 0))
	{
	  security_context_t user_context;
	  if (getprevcon (&user_context) < 0)
	    user_context =
	      (security_context_t) strdup (_("Unknown user context"));

	  fprintf (stderr,
		  _("%s: %s is not authorized to change the password of %s\n"),
		   program, user_context, pw->pw_name);
	  if (security_getenforce() > 0)
	    {
	      syslog (LOG_ALERT,
		      "%s is not authorized to change the password of %s",
		      user_context, pw->pw_name);
	      freecon (user_context);
	      exit (E_NOPERM);
	    }
	  else
	    {
	      fprintf (stderr,
		       _("SELinux is in permissive mode, continuing\n"));
	      freecon (user_context);
	    }
	}
    }
#endif

  /* Check if normal users are allowed to change the data. For NIS+ and
     LDAP, we let the service decide if the user is allowed.  */
  if (uid != 0 && pw_data &&
      pw_data->service != S_NISPLUS && pw_data->service != S_LDAP)
    {
      if (admin_only)
	{
	  sec_log (program, MSG_PASSWORD_CHANGE_DENIED,
		   pw_data->pw.pw_name, pw_data->pw.pw_uid, uid);
          fprintf(stderr, _("%s: Permission denied\n"), program);
	  if (pw_data)
	    free_user_t (pw_data);
	  return E_NOPERM;
	}
      if (pw->pw_uid != uid)
	{
	  sec_log (program, MSG_PASSWORD_CHANGE_DENIED,
		   pw_data->pw.pw_name, pw_data->pw.pw_uid, uid);
	  fprintf (stderr, _("You cannot change the shadow data for `%s'.\n"),
		   pw->pw_name);
	  syslog (LOG_WARNING, "%d cannot change shadow data for `%s'",
		  uid, pw->pw_name);
	  if (pw_data)
	    free_user_t (pw_data);
	  return E_NOPERM;
	}
    }

  if (S_flag)
    {
      sec_log (program, MSG_DISPLAY_PASSWORD_STATUS,
	       pw->pw_name, pw->pw_uid, uid);
      display_pw (pw);
      if (pw_data)
	free_user_t (pw_data);
      return E_SUCCESS;
    }

  /* We only change the password, let PAM do it.  */
  if (!admin_only)
    {
      pam_handle_t *pamh = NULL;
      int flags = 0, ret;

      if (P_flag)
	{
	  fprintf (stderr, _("%s: -P flag not supported in this mode!\n"),
		   program);
	  return E_USAGE;
	}


      if (stdin_flag)
	{
	  char *ptr;
	  char password[160]; /* 127 is the longest with current crypt */
	  int i;

	  i = read (STDIN_FILENO, password, sizeof (password) - 1);
	  if (i < 0)
	    {
	      fprintf (stderr, _("%s: error reading from stdin!\n"),
		       program);
	      return E_FAILURE;
	    }

	  password[i] = '\0';
	  /* Remove trailing \n.  */
	  ptr = strchr (password, '\n');
	  if (ptr)
	    *ptr = 0;
	  conv.conv = stdin_conv;
	  conv.appdata_ptr = strdup (password);
	}

      if (!silent)
	printf (_("Changing password for %s.\n"), pw->pw_name);

#ifdef HAVE_BIOAPI_H
      if (bioapi_flag)
	{
	  int bret = bioapi_chauthtok (pw->pw_name);
	  if (bret != E_SUCCESS)
	    {
	      syslog (LOG_ERR, "User %s: BioAPI %d",
		      caller_name, bret);
	      sec_log (program, MSG_PASSWORD_CHANGE_FAILED,
		       ret, pw->pw_name, pw->pw_uid, uid);
	      sleep (getlogindefs_num ("FAIL_DELAY", 1));
	      if (pw_data)
		free_user_t (pw_data);
	      return E_PAM_ERROR;
	    }
	}
      else
#endif
	{
	  if (silent)
	    flags |= PAM_SILENT;
	  if (k_flag)
	    flags |= PAM_CHANGE_EXPIRED_AUTHTOK;

	  ret = pam_start ("passwd", pw->pw_name, &conv, &pamh);
	  if (ret != PAM_SUCCESS)
	    {
	      fprintf (stderr, _("%s: PAM Failure, aborting: %s\n"),
		       program, pam_strerror (pamh, ret));
	      syslog (LOG_ERR, "Couldn't initialize PAM: %s",
		      pam_strerror (pamh, ret));
	      if (pw_data)
		free_user_t (pw_data);
	      return E_PAM_ERROR;
	    }

	  ret = pam_chauthtok (pamh, flags);
	  if (ret != PAM_SUCCESS)
	    {
	      syslog (LOG_ERR, "User %s: %s", caller_name,
                  pam_strerror (pamh, ret));
	      sec_log (program, MSG_PASSWORD_CHANGE_FAILED,
		       ret, pw->pw_name, pw->pw_uid, uid);
	      sleep (getlogindefs_num ("FAIL_DELAY", 1));
	      fprintf (stderr, "%s: %s\n", program,
		       pam_strerror (pamh, ret));
	      if (pw_data)
		free_user_t (pw_data);
	      return E_PAM_ERROR;
	    }

	  pam_end (pamh, PAM_SUCCESS);
	}
      sec_log (program, MSG_PASSWORD_CHANGED,
	       pw->pw_name, pw->pw_uid, uid);
      if (pw_data)
	free_user_t (pw_data);
      return E_SUCCESS;
    }

  /* if we come at this place, pw_data should not be NULL. */
  assert (pw_data);

  if (binddn)
    {
      char prompt[130+strlen (binddn)], *cp;

      pw_data->binddn = strdup (binddn);
      snprintf (prompt, sizeof (prompt), _("Enter LDAP Password:"));
      cp = getpass (prompt);
      pw_data->oldclearpwd = strdup (cp);
    }

  if (d_flag)
    {
#ifdef HAVE_BIOAPI_H
      if (bioapi_flag)
	bioapi_delete (pw->pw_name);
      else
#endif
	pw_data->newpassword = strdup ("");
    }
  else if (u_flag)
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
  else if (l_flag)
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

  if (x_flag)
    pw_data->spn.sp_max = (age_max * DAY) / SCALE;
  if (n_flag)
    pw_data->spn.sp_min = (age_min * DAY) / SCALE;
  if (w_flag)
    pw_data->spn.sp_warn = (warn * DAY) / SCALE;
  if (i_flag)
    pw_data->spn.sp_inact = (inact * DAY) / SCALE;
  if (e_flag)
    pw_data->spn.sp_lstchg = 0;
  if (x_flag || n_flag || w_flag || i_flag || e_flag || e_flag)
    pw_data->sp_changed = TRUE;

  if (write_user_data (pw_data, 0) != 0)
    {
      if (pw_data->sp_changed)
	fprintf (stderr,
		 _("Error while changing password expiry information.\n"));
      else
	fprintf (stderr, _("Error while changing password.\n"));
      free_user_t (pw_data);
      return E_FAILURE;
    }
  else
    {
#ifdef HAVE_NSCD_FLUSH_CACHE
      nscd_flush_cache ("passwd");
#endif
      if (!silent)
	{
	  if (pw_data->sp_changed)
	    printf (_("Password expiry information changed.\n"));
	  else if (d_flag)
	    printf (_("Password deleted.\n"));
	  else
	    printf (_("Password changed.\n"));
	}
    }

  sec_log (program, MSG_PASSWORD_CHANGED,
	   pw_data->pw.pw_name, pw_data->pw.pw_uid, uid);

  free_user_t (pw_data);

  return E_SUCCESS;
}

int
main (int argc, char **argv)
{
  int retval;
  char *prog;

#ifdef ENABLE_NLS
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);
#endif

  prog = basename (argv[0]);

  open_sec_log (prog);

  /* Before going any further, raise the ulimit and ignore
     signals.  */

  init_environment ();

  /* easy way to get ride of the first argument.  */
  if (argc > 1 && argv[1][0] == '-' && strchr ("gfs", argv[1][1]))
    {
      char buf[200];

      if (setuid (getuid ()) != 0)
	{
	  sec_log (prog, MSG_DROP_PRIVILEGE_FAILED, errno, getuid());
          fprintf (stderr, _("%s: Failed to drop privileges: %s\n"),
                   prog, strerror (errno));
          return E_FAILURE;
	}
      switch (argv[1][1])
        {
        case 'g':
          argv[1] = GPASSWD_PROGRAM;  /* XXX warning: const */
          break;
        case 'f':
          argv[1] = CHFN_PROGRAM;  /* XXX warning: const */
          break;
        case 's':
          argv[1] = CHSH_PROGRAM;  /* XXX warning: const */
          break;
        default:
          /* If this happens we have a real problem. */
          abort ();
        }
      snprintf (buf, sizeof buf, _("passwd: Cannot execute %s"), argv[1]);
      execvp(argv[1], &argv[1]);
      perror(buf);
      syslog (LOG_ERR, "Cannot execute %s", argv[1]);
      closelog ();
      return E_FAILURE;
    }

  retval = passwd_main (prog, argc, argv);
  closelog ();
  return retval;
}
