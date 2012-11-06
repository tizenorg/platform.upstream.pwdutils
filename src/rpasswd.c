/* Copyright (C) 2002-2006, 2009, 2010 Thorsten Kukuk
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

#include <assert.h>
#include <getopt.h>
#include <errno.h>
#include <ctype.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <signal.h>
#include <string.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#ifdef USE_GNUTLS
#include <gnutls/gnutls.h>
#else
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include "i18n.h"
#include "dbg_log.h"
#include "rpasswd-client.h"
#include "error_codes.h"

/* Define verbose output of rpasswd-client functions.  */
#define DO_VERBOSE_OUTPUT
#define HANDLE
#define PRINTF fprintf
#define ERR_HANDLE stderr
#define STD_HANDLE stdout
#define SELECT_SRVURL 1

#include "rpasswd-client.c"

/* Print the version information.  */
static void
print_version (const char *program)
{
  fprintf (stdout, "%s (%s) %s\n", program, PACKAGE, VERSION);
  fprintf (stdout, _("\
Copyright (C) %s Thorsten Kukuk.\n\
This is free software; see the source for copying conditions.  There is NO\n\
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\
"), "2006");
  /* fprintf (stdout, _("Written by %s.\n"), "Thorsten Kukuk"); */
}

static void
print_usage (FILE * stream, const char *program)
{
  fprintf (stream,
	   _("Usage: %s [-4|-6][-a][-f config-file][-h hostname][-p port][-v][name]\n"),
	   program);
}

static void
print_help (const char *program)
{
  print_usage (stdout, program);
  fprintf (stdout, _("%s - change password information\n\n"), program);

  fputs (_("  -4             Use IPv4 only\n"), stdout);
  fputs (_("  -6             Use IPv6 only\n"), stdout);
  fputs (_
	 ("  -a             Admin mode, special admin password is required\n"),
	 stdout);
  fputs (_("  -f config-file Specify a different config file\n"), stdout);
  fputs (_("  -h hostname    Specify the remote server\n"), stdout);
  fputs (_("  -p port        Specify port remote server is listening on\n"),
	 stdout);
  fputs (_("  -r level       Specify level of SSL certificate checks\n"),
	 stdout);
#ifdef USE_SLP
  fputs (_("  --no-slp       Don't use SLP to find a server\n"), stdout);
#endif
  fputs (_("  -v, --verbose  Be verbose, print SSL connection data\n"),
	 stdout);
  fputs (_("  --help         Give this help list\n"), stdout);
  fputs (_("  --usage        Give a short usage message\n"), stdout);
  fputs (_("  --version      Print program version\n"), stdout);
}

static void
print_error (const char *program)
{
  fprintf (stderr,
	   _("Try `%s --help' or `%s --usage' for more information.\n"),
	   program, program);
}

/* Read a line of input string, giving prompt when appropriate.  */
static int
read_string (int echo, const char *prompt, char **retstr)
{
  struct termios term_before, term_tmp;
  char line[PAM_MAX_MSG_SIZE];
  int nc = -1, have_term = 0;

  D (("called with echo='%s', prompt='%s'.", echo ? "ON" : "OFF", prompt));

  if (isatty (STDIN_FILENO))
    {				/* terminal state */
      /* is a terminal so record settings and flush it */
      if (tcgetattr (STDIN_FILENO, &term_before) != 0)
	{
	  fprintf (stderr, ("Error: failed to get terminal settings\n"));
	  *retstr = NULL;
	  return -1;
	}
      memcpy (&term_tmp, &term_before, sizeof (term_tmp));
      if (!echo)
	term_tmp.c_lflag &= ~(ECHO);

      have_term = 1;
    }
  else if (!echo)
    fprintf (stderr, _("Warning: cannot turn echo off\n"));

  /* reading the line */
  fprintf (stderr, "%s", prompt);
  /* this may, or may not set echo off -- drop pending input */
  if (have_term)
    (void) tcsetattr (STDIN_FILENO, TCSAFLUSH, &term_tmp);

  nc = read (STDIN_FILENO, line, PAM_MAX_MSG_SIZE - 1);
  if (have_term)
    {
      (void) tcsetattr (STDIN_FILENO, TCSADRAIN, &term_before);
      if (!echo)		/* do we need a newline? */
	fprintf (stderr, "\n");
    }

  if (nc > 0)			/* We got some user input.  */
    {
      if (line[nc - 1] == '\n')	/* <NUL> terminate */
	line[--nc] = '\0';
      else
	line[nc] = '\0';

      *retstr = strdup (line);	/* return malloc()ed string */
      _pam_overwrite (line);

      return nc;
    }
  else if (nc == 0)		/* Ctrl-D */
    {
      D (("user did not want to type anything"));
      fprintf (stderr, "\n");
    }

  /* getting here implies that there was an error or Ctrl-D pressed.  */
  if (have_term)
    (void) tcsetattr (STDIN_FILENO, TCSADRAIN, &term_before);

  memset (line, 0, PAM_MAX_MSG_SIZE);	/* clean up */
  *retstr = NULL;
  return nc;
}

#define CONV_ECHO_ON  1		/* types of echo state */
#define CONV_ECHO_OFF 0

#ifdef USE_GNUTLS
static int
handle_responses (gnutls_session ssl)
{
  response_header resp;
  char retval = E_SUCCESS;
  char *buf;

  do
    {
      int ret;

      if ((ret = gnutls_record_recv (ssl, &resp, sizeof (resp))) <= 0)
	{
	  if (ret == 0)
	    fprintf (stderr, _("error while reading request: %s"),
		     _("Peer has closed the TLS connection"));
	  else
	    fprintf (stderr, _("error while reading request: %s"),
		     gnutls_strerror (ret));
	  fputs ("\n", stderr);
	  return E_FAILURE;
	}

      buf = alloca (resp.data_len);
      if ((ret = gnutls_record_recv (ssl, buf, resp.data_len)) <= 0)
	{
	  fprintf (stderr, _("error while reading request data: %s"),
		   gnutls_strerror (ret));
	  fputs ("\n", stderr);
	  return E_FAILURE;
	}

      switch (resp.type)
	{
	case TEXT_INFO:
	  printf ("%s\n", buf);
	  break;
	case ERROR_MSG:
	  fprintf (stderr, "%s\n", buf);
	  break;
	case PROMPT_ECHO_OFF:
	  {
	    char *string = NULL;
	    int nc = read_string (CONV_ECHO_OFF, buf, &string);
	    if (nc < 0)
	      retval = send_string (ssl, PAM_CONV_ERR, string);
	    else
	      retval = send_string (ssl, PAM_SUCCESS, string);
	  }
	  break;
	case PROMPT_ECHO_ON:
	  {
	    char *string = NULL;
	    int nc = read_string (CONV_ECHO_ON, buf, &string);
	    if (nc < 0)
	      retval = send_string (ssl, PAM_CONV_ERR, string);
	    else
	      retval = send_string (ssl, PAM_SUCCESS, string);
	  }
	  break;
	case FINISH:
	  retval = buf[0];
	  break;
	default:
	  break;
	}

      if ((resp.type == PROMPT_ECHO_ON || resp.type == PROMPT_ECHO_OFF) &&
	  retval != 0)
	{
	  char err_buf[256];

	  fprintf (stderr, _("Cannot send input back to server: %s\n"),
		   strerror_r (errno, err_buf, sizeof (err_buf)));
	  return E_FAILURE;
	}
    }
  while (resp.type != FINISH);

  return retval;
}

#else

static int
handle_responses (SSL *ssl)
{
  response_header resp;
  char retval = E_SUCCESS;
  char *buf;

  do
    {
      errno = 0;
      if (TEMP_FAILURE_RETRY (SSL_read (ssl, &resp, sizeof (resp)))
	  != sizeof (resp))
	{
	  char err_buf[256];

	  if (errno == 0)
	    fprintf (stderr, _("error while reading request: %s"),
		     _("wrong data received"));
	  else
	    fprintf (stderr, _("error while reading request: %s"),
		     strerror_r (errno, err_buf, sizeof (err_buf)));
	  fputs ("\n", stderr);
	  return E_FAILURE;
	}

      buf = alloca (resp.data_len);
      if (TEMP_FAILURE_RETRY (SSL_read (ssl, buf, resp.data_len))
	  != resp.data_len)
	{
	  char err_buf[256];

	  fprintf (stderr, _("error while reading request data: %s"),
		   strerror_r (errno, err_buf, sizeof (err_buf)));
	  fputs ("\n", stderr);
	  return E_FAILURE;
	}

      switch (resp.type)
	{
	case TEXT_INFO:
	  printf ("%s\n", buf);
	  break;
	case ERROR_MSG:
	  fprintf (stderr, "%s\n", buf);
	  break;
	case PROMPT_ECHO_OFF:
	  {
	    char *string = NULL;
	    int nc = read_string (CONV_ECHO_OFF, buf, &string);
	    if (nc < 0)
	      retval = send_string (ssl, PAM_CONV_ERR, string);
	    else
	      retval = send_string (ssl, PAM_SUCCESS, string);
	  }
	  break;
	case PROMPT_ECHO_ON:
	  {
	    char *string = NULL;
	    int nc = read_string (CONV_ECHO_ON, buf, &string);
	    if (nc < 0)
	      retval = send_string (ssl, PAM_CONV_ERR, string);
	    else
	      retval = send_string (ssl, PAM_SUCCESS, string);
	  }
	  break;
	case FINISH:
	  retval = buf[0];
	  break;
	default:
	  break;
	}

      if ((resp.type == PROMPT_ECHO_ON || resp.type == PROMPT_ECHO_OFF) &&
	  retval != 0)
	{
	  char err_buf[256];

	  fprintf (stderr, _("Cannot send input back to server: %s\n"),
		   strerror_r (errno, err_buf, sizeof (err_buf)));
	  return E_FAILURE;
	}
    }
  while (resp.type != FINISH);

  return retval;
}
#endif

int
main (int argc, char **argv)
{
  const char *config_file = _PATH_RPASSWDCONF;
  const char *program = "rpasswd";
  char *hostp = NULL, *portp = NULL;
  int sock = -1, ai_family = PF_UNSPEC;
#ifdef USE_SLP
  int use_slp = 1;
#endif
  int verbose = 0;
  int admin_mode = 0;
  int reqcert = 3;
  int retval;
  char *username;
#ifdef USE_GNUTLS
  gnutls_session session;
  gnutls_certificate_credentials xcred;
#else
  SSL_CTX *ctx;
  SSL *ssl;
#endif

#ifdef ENABLE_NLS
  /* Set locale via LC_ALL.  */
  setlocale (LC_ALL, "");
  /* Set the text message domain.  */
  textdomain (PACKAGE);
#endif

  /* Ignore all signals which can make trouble later.  */
  signal (SIGXFSZ, SIG_IGN);
  signal (SIGPIPE, SIG_IGN);

  /* Parse program arguments */
  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] = {
	{"admin", no_argument, NULL, 'a'},
	{"config-file", required_argument, NULL, 'f'},
	{"host", required_argument, NULL, 'h'},
	{"ipv4", no_argument, NULL, '4'},
	{"ipv6", no_argument, NULL, '6'},
	{"port", no_argument, NULL, 'p'},
	{"verbose", no_argument, NULL, 'v'},
	{"reqcert", required_argument, NULL, 'r'},
#ifdef USE_SLP
	{"no-slp", no_argument, NULL, '\252'},
#endif
	{"version", no_argument, NULL, '\255'},
	{"usage", no_argument, NULL, '\254'},
	{"help", no_argument, NULL, '\253'},
	{NULL, 0, NULL, '\0'}
      };

      c = getopt_long (argc, argv, "af:h:p:r:v46",
		       long_options, &option_index);
      if (c == EOF)
	break;
      switch (c)
	{
	case 'a':
	  admin_mode = 1;
	  break;
	case 'f':
	  config_file = optarg;
	  break;
	case 'h':
	  hostp = optarg;
	  break;
	case '4':
	  if (ai_family == PF_INET || ai_family == PF_INET6)
	    {
	      print_usage (stderr, program);
	      return E_USAGE;
	    }
	  ai_family = PF_INET;
	  break;
	case '6':
	  if (ai_family == PF_INET || ai_family == PF_INET6)
	    {
	      print_usage (stderr, program);
	      return E_USAGE;
	    }
	  ai_family = PF_INET6;
	  break;
	case 'p':
	  portp = optarg;
	  break;
	case 'r':
	  reqcert = parse_reqcert (optarg);
	  break;
	case 'v':
	  verbose++;
	  break;
#ifdef USE_SLP
	case '\252':
	  use_slp = 0;
	  break;
#endif
	case '\253':
	  print_help (program);
	  return 0;
	case '\255':
	  print_version (program);
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

  if (argc > 1)
    {
      fprintf (stderr, _("%s: Too many arguments.\n"), program);
      print_error (program);
      return E_USAGE;
    }

  if (hostp)
    {
      if (portp)
	load_config (config_file, NULL, NULL, &reqcert, verbose, 0);
      else
	load_config (config_file, NULL, &portp, &reqcert, verbose, 0);
    }
  else if (portp)
    load_config (config_file, &hostp, NULL, &reqcert, verbose, 0);
  else
    load_config (config_file, &hostp, &portp, &reqcert, verbose, 0);

#ifdef USE_SLP
  if (hostp == NULL && portp == NULL && use_slp == 1)
    {
      char *descr;

      query_slp (&hostp, &portp, &descr);
      if (hostp != NULL && portp != NULL)
	printf (_("SLP: Found Server on %s, port %s"),
		hostp, portp);
      else if (hostp != NULL)
        printf (_("SLP: Found Server on %s"), hostp);

      if (descr)
	{
	  printf (" (%s)\n", descr);
	  free (descr);
	}
      else
	fputs ("\n", stdout);
    }
#endif

  if (portp == NULL)
    portp = "rpasswd";

  /* Get the login name of the calling user. This could be the one
     argument we still have or we use getpwuid/getuid to determine
     the login name.  */
  if (argc == 1)
    username = strdup (argv[0]);
  else
    {
      int pw_buflen = 256;
      char *pw_buffer = alloca (pw_buflen);
      struct passwd pw_resultbuf;
      struct passwd *pw = NULL;

      while (getpwuid_r (getuid (), &pw_resultbuf, pw_buffer, pw_buflen,
			 &pw) != 0 && errno == ERANGE)
	{
	  errno = 0;
	  pw_buflen += 256;
	  pw_buffer = alloca (pw_buflen);
	}
      if (pw == NULL)
	{
	  fprintf (stderr, _("Go away, you do not exist!"));
	  return E_UNKNOWN_USER;
	}
      username = strdup (pw->pw_name);
    }

  if (hostp != NULL)
    {
      sock = connect_to_server (hostp, portp, ai_family, 0);
      if (sock < 0)
	return E_FAILURE;
    }
  else
    {
      fprintf (stderr, _("No server specified\n"));
      return E_USAGE;
    }

  /* Do SSL */
#ifdef USE_GNUTLS
  gnutls_global_init ();
  /* Initialize TLS session. */
  gnutls_init (&session, GNUTLS_CLIENT);
  retval = start_ssl (sock, reqcert, verbose, session, &xcred);
#else
  retval = start_ssl (sock, reqcert, verbose, &ctx, &ssl);
#endif
  if (retval != 0)
    return retval;

#ifdef USE_GNUTLS
  if ((retval = start_request (session, username, admin_mode)) == 0)
    retval = handle_responses (session);
  else
    retval = E_FAILURE;
#else
  if ((retval = start_request (ssl, username, admin_mode)) == 0)
    retval = handle_responses (ssl);
  else
    retval = E_FAILURE;
#endif

  free (username);

#ifdef USE_GNUTLS
  gnutls_bye (session, GNUTLS_SHUT_RDWR);
  close (sock);
  gnutls_deinit (session);
  gnutls_certificate_free_credentials (xcred);
  gnutls_global_deinit ();
#else
  close (sock);
  SSL_free (ssl);
  SSL_CTX_free (ctx);
#endif

  return retval;
}
