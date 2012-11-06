/*
 * Copyright (c) 2004, 2005, 2009, 2010 Thorsten Kukuk <kukuk@suse.de>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <pwd.h>
#include <shadow.h>
#include <dlfcn.h>
#include <time.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <rpc/types.h>

#ifdef USE_GNUTLS
#include <gnutls/gnutls.h>
#else
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#define PAM_SM_PASSWORD
#include <security/_pam_macros.h>
#include <security/pam_modules.h>

#include "error_codes.h"
#include "rpasswd-client.h"

/* We don't use translated texts.  */
#define _(s) s

struct options_t {
  int debug;
  int use_slp;
  int verbose;
  int quiet;
  int reqcert;
  char *config_file;
  char *host;
  char *port;
  char *descr;
};
typedef struct options_t options_t;

/* syslogging function for errors and other information */
static void
__pam_log (int err, const char *format,...)
{
  va_list args;
  char *str;

  va_start (args, format);
  if (vasprintf (&str, format, args) < 0)
    return;
  syslog (err, "pam_rpasswd: %s", str);
  va_end (args);
}

/* write message to user */
static int
__write_message (pam_handle_t *pamh, int msg_style,
                 const char *fmt,...)
{
  struct pam_message msg[1], *pmsg[1];
  struct pam_response *resp=NULL;
  struct pam_conv *conv;
  void *conv_void;
  char buffer[512];
  va_list ap;
  int retval;
  int buflen;

  va_start (ap, fmt);
  vsnprintf (buffer, sizeof (buffer), fmt, ap);
  va_end (ap);

  buflen = strlen (buffer);
  if (buffer[buflen - 1] == '\n')
    buffer[buflen - 1] = '\0';

  pmsg[0] = &msg[0];
  msg[0].msg_style = msg_style;
  msg[0].msg = buffer;

  retval = pam_get_item (pamh, PAM_CONV, (const void **) &conv_void);
  conv = (struct pam_conv *) conv_void;
  if (retval == PAM_SUCCESS)
    {
      retval = conv->conv (1, (const struct pam_message **)pmsg,
                           &resp, conv->appdata_ptr);
      if (retval != PAM_SUCCESS)
        return retval;
    }
  else
    return retval;

  msg[0].msg = NULL;
  if (resp)
    _pam_drop_reply(resp, 1);

  return retval;
}

#define HANDLE pam_handle_t *pamh,
#define IAM_PAM_MODULE
#define PRINTF __write_message
#define ERR_HANDLE pamh, PAM_ERROR_MSG
#define STD_HANDLE pamh, PAM_TEXT_INFO

#include "rpasswd-client.c"

#define CONV_ECHO_ON  1		/* types of echo state */
#define CONV_ECHO_OFF 0

static int
read_string (pam_handle_t *pamh, int echo, const char *prompt,
	     char **retstr)
{
  struct pam_message msg[1], *pmsg[1];
  struct pam_response *resp;
  struct pam_conv *conv;
  void *conv_void;
  int retval;

  /* set up conversation call */

  pmsg[0] = &msg[0];
  if (echo == CONV_ECHO_ON)
    msg[0].msg_style = PAM_PROMPT_ECHO_ON;
  else
    msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
  msg[0].msg = prompt;
  resp = NULL;

  retval = pam_get_item (pamh, PAM_CONV, (const void **) &conv_void);
  conv = (struct pam_conv *) conv_void;
  if (retval == PAM_SUCCESS)
    {
      retval = conv->conv (1, (const struct pam_message **)pmsg,
                           &resp, conv->appdata_ptr);
      if (retval != PAM_SUCCESS)
        return retval;
    }
  else
    return retval;

  if (resp)
    {
      *retstr = strdup (resp->resp ? resp->resp : "");
      if (resp)
        _pam_drop_reply (resp, 1);
    }
  else
    return PAM_CONV_ERR;

  return PAM_SUCCESS;
}

#ifdef USE_GNUTLS
static int
handle_responses (pam_handle_t *pamh, gnutls_session ssl)
{
  response_header resp;
  char retval = PAM_SUCCESS;
  char *buf = NULL;

  do
    {
      int ret;

      /* header */
      if ((ret = gnutls_record_recv (ssl, &resp, sizeof (resp))) <= 0)
	{
	  if (ret == 0)
	    __write_message (pamh, PAM_ERROR_MSG,
			     _("error while reading request: %s"),
			     _("Peer has closed the TLS connection"));
	  else
	    __write_message (pamh, PAM_ERROR_MSG,
			     _("error while reading request: %s"),
			     gnutls_strerror (ret));
	  return PAM_SYSTEM_ERR;
	}

      /* first entry */
      if (resp.data_len > 0)
	{
	  buf = malloc (resp.data_len);
	  if (buf == NULL)
	    {
	      __write_message (pamh, PAM_ERROR_MSG,
			       _("error while allocating memory: %m"));
	      return PAM_SYSTEM_ERR;
	    }

	  if ((ret = gnutls_record_recv (ssl, buf, resp.data_len)) <= 0)
	    {
	      __write_message (pamh, PAM_ERROR_MSG,
			       _("error while reading request data: %s"),
			       gnutls_strerror (ret));
	      free (buf);
	      return PAM_SYSTEM_ERR;
	    }
	}

      switch (resp.type)
	{
	case TEXT_INFO:
	  if (buf)
	    __write_message (pamh, PAM_TEXT_INFO,
			     "%s\n", buf);
	  break;
	case ERROR_MSG:
	  if (buf)
	    __write_message (pamh, PAM_ERROR_MSG,
			     "%s\n", buf);
	  break;
	case PROMPT_ECHO_OFF:
	  {
	    char *string = NULL;
	    int nc = read_string (pamh, CONV_ECHO_OFF, buf, &string);
	    if (nc < 0)
	      retval = send_string (pamh, ssl, PAM_CONV_ERR, string);
	    else
	      retval = send_string (pamh, ssl, PAM_SUCCESS, string);
	  }
	  break;
	case PROMPT_ECHO_ON:
	  {
	    char *string = NULL;
	    int nc = read_string (pamh, CONV_ECHO_ON, buf, &string);
	    if (nc < 0)
	      retval = send_string (pamh, ssl, PAM_CONV_ERR, string);
	    else
	      retval = send_string (pamh, ssl, PAM_SUCCESS, string);
	  }
	  break;
	case FINISH:
	  if (buf)
	    retval = buf[0];
	  else
	    retval = PAM_SYSTEM_ERR;
	  break;
	default:
	  break;
	}

      if ((resp.type == PROMPT_ECHO_ON || resp.type == PROMPT_ECHO_OFF) &&
	  retval != 0)
	{
	  char err_buf[256];

	  PRINTF (ERR_HANDLE, _("Cannot send input back to server: %s\n"),
		  strerror_r (errno, err_buf, sizeof (err_buf)));
	  free (buf);
	  return PAM_SYSTEM_ERR;
	}
      if (buf)
	{
	  free (buf);
	  buf = NULL;
	}
    }
  while (resp.type != FINISH);

  return retval;
}
#else

static int
handle_responses (pam_handle_t *pamh, SSL *ssl)
{
  response_header resp;
  char retval = PAM_SUCCESS;
  char *buf = NULL;

  do
    {
      errno = 0;
      if (TEMP_FAILURE_RETRY (SSL_read (ssl, &resp, sizeof (resp)))
	  != sizeof (resp))
	{
	  char err_buf[256];

	  if (errno == 0)
	    __write_message (pamh, PAM_ERROR_MSG,
			     _("error while reading request: %s"),
			     _("wrong data received"));
	  else
	    __write_message (pamh, PAM_ERROR_MSG,
			     _("error while reading request: %s"),
			     strerror_r (errno, err_buf, sizeof (err_buf)));
	  return PAM_SYSTEM_ERR;
	}

      if (resp.data_len > 0)
	{
	  if (buf == NULL)
	    {
	      __write_message (pamh, PAM_ERROR_MSG,
			       _("error while allocating memory: %m"));
	      return PAM_SYSTEM_ERR;
	    }

	  if (TEMP_FAILURE_RETRY (SSL_read (ssl, buf, resp.data_len))
	      != resp.data_len)
	    {
	      __write_message (pamh, PAM_ERROR_MSG,
			       _("error while reading request data: %m"));
	      free (buf);
	      return PAM_SYSTEM_ERR;
	    }
	}

      switch (resp.type)
	{
	case TEXT_INFO:
	  if (buf)
	    __write_message (pamh, PAM_TEXT_INFO,
			     "%s\n", buf);
	  break;
	case ERROR_MSG:
	  if (buf)
	    __write_message (pamh, PAM_ERROR_MSG,
			     "%s\n", buf);
	  break;
	case PROMPT_ECHO_OFF:
	  {
	    char *string = NULL;
	    int nc = read_string (pamh, CONV_ECHO_OFF, buf, &string);
	    if (nc < 0)
	      retval = send_string (ssl, PAM_CONV_ERR, string);
	    else
	      retval = send_string (ssl, PAM_SUCCESS, string);
	  }
	  break;
	case PROMPT_ECHO_ON:
	  {
	    char *string = NULL;
	    int nc = read_string (pamh, CONV_ECHO_ON, buf, &string);
	    if (nc < 0)
	      retval = send_string (ssl, PAM_CONV_ERR, string);
	    else
	      retval = send_string (ssl, PAM_SUCCESS, string);
	  }
	  break;
	case FINISH:
	  if (buf)
	    retval = buf[0];
	  else
	    retval = PAM_SYSTEM_ERR;
	  break;
	default:
	  break;
	}

      if ((resp.type == PROMPT_ECHO_ON || resp.type == PROMPT_ECHO_OFF) &&
	  retval != 0)
	{
	  PRINTF (ERR_HANDLE, _("Cannot send input back to server: %m\n"));
	  free (buf);
	  return PAM_SYSTEM_ERR;
	}

      if (buf)
	{
	  free (buf);
	  buf = NULL;
	}
    }
  while (resp.type != FINISH);

  return retval;
}
#endif

static void
parse_option (const char *argv, options_t *options)
{
  if (argv == NULL || argv[0] == '\0')
    return;

  if (strcasecmp (argv, "debug") == 0)
    options->debug = 1;
  else if (strcasecmp (argv, "use_slp=1") == 0)
    options->use_slp = 1;
  else if (strcasecmp (argv, "use_slp=0") == 0)
    options->use_slp = 0;
  else if (strcasecmp (argv, "verbose") == 0)
    options->verbose = 1;
  else if (strcasecmp (argv, "quiet") == 0)
    options->quiet = 1;
  else if (strncasecmp (argv, "reqcert=", 8) == 0)
    options->reqcert = parse_reqcert (&argv[8]);
  else if (strncasecmp (argv, "config_file=", 12) == 0)
    options->config_file = strdup (&argv[12]);
  else if (strncasecmp (argv, "host=", 5) == 0)
    options->host = strdup (&argv[5]);
  else if (strncasecmp (argv, "port=", 5) == 0)
    options->port = strdup (&argv[5]);
  else
    __pam_log (LOG_ERR, "Unknown option: `%s'", argv);
}


static options_t *
get_options (int argc, const char **argv)
{
  options_t *options = calloc (1, sizeof (options_t));

  if (options == NULL)
    return NULL;

  options->reqcert = 3;
  options->config_file = _PATH_RPASSWDCONF;

  /* Parse parameters for module */
  for ( ; argc-- > 0; argv++)
    parse_option (*argv, options);

  if (options->quiet)
    options->verbose = 0;

  return options;
}

PAM_EXTERN int
pam_sm_chauthtok (pam_handle_t *pamh, int flags,
		  int argc, const char **argv)
{
  options_t *options;
  void *user_void;
  char *user;
  int retval;
  int sock;
#ifdef USE_GNUTLS
  gnutls_session session;
  gnutls_certificate_credentials xcred;
#else
  SSL_CTX *ctx;
  SSL *ssl;
#endif
#ifdef USE_SLP
  int used_slp = 0;
#endif

  options = get_options (argc, argv);
  if (options == NULL)
    {
      __pam_log (LOG_ERR, "cannot get options");
      return PAM_BUF_ERR;
    }

  if (options->debug)
    __pam_log (LOG_DEBUG, "pam_sm_chauthtok() called");


  retval = pam_get_item (pamh, PAM_USER, (const void **) &user_void);
  if (retval != PAM_SUCCESS)
    {
      free (options);
      return retval;
    }
  user = (char *) user_void;

  if (user == NULL || strlen (user) == 0)
    {
      if (options->debug)
	__pam_log (LOG_DEBUG, "user (%s) unknown", user ? user : "NULL");
      /* The app is supposed to get us the username! */
      free (options);
      return PAM_USER_UNKNOWN;
    }

  if (flags & PAM_PRELIM_CHECK)
    {
      free (options);
      return PAM_SUCCESS;
    }

  if (options->host)
    {
      if (options->port)
        load_config (options->config_file, NULL, NULL, &options->reqcert);
      else
        load_config (options->config_file, NULL, &options->port,
		     &options->reqcert);
    }
  else if (options->port)
    load_config (options->config_file, &options->host, NULL,
		 &options->reqcert);
  else
    load_config (options->config_file, &options->host,
		 &options->port, &options->reqcert);


#ifdef USE_SLP
  if (options->host == NULL && options->port == NULL &&
      options->use_slp == 1)
    {
      query_slp (pamh, &options->host, &options->port, &options->descr);
      used_slp = 1;
    }
#endif

  if (options->host == NULL)
    {
      PRINTF (ERR_HANDLE, "No server specified\n");
      free (options);
      return PAM_SYSTEM_ERR;
    }

  if (options->port == NULL)
    options->port = "rpasswd";

#ifdef USE_SLP
  if (used_slp)
    {
      if (options->port != NULL && strcmp (options->port, "rpasswd") != 0)
	{
	  if (options->descr)
	    PRINTF (STD_HANDLE, _("SLP: Found Server on %s, port %s (%s)\n"),
		    options->host, options->port, options->descr);
	  else
	    PRINTF (STD_HANDLE, _("SLP: Found Server on %s, port %s\n"),
		    options->host, options->port);
	}
      else
	{
	  if (options->descr)
	    PRINTF (STD_HANDLE, _("SLP: Found Server on %s (%s)\n"),
		    options->host, options->descr);
	  else
	    PRINTF (STD_HANDLE, _("SLP: Found Server on %s\n"),
		    options->host);
	}
    }
#endif

  /* Now we have all the initial information we need from the app to
     set things up (we assume that getting the username succeeded...) */
  sock = connect_to_server (pamh, options->host, options->port,
			    PF_UNSPEC, options->quiet);
  if (sock < 0)
    {
      free (options);
      return PAM_TRY_AGAIN;
    }

  /* Do SSL */
#ifdef USE_GNUTLS
  gnutls_global_init ();
  /* Initialize TLS session. */
  gnutls_init (&session, GNUTLS_CLIENT);
  retval = start_ssl (pamh, sock, options->reqcert, options->verbose,
		      session, &xcred);
#else
  retval = start_ssl (pamh, sock, options->reqcert, options->verbose,
		      &ctx, &ssl);
#endif

  if (retval != 0)
    {
      free (options);
      return PAM_SYSTEM_ERR;
    }

#ifdef USE_GNUTLS
  if ((retval = start_request (pamh, session, user, 0)) == 0)
    retval = handle_responses (pamh, session);
  else
    retval = PAM_SYSTEM_ERR;
#else
  if ((retval = start_request (ssl, user, 0)) == 0)
    retval = handle_responses (pamh, ssl);
  else
    retval = PAM_SYSTEM_ERR;
#endif

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

  free (options);

  return retval;
}
