/* Copyright (C) 2002-2006, 2008, 2009 Thorsten Kukuk
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

#include <getopt.h>
#include <error.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <syslog.h>
#include <signal.h>
#include <string.h>

#ifdef USE_GNUTLS
#include <gnutls/gnutls.h>
#else
#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include "i18n.h"
#include "dbg_log.h"
#include "use_slp.h"
#include "logindefs.h"
#include "error_codes.h"
#include "rpasswd-client.h"

#if !defined(IPV6_V6ONLY) && defined(__linux__)
#define IPV6_V6ONLY   26
#endif

/* Path of the file where the PID of the running system is stored.  */
#define _PATH_RPASSWDDPID    "/var/run/rpasswdd.pid"

extern int setresuid(uid_t ruid, uid_t euid, uid_t suid);

/* XXX This variable should not be global.  */
#ifdef USE_GNUTLS
/* XXX */
#else
static SSL_CTX *ctx;
#endif
/* Socket for incoming connections.  */
static struct pollfd pollfd_conn[10];
static int pollfd_cnt = 0;
#ifdef USE_SLP
/* register/deregister at SLP server.  */
static int use_slp = 0;
#endif

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
print_usage (FILE *stream, const char *program)
{
#ifdef USE_SLP
  fprintf (stream, _("Usage: %s [-4] [-6] [-d] [-c certificate] [-k privatekey] [-p port]\n       [--slp [--slp-timeout timeout] [--slp-descr description]]\n"),
	   program);
#else
  fprintf (stream, _("Usage: %s [-4] [-6] [-d] [-c certificate] [-k privatekey] [-p port]\n"),
	   program);
#endif
}

static void
print_help (const char *program)
{
  print_usage (stdout, program);
  fprintf (stdout, _("%s - change password information\n\n"), program);

  fputs (_("  -4             Use IPv4\n"), stdout);
  fputs (_("  -6             Use IPv6\n"), stdout);
  fputs (_("  -c certificate Specify alternate certificate file\n"), stdout);
  fputs (_("  -k privatekey  Specify alternate file with private key\n"),
	 stdout);
  fputs (_("  -d             Run in debug mode\n"), stdout);
  fputs (_("  -p port        Port on which the server should listen\n"),
	 stdout);
#ifdef USE_SLP
  fputs (_("  --slp          Register at local SLP server\n"), stdout);
  fputs (_("  --slp-timeout  Set timeout for re-registration\n"), stdout);
  fputs (_("  --slp-descr    Set a description shown to SLP clients\n"),
	 stdout);
#endif
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

/* Returns 1 if the process in pid file FILE is running, 0 if not.  */
static int
check_pid (const char *file)
{
  FILE *fp;

  fp = fopen (file, "r");
  if (fp)
    {
      pid_t pid;
      int n;

      n = fscanf (fp, "%d", &pid);
      fclose (fp);

      if (n != 1 || kill (pid, 0) == 0)
        return 1;
    }

  return 0;
}

/* Write the current process id to the pid file.
   Returns 0 if successful, -1 if not.  */
static int
write_pid (const char *file)
{
  FILE *fp;

  fp = fopen (file, "w");
  if (fp == NULL)
    return -1;

  fprintf (fp, "%d\n", getpid ());
  if (fflush (fp) || ferror (fp))
    return -1;

  fclose (fp);

  return 0;
}

/************************************************************************
*************************************************************************
***                                                                   ***
*** Here is now the connection handling part                          ***
***                                                                   ***
*************************************************************************
************************************************************************/

/* Initialize database information structures.  */
static void
server_init (int port, int ipv4, int ipv6)
{
  int have_usagi = 1; /* Assume we have a USAGI patched kernel.  */

  /* The Linux kernel without USAGI patch will handle IPv4 connections
     over an existing IPv6 binding. So we cannot bind explicit a IPv6
     and a IPv4 socket. We use only a IPv6 socket in this case.  */

  if (ipv6)
    {
      struct sockaddr_in6 sock_addr;
      int on = 1;

      /* Create the socket.  */
      pollfd_conn[pollfd_cnt].fd = socket (AF_INET6, SOCK_STREAM, 0);
      if (pollfd_conn[pollfd_cnt].fd < 0)
	{
	  dbg_log ("cannot open socket: %s", strerror (errno));
	  exit (1);
	}

#ifdef IPV6_V6ONLY
      /* we try to bind to IPv6 only and to bind a second socket
	 for IPv4. If the IPV6_V6ONLY option failed, we assume IPv6
	 will also handle IPv4 addresses.  */

      if (setsockopt (pollfd_conn[pollfd_cnt].fd, IPPROTO_IPV6, IPV6_V6ONLY,
		      (char *)&on, sizeof (on)) <0)
	{
	  if (errno != ENOPROTOOPT)
	    dbg_log ("setsockopt (IPPROTO_IPV6, IPV6_V6ONLY): %m");
	  have_usagi = 0;
	}
#endif

      memset (&sock_addr, '\0', sizeof (sock_addr));
      sock_addr.sin6_family = AF_INET6;
      sock_addr.sin6_addr = in6addr_any;
      sock_addr.sin6_port = port;

      if (bind (pollfd_conn[pollfd_cnt].fd, (struct sockaddr *) &sock_addr,
		sizeof (sock_addr)) < 0)
	{
	  dbg_log ("bind: %s", strerror (errno));
	  exit (1);
	}

      /* Set the socket up to accept connections.  */
      if (listen (pollfd_conn[pollfd_cnt].fd, SOMAXCONN) < 0)
	{
	  dbg_log ("cannot enable socket to accept connections: %s",
		   strerror (errno));
	  exit (1);
	}
      ++pollfd_cnt;
    }

  if (ipv4 && (!ipv6 || have_usagi))
    {
      struct sockaddr_in sock_addr;

      /* Create the socket.  */
      pollfd_conn[pollfd_cnt].fd = socket (AF_INET, SOCK_STREAM, 0);
      if (pollfd_conn[pollfd_cnt].fd < 0)
	{
	  dbg_log ("cannot open socket: %s", strerror (errno));
	  exit (1);
	}

      memset (&sock_addr, '\0', sizeof (sock_addr));
      sock_addr.sin_family = AF_INET;
      sock_addr.sin_addr.s_addr = INADDR_ANY;
      sock_addr.sin_port = port;

      if (bind (pollfd_conn[pollfd_cnt].fd, (struct sockaddr *) &sock_addr,
		sizeof (sock_addr)) < 0)
	{
	  dbg_log ("bind: %s", strerror (errno));
	  exit (1);
	}

      /* Set the socket up to accept connections.  */
      if (listen (pollfd_conn[pollfd_cnt].fd, SOMAXCONN) < 0)
	{
	  dbg_log ("cannot enable socket to accept connections: %s",
		   strerror (errno));
	  exit (1);
	}
      ++pollfd_cnt;
    }
}

/* Close the connections.  */
static void
close_sockets (void)
{
  int i;

  for (i = 0; i < pollfd_cnt; i++)
    if (pollfd_conn[i].fd >= 0)
      close (pollfd_conn[i].fd);
}

#ifdef USE_GNUTLS
static int
send_string (gnutls_session ssl, response_type type, const char *str)
{
  response_header resp;
  ssize_t err_code;

  resp.type = type;
  resp.data_len = strlen (str) + 1;
  if ((err_code = gnutls_record_send (ssl, &resp, sizeof (resp))) <= 0)
    {
      dbg_log ("%s:%d gnutls_record_send failed: %s",
	       __FILE__, __LINE__, gnutls_strerror (err_code));
      return -1;
    }
  if ((err_code = gnutls_record_send (ssl, str, resp.data_len)) <= 0)
    {
      dbg_log ("%s:%d gnutls_record_send failed: %s", __FILE__, __LINE__,
	       gnutls_strerror (err_code));
      return -1;
    }

  return 0;
}


static ssize_t
safe_read (gnutls_session ssl, void *data, size_t count, int timeout)
{
  struct pollfd conn;
  void *sock;

  sock = gnutls_transport_get_ptr (ssl);
  conn.fd = (long) sock;
  conn.events = POLLRDNORM;

  errno = 0;

  while (1)
    {
      int nr = poll (&conn, 1, timeout * 1000);

      if (nr < 0)
        {
	  /* Don't print error messages if poll is only interupted
	     by a signal.  */
	  if (errno != EINTR)
	    dbg_log ("poll() failed: %s", strerror (errno));
          continue;
        }
      else if (nr == 0)
	{
	  /* XXX TIMEOUT */
	  errno = ETIME;
	  return -1;
	}
      else
	break;
    }

  /* We have new incoming data.  */
  if (conn.revents & (POLLRDNORM|POLLERR|POLLHUP|POLLNVAL))
    {
      if (gnutls_record_recv (ssl, data, count) <= 0)
	return -1;
      else
	return count;
    }
  else
    {
      /* I don't know if this can ever happen.  */
      errno = EAGAIN;
      return -1;
    }
}

#else

static int
send_string (SSL *ssl, response_type type, const char *str)
{
  response_header resp;

  resp.type = type;
  resp.data_len = strlen (str) + 1;
  if (TEMP_FAILURE_RETRY(SSL_write (ssl, &resp, sizeof (resp)))
      != sizeof (resp))
    return -1;
  if (TEMP_FAILURE_RETRY(SSL_write (ssl, str, resp.data_len))
      != resp.data_len)
    return -1;

  return 0;
}

static ssize_t
safe_read (SSL *ssl, void *data, size_t count, int timeout)
{
  struct pollfd conn;

  conn.fd = SSL_get_fd (ssl);
  conn.events = POLLRDNORM;

  errno = 0;

  while (1)
    {
      int nr = poll (&conn, 1, timeout * 1000);

      if (nr < 0)
        {
	  /* Don't print error messages if poll is only interupted
	     by a signal.  */
	  if (errno != EINTR)
	    dbg_log ("poll() failed: %s", strerror (errno));
          continue;
        }
      else if (nr == 0)
	{
	  /* XXX TIMEOUT */
	  errno = ETIME;
	  return -1;
	}
      else
	break;
    }

  /* We have new incoming data.  */
  if (conn.revents & (POLLRDNORM|POLLERR|POLLHUP|POLLNVAL))
    return TEMP_FAILURE_RETRY (SSL_read (ssl, data, count));
  else
    {
      /* I don't know if this can ever happen.  */
      errno = EAGAIN;
      return -1;
    }
}
#endif

static int
#ifdef USE_GNUTLS
read_string (gnutls_session ssl, char **retstr)
#else
read_string (SSL *ssl, char **retstr)
#endif
{
  conv_header resp;
  *retstr = NULL;

  errno = 0;
  if (safe_read (ssl, &resp, sizeof (resp), 120) != sizeof (resp))
    {
      char err_buf[256];

      if (errno == 0)
	dbg_log ("error while reading request: %s",
		 "wrong data received");
      else
	dbg_log ("error while reading request: %s",
		 strerror_r (errno, err_buf, sizeof (err_buf)));
      return PAM_CONV_ERR;
    }

  /* 1024 bytes data should be enough. Don't allow more to avoid
     DOS attacks.  */
  if (resp.data_len > 0 && resp.data_len <= 1024)
    {
      char *buf = alloca (resp.data_len + 1);

      if (safe_read (ssl, buf, resp.data_len, 120) != resp.data_len)
	{
	  char err_buf[256];

	  if (errno == 0)
	    dbg_log ("error while reading request data: %s",
		     "wrong data received");
	  else
	    dbg_log ("error while reading request data: %s",
		     strerror_r (errno, err_buf, sizeof (err_buf)));
	  return PAM_CONV_ERR;
	}
      buf[resp.data_len] = '\0';
      *retstr = strdup (buf);
    }
  else
    return PAM_CONV_ERR;

  return resp.retval;
}

static int
rpasswd_conv(int num_msg, const struct pam_message **msgm,
	     struct pam_response **response, void *appdata_ptr)
{
  int count=0;
  struct pam_response *reply;
#ifdef USE_GNUTLS
  gnutls_session ssl = appdata_ptr;
#else
  SSL *ssl = appdata_ptr;
#endif

  if (num_msg <= 0)
    return PAM_CONV_ERR;

  D(("allocating empty response structure array."));

  reply = (struct pam_response *) calloc(num_msg,
					 sizeof(struct pam_response));
  if (reply == NULL) {
    D(("no memory for responses"));
    return PAM_CONV_ERR;
  }

  D(("entering conversation function."));

  for (count = 0; count < num_msg; ++count)
    {
      char *string = NULL;

      switch (msgm[count]->msg_style)
	{
        case PAM_PROMPT_ECHO_OFF:
	  D(("PAM_PROMPT_ECHO_OFF"));
	  if (send_string (ssl, PROMPT_ECHO_OFF, msgm[count]->msg) != 0)
	    goto failed_conversation;
	  if (read_string (ssl, &string) != PAM_SUCCESS)
	    goto failed_conversation;
	  break;
        case PAM_PROMPT_ECHO_ON:
	  D(("PAM_PROMPT_ECHO_ON"));
	  if (send_string (ssl, PROMPT_ECHO_OFF, msgm[count]->msg) != 0)
	    goto failed_conversation;
	  if (read_string (ssl, &string) != PAM_SUCCESS)
	    goto failed_conversation;
	  break;
        case PAM_ERROR_MSG:
	  D(("PAM_ERROR_MSG"));
	  if (send_string (ssl, ERROR_MSG, msgm[count]->msg) != 0)
	    goto failed_conversation;
	  break;
        case PAM_TEXT_INFO:
	  D(("PAM_TEXT_INFO"));
	  if (send_string (ssl, TEXT_INFO, msgm[count]->msg) != 0)
	    goto failed_conversation;
	  break;
        default:
	  /* send_string (ssl, TEXT_INFO, _("erroneous conversation (%d)")
	     ,msgm[count]->msg_style); */
	  goto failed_conversation;
        }

      if (string) {                         /* must add to reply array */
	/* add string to list of responses */

	reply[count].resp_retcode = 0;
	reply[count].resp = string;
	string = NULL;
      }
    }

  /* New (0.59+) behavior is to always have a reply - this is
     compatable with the X/Open (March 1997) spec. */
  *response = reply;
  reply = NULL;

  return PAM_SUCCESS;

failed_conversation:

    if (reply) {
        for (count=0; count<num_msg; ++count) {
            if (reply[count].resp == NULL) {
                continue;
            }
            switch (msgm[count]->msg_style) {
            case PAM_PROMPT_ECHO_ON:
            case PAM_PROMPT_ECHO_OFF:
                _pam_overwrite(reply[count].resp);
                free(reply[count].resp);
                break;
            case PAM_ERROR_MSG:
            case PAM_TEXT_INFO:
                /* should not actually be able to get here... */
                free(reply[count].resp);
            }
            reply[count].resp = NULL;
        }
        /* forget reply too */
        free(reply);
        reply = NULL;
    }

    return PAM_CONV_ERR;
}

/* Sanity check on locale string.
   Otherwise local lusers may be tempted to send us
   a locale of "../../../../../tmp" and deposit a
   message catalog there containing format strings with
   lots of %n's in them.  */
static int
sane_locale (const char *name)
{
  if (!name)
    return 0;
  if (strchr (name, '/'))
    return 0;
  if (strstr (name, ".."))
    return 0;
  /* Any other checks? */
  return 1;
}

/* Handle new request.  */
static int
#ifdef USE_GNUTLS
handle_request (gnutls_session ssl, request_header *req, char *locale,
		const char *username, const char * program)
#else
handle_request (SSL *ssl, request_header *req, char *locale,
		const char *username, const char *program)
#endif
{
  const struct pam_conv conv = {
    rpasswd_conv,
    ssl
  };
  pam_handle_t *pamh = NULL;
  int flags = 0, ret;
  int retval = E_SUCCESS;
  int pw_buflen = 256;
  char *pw_buffer = alloca (pw_buflen);
  struct passwd pw_resultbuf;
  struct passwd *pw = NULL;

  if (debug_level > 0)
    dbg_log ("handle_request: request received (Version = %d)",
             req->version);

  if (req->version != RPASSWD_VERSION)
    {
      if (debug_level > 0)
        dbg_log ("cannot handle request version %d; current version is %d",
                 req->version, RPASSWD_VERSION);
      retval = E_WRONG_VERSION;
      goto send_finish;
    }

#ifdef ENABLE_NLS
  if (locale && sane_locale(locale))
    setlocale (LC_ALL, locale);
#endif

  /* Get password file entry... */
  while (getpwnam_r (username, &pw_resultbuf, pw_buffer, pw_buflen, &pw) != 0
         && errno == ERANGE)
    {
      errno = 0;
      pw_buflen += 256;
      pw_buffer = alloca (pw_buflen);
    }
  if (pw == NULL && req->request != START_ADMIN)
    {
      dbg_log ("passwd entry for \"%s\" not found", username);
      /* Dummy authentication. So the user will not see that this
	 account does not exist.  */
      ret = pam_start ("rpasswd", username, &conv, &pamh);
      if (ret != PAM_SUCCESS)
	{
	  retval = E_PAM_ERROR;
	  goto send_finish;
	}
      /* We are not interested in the return value, we always assume
	 a failed.  */
      pam_authenticate (pamh, flags);
      pam_end (pamh, PAM_SUCCESS);
      /* after using PAM we have to reset openlog data */
      openlog (program, LOG_CONS | LOG_ODELAY, LOG_DAEMON);
      sleep (getlogindefs_num ("FAIL_DELAY", 1));
      send_string (ssl, ERROR_MSG, "Authentication failure");
      retval = E_FAILURE;
      goto send_finish;
    }

  /* Do extra authentication if run in admin mode or the passwort
     for root should be changed.  */
  if (req->request == START_ADMIN || (pw && pw->pw_uid == 0))
    {
      const char *account;

      if (req->request == START_ADMIN)
	account = "root";
      else
	account = username;

      /* Do PAM authentification at first.  */
      ret = pam_start ("rpasswd", account, &conv, &pamh);
      if (ret != PAM_SUCCESS)
	{
	  /* after using PAM we have to reset openlog data */
	  openlog (program, LOG_CONS | LOG_ODELAY, LOG_DAEMON);
	  dbg_log ("Couldn't initialize PAM: %s", pam_strerror (pamh, ret));
	  retval = E_PAM_ERROR;
	  goto send_finish;
	}
      else if (req->request == START_ADMIN)
	{ /* print the message only in admin mode.  */
	  char host[MAXHOSTNAMELEN+1];
	  char *cp;

	  gethostname (host, sizeof (host));
	  if (asprintf (&cp, _("Please authenticate as %s on %s"),
			account, host) < 0)
	    {
	      retval = E_FAILURE;
	      goto send_finish;
	    }

	  send_string (ssl, TEXT_INFO, cp);
	  free (cp);
	}

      ret = pam_authenticate (pamh, flags);
      if (ret != PAM_SUCCESS)
	{
	  pam_end (pamh, ret);
	  /* after using PAM we have to reset openlog data */
	  openlog (program, LOG_CONS | LOG_ODELAY, LOG_DAEMON);
	  dbg_log ("User %s: %s", account,
		   pam_strerror (pamh, ret));
	  sleep (getlogindefs_num ("FAIL_DELAY", 1));
	  send_string (ssl, ERROR_MSG, pam_strerror (pamh, ret));
	  retval = E_FAILURE;
	  goto send_finish;
	}
      pam_end (pamh, PAM_SUCCESS);
      /* after using PAM we have to reset openlog data */
      openlog (program, LOG_CONS | LOG_ODELAY, LOG_DAEMON);

      if (req->request == START_ADMIN)
	{ /* In Admin mode send info text what we are now doing.  */
	  char *cp;

	  if (pw == NULL) /* Now send error message for admin.  */
	    {
	      dbg_log ("passwd entry for \"%s\" not found", username);
	      retval = E_UNKNOWN_USER;
	      goto send_finish;
	    }

	  if (asprintf (&cp, _("\nNow enter the new password for %s"),
			username) < 0)
	    {
	      retval = E_FAILURE;
	      goto send_finish;
	    }
	  send_string (ssl, TEXT_INFO, cp);
	  free (cp);
	}
    }
  else /* (req->request != START_ADMIN)  */
    {
      /* Set the real uid to the one of the user for which we wish to
	 change the password and let the effective and saved uid to be
	 root. With this, most PAM modules thinks they are called from
	 a setuid root passwd program. Not needed if we run in Admin mode.
	 In this case, PAM moduls should think passwd is called by root.  */
      if (setresuid (pw->pw_uid, 0, 0) == -1)
	{
	  char *cp;

	  if (asprintf (&cp, _("setresuid failed on server: %s"),
			strerror (errno)) > 0)
	    {
	      dbg_log (cp);
	      send_string (ssl, ERROR_MSG, cp);
	      free (cp);
	    }
	  retval = E_FAILURE;
	  goto send_finish;
	}
    }

  ret = pam_start ("rpasswd", username, &conv, &pamh);
  if (ret != PAM_SUCCESS)
    {
      /* after using PAM we have to reset openlog data */
      openlog (program, LOG_CONS | LOG_ODELAY, LOG_DAEMON);
      dbg_log ("Couldn't initialize PAM: %s", pam_strerror (pamh, ret));
      retval = E_PAM_ERROR;
      goto send_finish;
    }


  ret = pam_chauthtok (pamh, flags);
  if (ret != PAM_SUCCESS)
    {
      pam_end (pamh, ret);
      /* after using PAM we have to reset openlog data */
      openlog (program, LOG_CONS | LOG_ODELAY, LOG_DAEMON);
      dbg_log ("User %s: %s", username,
	       pam_strerror (pamh, ret));
      sleep (getlogindefs_num ("FAIL_DELAY", 1));
      send_string (ssl, ERROR_MSG, pam_strerror (pamh, ret));
      retval = E_FAILURE;
      goto send_finish;
    }

  pam_end (pamh, PAM_SUCCESS);

  /* after using PAM we have to reset openlog data */
  openlog (program, LOG_CONS | LOG_ODELAY, LOG_DAEMON);

  if (retval)
    send_string (ssl, TEXT_INFO, _("Password not changed"));
#if 0
  else
    send_string (ssl, TEXT_INFO, _("Password changed"));
#endif

 send_finish:
  {
    response_header resp;

    resp.type = FINISH;
    resp.data_len = 1;
#ifdef USE_GNUTLS
    gnutls_record_send (ssl, &resp, sizeof (resp));
    gnutls_record_send (ssl, &retval, resp.data_len);
#else
    SSL_write (ssl, &resp, sizeof (resp));
    SSL_write (ssl, &retval, resp.data_len);
#endif
  }

  if (debug_level > 0)
    dbg_log ("handle_request: exit (%d)", retval);
  return retval;
}

#ifdef USE_GNUTLS
/* These are global */
static gnutls_certificate_credentials x509_cred;

static gnutls_session
initialize_gnutls_session (const char *certificate, const char *privatekey)
{
  gnutls_session session;

  gnutls_certificate_allocate_credentials (&x509_cred);
#if 0 /* XXX */
  gnutls_certificate_set_x509_trust_file (x509_cred, certificate,
					  GNUTLS_X509_FMT_PEM);

  gnutls_certificate_set_x509_crl_file (x509_cred, CRLFILE,
					GNUTLS_X509_FMT_PEM);
#endif
  gnutls_certificate_set_x509_key_file (x509_cred, certificate, privatekey,
					GNUTLS_X509_FMT_PEM);

  gnutls_init (&session, GNUTLS_SERVER);

  gnutls_set_default_priority (session);
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);

  /* XXX gnutls_certificate_server_set_request (session, GNUTLS_CERT_REQUEST);
     gnutls_dh_set_prime_bits (session, DH_BITS);

     generate_dh_params();

     gnutls_certificate_set_dh_params( x509_cred, dh_params); */

  return session;
}
#endif

/* This is the main loop.  It can be replicated in different threads but the
   `poll' call makes sure only one thread handles an incoming connection.  */
static void
#ifdef USE_GNUTLS
server_run (const char *certificate, const char *privatekey,
	    const char *program)
#else
server_run (const char *program)
#endif
{
  int i;

  for (i = 0; i < pollfd_cnt; i++)
    pollfd_conn[i].events = POLLRDNORM;

  while (1)
    {
      int nr;

      nr = poll (pollfd_conn, pollfd_cnt, -1);

      if (nr < 0)
        {
	  /* Don't print error messages if poll is only interupted
	     by a signal.  */
	  if (errno != EINTR)
	    dbg_log ("poll() failed: %s", strerror (errno));
          continue;
        }

      /* We have a new incoming connection. Look at which socket.  */
      for (i = 0; i < pollfd_cnt; i++)
	{
	  if (pollfd_conn[i].revents & (POLLRDNORM|POLLERR|POLLHUP|POLLNVAL))
	    {
	      /* Accept the connection.  */
	      int ssl_err;
	      long fd;
	      request_header req;
	      char buf[256];
	      char *locale, *username;
#ifdef USE_GNUTLS
	      gnutls_session ssl;
#else
	      SSL *ssl;
#endif

	      fd = accept (pollfd_conn[i].fd, NULL, NULL);
	      if (fd < 0)
		{
		  dbg_log ("while accepting connection: %s",
			   strerror_r (errno, buf, sizeof (buf)));
		  continue;
		}
	      /* TCP connection is ready. Do server side SSL. */
#ifdef USE_GNUTLS
	      ssl = initialize_gnutls_session (certificate, privatekey);
	      gnutls_transport_set_ptr (ssl, (gnutls_transport_ptr)fd);
	      ssl_err = gnutls_handshake (ssl);
	      if (ssl_err < 0)
		{
		  close (fd);
		  gnutls_deinit (ssl);
		  dbg_log ("Handshake has failed (%s)",
			   gnutls_strerror (ssl_err));
		  continue;
		}

	      /* see the Getting peer's information example */
	      /* print_info(session); */
	      /* XXX print cipher info and check client
		 certificate */

	      if ((ssl_err = gnutls_record_recv (ssl, &req, sizeof (req))) <= 0)
		{
		  if (debug_level > 0)
		    {
		      if (ssl_err == 0)
			dbg_log ("error while reading request: %s",
				 "client has closed the GNUTLS connection");
		      else
			dbg_log ("error while reading request: %s",
				 gnutls_strerror (ssl_err));
		    }
		  gnutls_deinit (ssl);
		  close (fd);
		  continue;
		}
#else
	      ssl = SSL_new (ctx);
	      if (ssl == NULL)
		{
		  dbg_log ("cannot enable SSL encryption");
		  close (fd);
		  continue;
		}
	      SSL_set_fd (ssl, fd);
	      ssl_err = SSL_accept (ssl);
	      if (ssl_err < 1)
		{
		  dbg_log ("SSL_accept: %s", ERR_error_string (ssl_err, NULL));
		  close (fd);
		  continue;
		}

	      /* Get the cipher - opt */
	      if (debug_level > 0)
		dbg_log ("SSL connection using %s", SSL_get_cipher (ssl));

#if 0
	      /* Get client's certificate (note: beware of dynamic
		 allocation) - opt */

	      client_cert = SSL_get_peer_certificate (ssl);
	      if (client_cert != NULL)
		{
		  printf ("Client certificate:\n");

		  str = X509_NAME_oneline (X509_get_subject_name (client_cert),
					   0, 0);
		  CHK_NULL(str);
		  printf ("\t subject: %s\n", str);
		  free (str);

		  str = X509_NAME_oneline (X509_get_issuer_name (client_cert),
					   0, 0);
		  CHK_NULL(str);
		  printf ("\t issuer: %s\n", str);
		  free (str);

		  /* We could do all sorts of certificate verification
		     stuff here before deallocating the certificate. */
		  X509_free (client_cert);
		}
	      else
		printf ("Client does not have certificate.\n");
#endif
	      /* Now read the request.  */
	      errno = 0;
	      if (TEMP_FAILURE_RETRY (SSL_read (ssl, &req, sizeof (req)))
		  != sizeof (req))
		{
		  if (debug_level > 0)
		    {
		      if (errno == 0)
			dbg_log ("error while reading request: %s",
				 "wrong data received");
		      else
			dbg_log ("error while reading request: %s",
				 strerror_r (errno, buf, sizeof (buf)));
		    }
		  close (fd);
		  continue;
		}
#endif

	      /* It should not be possible to crash the rpasswdd with
		 a silly request (i.e., a terribly large key). We limit
		 the size to 1kb for locale and username.  */
	      if (req.locale_len < 0 || req.locale_len > 1024)
		{
		  if (debug_level > 0)
		    dbg_log ("locale length in request too long: %d",
			     req.locale_len);
		  continue;
		}
	      else if (req.locale_len > 0)
		{
		  /* Get the locale.  */
		  char localebuf[req.locale_len + 1];

		  if (safe_read (ssl, localebuf, req.locale_len, 1)
		      != req.locale_len)
		    {
		      if (debug_level > 0)
			{
			  char err_buf[256];

			  if (errno == 0)
			    dbg_log ("error while reading request locale: %s",
				     "wrong data received");
			  else
			    dbg_log ("error while reading request locale: %s",
				     strerror_r (errno, err_buf,
						 sizeof (err_buf)));
			}
		      continue;
		    }
		  /* Don't assume the string is NUL-terminated */
		  localebuf[req.locale_len] = '\0';
		  if ((locale = strdup (localebuf)) == NULL)
		    {
		      dbg_log ("running out of memory!");
		      continue;
		    }
		}
	      else
		locale = NULL;

	      if (req.data_len < 0 || req.data_len > 1024)
		{
		  if (debug_level > 0)
		    dbg_log ("data length in request too long: %d",
			     req.data_len);
		  if (locale)
		    free (locale);
		  continue;
		}
	      else if (req.data_len > 0)
		{
		  /* Get the data.  */
		  char databuf[req.data_len + 1];

		  if (safe_read (ssl, databuf, req.data_len, 1)
		      != req.data_len)
		    {
		      if (debug_level > 0)
			{
			  char err_buf[256];

			  if (errno == 0)
			    dbg_log ("error while reading request username: %s",
				     "wrong data received");
			  else
			    dbg_log ("error while reading request username: %s",
				     strerror_r (errno, err_buf,
						 sizeof (err_buf)));
			}
		      if (locale)
			free (locale);
		      continue;
		    }
		  /* Don't assume the string is NUL-terminated */
		  databuf[req.data_len] = '\0';
		  if ((username = strdup (databuf)) == NULL)
		    {
		      dbg_log ("running out of memory!");
		      if (locale)
			free (locale);
		      continue;
		    }
		}
	      else
		{
		  dbg_log ("No username supplied");
		  if (locale)
		    free (locale);
		  continue;
		}


	      /* To avoid a DoS attack, fork at first and let the child
		 handle the request.  */
	      switch (fork ())
		{
		case 0:
		  /* Child: get all the data and process it.  */
		  {
		    int ret = handle_request (ssl, &req, locale, username,
					      program);

		    close (fd);
		    exit (ret);
		    }
		  break;
		case -1:
		  {
		    char *cp;

		    if (asprintf (&cp, "fork: %s", strerror (errno)) > 0)
		      {
			dbg_log (cp);
			send_string (ssl, ERROR_MSG, cp);
			free (cp);
#ifdef USE_GNUTLS
			/* do not wait for the peer to close the connection.  */
			gnutls_bye (ssl, GNUTLS_SHUT_WR);
			close (fd);
			gnutls_deinit (ssl);
#else
			close (fd);
			SSL_free (ssl);
#endif
			if (locale)
			  free (locale);
			free (username);
		      }
		  }
		  break;
		default:
		  /* Parent: we are done.  */
#ifdef USE_GNUTLS
		  /* do not wait for the peer to close the connection.  */
		  gnutls_bye (ssl, GNUTLS_SHUT_WR);
		  close (fd);
		  gnutls_deinit (ssl);
#else
		  close (fd);
		  SSL_free (ssl);
#endif
		  if (locale)
		    free (locale);
		  free (username);
		}
	    }
	}
    }
}


/* Cleanup.  */
static void
termination_handler (int sig __attribute__ ((unused)))
{
  close_sockets ();

#ifdef USE_SLP
  /* Remove from local SLP server.  */
  if (use_slp)
    deregister_slp ();
#endif

  /* Clean up pid file.  */
  unlink (_PATH_RPASSWDDPID);

  exit (EXIT_SUCCESS);
}

/* Make sure there are no zombies left.  */
static void
sig_child (int sig __attribute__ ((unused)))
{
  int st;

  /* Clear all childs */
  while (waitpid(-1, &st, WNOHANG) > 0)
    ;
}

static void
init_limits (void)
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
}

int
main (int argc, char **argv)
{
  /* ipv4 and/or ipv6 binding.  */
  int ipv4 = 0;
  int ipv6 = 0;
  int go_background = 1;
  const char *program = "rpasswdd";
  char *certificate = "/etc/rpasswdd.pem";
  char *privatekey = "/etc/rpasswdd.pem";
  int port = -1;
#ifdef USE_SLP
  int slp_timeout = 3600;
  char *slp_descr = NULL;
#endif
#ifndef USE_GNUTLS
  SSL_METHOD *meth;
#endif

#ifdef ENABLE_NLS
  /* Set locale via LC_ALL.  */
  setlocale (LC_ALL, "C");
  /* Set the text message domain.  */
  textdomain (PACKAGE);
#endif

  /* Parse program arguments */
  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
        {
	  {"port",     required_argument, NULL, 'p'},
	  {"debug",    no_argument,       NULL, 'd'},
	  {"ipv4",     no_argument,       NULL, '4'},
	  {"ipv6",     no_argument,       NULL, '6'},
	  {"certificate", required_argument, NULL, 'c'},
	  {"privatekey",  required_argument, NULL, 'k'},
	  {"slp-descr",   required_argument, NULL, '\250'},
	  {"slp-timeout", required_argument, NULL, '\251'},
	  {"slp",      no_argument,       NULL, '\252'},
          {"version",  no_argument,       NULL, '\255'},
          {"usage",    no_argument,       NULL, '\254'},
          {"help",     no_argument,       NULL, '\253'},
          {NULL,       0,                 NULL, '\0'}
        };

      c = getopt_long (argc, argv, "46c:dk:p:", long_options,
                       &option_index);
      if (c == EOF)
        break;
      switch (c)
        {
	case '4':
	  ipv4 = 1;
	  break;
	case '6':
	  ipv6 = 1;
	  break;
	case 'c':
	  certificate = optarg;
	  break;
	case 'k':
	  privatekey = optarg;
	  break;
	case 'd':
	  ++debug_level;
	  go_background = 0;
	  break;
	case 'p':
	  port = htons (atol (optarg));
	  break;
#ifdef USE_SLP
	case '\250':
	  slp_descr = optarg;
	  break;
	case '\251':
	  slp_timeout = atol (optarg);
	  break;
	case '\252':
	  use_slp = 1;
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

  if (argc != 0)
    {
      fprintf (stderr, _("%s: Too many arguments.\n"), program);
      print_error (program);
      return E_USAGE;
    }

  if (ipv4 == 0 && ipv6 == 0)
    ipv4 = ipv6 = 1;

  /* Check if we are already running. */
  if (check_pid (_PATH_RPASSWDDPID))
    error (EXIT_FAILURE, 0, _("already running"));

#ifdef USE_GNUTLS

  /* this must be called once in the program.  */
  gnutls_global_init ();

#else
  /* Initialize SSL data. We need to do this before we go in
     background, else we cannot read the PEM phass phrase.  */
  SSL_load_error_strings ();
  SSLeay_add_ssl_algorithms ();
  meth = SSLv23_server_method ();
  ctx = SSL_CTX_new (meth);
  if (!ctx)
    {
      dbg_log (ERR_error_string (ERR_get_error (), NULL));
      return E_SSL_FAILURE;
    }

  if (SSL_CTX_use_certificate_file (ctx, certificate, SSL_FILETYPE_PEM) <= 0)
    {
      dbg_log ("Loading certificate (%s): %s", certificate,
	       ERR_error_string (ERR_get_error (), NULL));
      return E_SSL_FAILURE;
    }
  if (SSL_CTX_use_PrivateKey_file (ctx, privatekey, SSL_FILETYPE_PEM) <= 0)
    {
      dbg_log ("Loading privatekey (%s): %s", privatekey,
	       ERR_error_string (ERR_get_error (), NULL));
      return E_SSL_FAILURE;
    }

  if (!SSL_CTX_check_private_key (ctx))
    {
      dbg_log (ERR_error_string (ERR_get_error (), NULL));
      return E_SSL_FAILURE;
    }
#endif

  /* Behave like a daemon.  */
  if (go_background)
    {
      int i;

      if (fork ())
        exit (0);

      for (i = 0; i < getdtablesize (); i++)
        close (i);

      if (fork ())
        exit (0);

      setsid ();

      if (chdir ("/") < 0)
	dbg_log ("chdir(\"/\") failed: %s", strerror (errno));

      openlog (program, LOG_CONS | LOG_ODELAY, LOG_DAEMON);

      if (write_pid (_PATH_RPASSWDDPID) < 0)
        dbg_log ("%s: %s", _PATH_RPASSWDDPID, strerror (errno));

      /* Ignore job control signals.  */
      signal (SIGTTOU, SIG_IGN);
      signal (SIGTTIN, SIG_IGN);
      signal (SIGTSTP, SIG_IGN);
    }

  /* Install sig child handler to get ride of zombies.  */
  signal (SIGCHLD, sig_child);
  /* Ignore "File size limit exceeded" signals.  */
  signal (SIGXFSZ, SIG_IGN);
  /* We don't support SIGHUP yet.  */
  signal (SIGHUP, SIG_IGN);
  signal (SIGINT,  termination_handler);
  signal (SIGPIPE, SIG_IGN);
  signal (SIGQUIT, termination_handler);
  signal (SIGTERM, termination_handler);


  /* Set the limits to a usefull value.  */
  init_limits ();

  /* If port was not specified on commandline, try at first a lookup
     in the service database, if this fails, use the compiled in
     default port.  */
  if (port == -1)
    {
      struct servent *serv = getservbyname ("rpasswd", "tcp");

      if (serv)
	port = serv->s_port;
      else
	port = htons (RPASSWDD_PORT);
    }

  /* Init databases.  */
  server_init (port, ipv4, ipv6);

#ifdef USE_SLP
  /* Register at local SLP server.  */
  if (use_slp)
    register_slp (ntohs(port), slp_timeout, slp_descr);
#endif

  /* Handle incoming requests.  */
#ifdef USE_GNUTLS
  server_run (certificate, privatekey, program);
#else
  server_run (program);
#endif

  return E_SUCCESS;
}
