/* Copyright (C) 2002-2005, 2008, 2010, 2011 Thorsten Kukuk
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

#include <ctype.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#ifdef USE_SLP
#include <slp.h>
#endif


#ifdef USE_GNUTLS
static int
start_request (HANDLE gnutls_session ssl, char *username, int admin_mode)
{
  request_header req;
  char *locale = getenv ("LANG");
  int ret;

  if (admin_mode)
    req.request = START_ADMIN;
  else
    req.request = START;
  req.version = RPASSWD_VERSION;
  req.data_len = strlen (username) + 1;
  if (locale)
    req.locale_len = strlen (locale) + 1;
  else
    req.locale_len = 0;

  if ((ret = gnutls_record_send (ssl, &req, sizeof (request_header))) <= 0)
    {
      if (ret == 0)
	PRINTF (ERR_HANDLE, _("error while sending start request: %s\n"),
		_("Peer has closed the TLS connection"));
      else
	PRINTF (ERR_HANDLE, _("error while sending start request: %s\n"),
		gnutls_strerror (ret));
      return -1;
    }

  if (locale)
    {
      if ((ret = gnutls_record_send (ssl, locale, req.locale_len)) <= 0)
	{
	  if (ret == 0)
	    PRINTF (ERR_HANDLE, _("error while sending locale data: %s\n"),
		    _("Peer has closed the TLS connection"));
	  else
	    PRINTF (ERR_HANDLE, _("error while sending locale data: %s\n"),
		    gnutls_strerror (ret));
	  return -1;
	}
    }
  if ((ret = gnutls_record_send (ssl, username, req.data_len)) <= 0)
    {
      if (ret == 0)
	PRINTF (ERR_HANDLE, _("error while sending username: %s\n"),
		_("Peer has closed the TLS connection"));
      else
	PRINTF (ERR_HANDLE, _("error while sending username: %s\n"),
		gnutls_strerror (ret));
      return -1;
    }

  return 0;
}

static int
send_string (HANDLE gnutls_session ssl, u_int32_t retval, const char *str)
{
  int ret;
  conv_header resp;

  resp.retval = retval;
  if (str == NULL)
    resp.data_len = 0;
  else
    resp.data_len = strlen (str) + 1;

  if ((ret = gnutls_record_send (ssl, &resp, sizeof (resp))) <= 0)
    {
      if (ret == 0)
	PRINTF (ERR_HANDLE, _("error while sending string: %s\n"),
		_("Peer has closed the TLS connection"));
      else
	PRINTF (ERR_HANDLE, _("error while sending string: %s\n"),
		gnutls_strerror (ret));
      return E_FAILURE;
    }

  if (str)
    {
      if ((ret = gnutls_record_send (ssl, str, resp.data_len)) <= 0)
	{
	  if (ret == 0)
	    PRINTF (ERR_HANDLE, _("error while sending string: %s\n"),
		    _("Peer has closed the TLS connection"));
	  else
	    PRINTF (ERR_HANDLE, _("error while sending string: %s\n"),
		    gnutls_strerror (ret));
	  return E_FAILURE;
	}
    }

  return E_SUCCESS;
}

#else

static int
start_request (SSL *ssl, char *username, int admin_mode)
{
  request_header req;
  char *locale = getenv ("LANG");

  if (admin_mode)
    req.request = START_ADMIN;
  else
    req.request = START;
  req.version = RPASSWD_VERSION;
  req.data_len = strlen (username) + 1;
  if (locale)
    req.locale_len = strlen (locale) + 1;
  else
    req.locale_len = 0;

  if (SSL_write (ssl, &req, sizeof (request_header)) !=
      sizeof (request_header))
    return -1;

  if (locale)
    if (SSL_write (ssl, locale, req.locale_len) != req.locale_len)
      return -1;

  if (SSL_write (ssl, username, req.data_len) != req.data_len)
    return -1;

  return 0;
}

static int
send_string (SSL *ssl, u_int32_t ret, const char *str)
{
  conv_header resp;

  resp.retval = ret;
  if (str == NULL)
    resp.data_len = 0;
  else
    resp.data_len = strlen (str) + 1;
  if (TEMP_FAILURE_RETRY (SSL_write (ssl, &resp, sizeof (resp)))
      != sizeof (resp))
    return E_FAILURE;

  if (str)
    if (TEMP_FAILURE_RETRY (SSL_write (ssl, str, resp.data_len))
	!= resp.data_len)
      return E_FAILURE;

  return E_SUCCESS;
}
#endif

#ifdef USE_SLP
/* Ask SLP server for rpasswd service.  */

struct slpcb
{
  char *srvurl;
  SLPError err;
  struct slpcb *next;
  char *hostp;
  char *portp;
  char *descr;
};

static void
free_slpcb (struct slpcb *cb)
{
  struct slpcb *tcb;

  free (cb->srvurl);
  cb = cb->next;

  while (cb)
    {
      tcb = cb;
      cb = cb->next;
      free (tcb->srvurl);
      if (tcb->descr)
	free (tcb->descr);
      free (tcb);
    }
}

static void
parse_slpcb (struct slpcb *cb)
{
#define NEEDLE "://"
  size_t needle_length = strlen (NEEDLE);

  cb->hostp = strstr (cb->srvurl, NEEDLE);

  if (cb->hostp == NULL || strlen (cb->hostp) < needle_length + 1)
    return;

  cb->hostp += needle_length;

  cb->portp = strchr (cb->hostp, ':');
  if (cb->portp)
    {
      char *cp;

      cb->portp[0] = '\0';
      cb->portp += 1;
      cp = cb->portp;
      while (isdigit (*cp))
	cp++;

      if (*cp != '\0')
	*cp = '\0';
    }
}

static SLPBoolean
MySLPSrvURLCallback (SLPHandle hslp __attribute__ ((unused)),
		     const char *srvurl,
		     unsigned short lifetime __attribute__ ((unused)),
		     SLPError errcode, void *cookie)
{
  struct slpcb *cb = (struct slpcb *) cookie;

  if (errcode == SLP_OK)
    {
      if (cb->srvurl != NULL)
	{
	  struct slpcb *cbt = malloc (sizeof (struct slpcb));
	  if (cbt == NULL)
	    return SLP_FALSE;

	  cbt->srvurl = cb->srvurl;
	  cbt->hostp = cb->hostp;
	  cbt->portp = cb->portp;
	  cbt->err = cb->err;
	  cbt->next = cb->next;
	  cb->next = cbt;
	  cb->descr = NULL;
	}
      cb->srvurl = strdup (srvurl);
      parse_slpcb (cb);
      cb->err = SLP_OK;
      return SLP_TRUE;
    }
  else if (errcode != SLP_LAST_CALL)
    cb->err = errcode;

  return SLP_FALSE;		/* We don't wan't to be called again.  */
}

static SLPBoolean
MySLPAttrCallback (SLPHandle hslp __attribute__ ((unused)),
		   const char *attrlist, SLPError errcode, void *cookie)
{
  char **descr = (char **) cookie;

  if (errcode == SLP_OK)
    {
      char *cp = strstr (attrlist, "(description=");

      if (cp == NULL)
	return SLP_FALSE;

      *descr = strdup (cp + 13);

      cp = strchr (*descr, ')');
      if (cp != NULL)
	*cp = '\0';
    }

  return SLP_FALSE;
}

static int
query_slp (HANDLE char **hostp, char **portp, char **descrp)
{
  struct slpcb *cb, callbackres = { NULL, 0, NULL, NULL, NULL, NULL };
  SLPError err;
  SLPHandle hslp;

  *hostp = NULL;
  *portp = NULL;
  *descrp = NULL;

  PRINTF (STD_HANDLE, _("Searching a server...\n"));

  err = SLPOpen ("en", SLP_FALSE, &hslp);
  if (err != SLP_OK)
    {
      PRINTF (ERR_HANDLE, _("Error opening SLP handle: %i.\n"), err);
      return err;
    }

  err = SLPFindSrvs (hslp, "rpasswdd", 0, 0,
		     MySLPSrvURLCallback, &callbackres);

  /* err may contain an error code that occurred as the slp library
     _prepared_ to make the call.  */
  if (err != SLP_OK || callbackres.err != SLP_OK)
    {
      PRINTF (STD_HANDLE, _("No service found with SLP.\n"));
      return -1;
    }

  cb = &callbackres;

  while (cb != NULL)
    {
      char *buf;

      if (asprintf (&buf, "service:rpasswdd://%s:%s/", cb->hostp,
		    cb->portp ? : "774") < 0)
	return -1;
      err = SLPFindAttrs (hslp, buf, "", "",	/* use configured scopes */
			  MySLPAttrCallback, &(cb->descr));
      free (buf);
      if (err != SLP_OK)
	{
	  PRINTF (STD_HANDLE,
		  _("Error while searching for SLP description.\n"));
	  return -1;
	}
      cb = cb->next;
    }

  /* Now that we're done using slp, close the slp handle */
  SLPClose (hslp);

  cb = &callbackres;
#if defined(SELECT_SRVURL)
  if (cb->next != NULL)		/* Only if we have more than one entry.  */
    {
      /* Ask the user which one to use.  */
      struct slpcb *tcb = &callbackres;
      int choice = 0;		/* index of the user's choice.  */
      char response[20];	/* string to hold the user's response.  */
      int i = 0;

      printf (_("\nPlease select a server:\n"));
      while (tcb != NULL)
	{
	  ++i;
	  printf ("[%2d] %s", i, tcb->hostp);
	  if (tcb->portp)
	    printf (_(" (port %s)"), tcb->portp);
	  if (tcb->descr)
	    printf (" - %s", tcb->descr);
	  fputs ("\n", stdout);
	  tcb = tcb->next;
	}

      while ((choice < 1) || (choice > i))
	{
	  char *cp;
	  printf (_("Enter number of choice [1-%d]: "), i);
	  fflush (stdin);
	  cp = fgets (response, sizeof (response), stdin);
	  fflush (stdin);
	  if (cp == NULL)
	    choice = 0;
	  else
	    choice = strtol (response, NULL, 10);
	}
      printf ("\n");
      for (i = 0; i < (choice - 1); i++)
	cb = cb->next;
    }
#endif

  if (cb->hostp != NULL)
    {
      *hostp = strdup (cb->hostp);
      if (cb->portp)
	*portp = strdup (cb->portp);
      if (cb->descr)
	*descrp = strdup (cb->descr);

      free_slpcb (&callbackres);
      return 0;
    }

  free_slpcb (&callbackres);
  return -1;
}
#endif

static int
parse_reqcert (const char *str)
{
  if (strcmp (str, "never") == 0)
    return 0;
  else if (strcmp (str, "allow") == 0)
    return 1;
  else if (strcmp (str, "try") == 0)
    return 2;
  else if (strcmp (str, "demand") == 0 || strcmp (str, "hard") == 0)
    return 3;

  /* If we cannot parse it, use saftest mode.  */
  return 3;
}

/* Load the config file (/etc/rpasswd.conf)  */
static int
load_config (const char *configfile, char **hostp, char **portp, int *reqcertp
#ifdef DO_VERBOSE_OUTPUT
	     , int verbose, int check_syntax
#endif
  )
{
  FILE *fp;
  char *buf = NULL;
  size_t buflen = 0;
  int have_entries = 0;		/* # of entries we found in config file */
#ifdef DO_VERBOSE_OUTPUT
  int bad_entries = 0;
#endif

  fp = fopen (configfile, "r");
  if (NULL == fp)
    return 1;

#ifdef DO_VERBOSE_OUTPUT
  if (verbose > 1)
    PRINTF (STD_HANDLE, _("parsing config file"));
#endif

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

#ifdef DO_VERBOSE_OUTPUT
      if (verbose > 1)
	PRINTF (STD_HANDLE, "%s %s", _("Trying entry:"), cp);

      if (check_syntax)
	PRINTF (STD_HANDLE, "%s %s\n", _("Trying entry:"), cp);
#endif

      if (strncmp (cp, "server", 6) == 0 && isspace ((int) cp[6]))
	{
	  if (hostp != NULL)
	    {
	      char tmpserver[MAXHOSTNAMELEN + 1];

	      if (sscanf (cp, "server %s", tmpserver) == 1)
		*hostp = strdup (tmpserver);
	    }
	  continue;
	}
      else if (strncmp (cp, "port", 4) == 0 && isspace ((int) cp[4]))
	{
	  if (portp != NULL)
	    {
	      char tmpport[30];

	      if (sscanf (cp, "port %s", tmpport) == 1)
		*portp = strdup (tmpport);
	    }
	  continue;
	}
      else if (strncmp (cp, "reqcert", 7) == 0 && isspace ((int) cp[7]))
	{
	  char *p = &cp[7];

	  while (isspace (*p))
	    ++p;

	  *reqcertp = parse_reqcert (p);
	  continue;
	}

#ifdef DO_VERBOSE_OUTPUT
      if (check_syntax)
	{
	  PRINTF (STD_HANDLE, _("Entry \"%s\" is not valid!\n"), cp);
	  ++bad_entries;
	}
      else
	PRINTF (ERR_HANDLE, _("Entry \"%s\" is not valid, ignored!\n"), cp);
#endif
    }
  fclose (fp);

  if (buf)
    free (buf);

#ifdef DO_VERBOSE_OUTPUT
  if (check_syntax)
    {
      if (bad_entries)
	{
	  PRINTF (STD_HANDLE, _("Bad entries found.\n"));
	  return 1;
	}
      if (!have_entries)
	{
	  PRINTF (STD_HANDLE, _("No entry found.\n"));
	  return 1;
	}
    }
#endif

  if (!have_entries)
    {
#ifdef DO_VERBOSE_OUTPUT
      if (verbose > 1)
	PRINTF (STD_HANDLE, _("No entry found."));
#endif
      return 1;
    }

  return 0;
}

static int
connect_to_server (HANDLE const char *hostp, const char *portp,
		   int family, int quiet)
{
#ifdef NI_WITHSCOPEID
  const int niflags = NI_NUMERICHOST | NI_WITHSCOPEID;
#else
  const int niflags = NI_NUMERICHOST;
#endif
  struct addrinfo hints, *res, *res0;
  int error;
  int sock = -1;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = family;

  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_CANONNAME;

  error = getaddrinfo (hostp, portp, &hints, &res0);
  if (error)
    {
      if (error == EAI_NONAME)
	{
	  PRINTF (ERR_HANDLE,
		  _
		  ("Hostname or service not known for specified protocol\n"));
	  return -1;
	}
      else if (error == EAI_SERVICE)
	{
	  /* if port cannot be resolved, try compiled in
	     port number. If this works, don't abort here.  */
	  char *cp;
	  if (asprintf (&cp, "%d", RPASSWDD_PORT) < 0)
	    return -1;
	  error = getaddrinfo (hostp, cp, &hints, &res0);
	  free (cp);
	  if (error)
	    {
	      PRINTF (ERR_HANDLE, _("bad port: %s\n"), portp);
	      return -1;
	    }
	}
      else
	{
	  PRINTF (ERR_HANDLE, "%s: %s\n", hostp, gai_strerror (error));
	  return -1;
	}
    }

  for (res = res0; res; res = res->ai_next)
    {
      char hbuf[NI_MAXHOST];

      if (getnameinfo (res->ai_addr, res->ai_addrlen,
		       hbuf, sizeof (hbuf), NULL, 0, niflags) != 0)
	strcpy (hbuf, "(invalid)");
      switch (res->ai_family)
	{
	case AF_INET:
	  if (!quiet)
	    {
	      struct sockaddr_in s_in;
	      memcpy (&s_in, res->ai_addr, sizeof (struct sockaddr_in));
	      PRINTF (STD_HANDLE, _("Trying %s port %d...\n"),
		      hbuf, ntohs (s_in.sin_port));
	    }
	  break;
	case AF_INET6:
	  if (!quiet)
	    {
	      struct sockaddr_in6 s_in6;
	      memcpy (&s_in6, res->ai_addr, sizeof (struct sockaddr_in));
	      PRINTF (STD_HANDLE, _("Trying %s port %d...\n"),
		      hbuf, ntohs (s_in6.sin6_port));
	    }
	  break;
	default:
	  if (!quiet)
	    PRINTF (STD_HANDLE, _("Trying %s...\n"), hbuf);
	  break;
	}

      /* Create the socket.  */
      sock = socket (res->ai_family, res->ai_socktype, res->ai_protocol);
      if (sock < 0)
	continue;

      if (connect (sock, res->ai_addr, res->ai_addrlen) < 0)
	{
	  if (getnameinfo (res->ai_addr, res->ai_addrlen,
			   hbuf, sizeof (hbuf), NULL, 0, niflags) != 0)
	    strcpy (hbuf, "(invalid)");
	  PRINTF (ERR_HANDLE, _("connect to address %s: %s\n"), hbuf,
		  strerror (errno));
	  close (sock);
	  sock = -1;
	  continue;
	}
      if (!quiet)
	PRINTF (STD_HANDLE, "\n");
      break;
    }
  freeaddrinfo (res0);
  return sock;
}

#ifdef USE_GNUTLS

#include <gnutls/x509.h>

#ifndef HAVE_GNUTLS_PK_ALGORITHM_GET_NAME

static const char *
gnutls_pk_algorithm_get_name (gnutls_pk_algorithm algorithm)
{
  if (algorithm == GNUTLS_PK_RSA)
    return "RSA";
  else if (algorithm == GNUTLS_PK_DSA)
    return "DSA";
  else
    return "UNKNOWN";
}
#endif

/* This function will print information about this session's peer
 * certificate.
 */
static void
print_x509_certificate_info (HANDLE gnutls_session session)
{
  char dn[128];
  size_t size;
  unsigned int algo, bits;
  time_t expiration_time, activation_time;
  const gnutls_datum *cert_list;
  unsigned int cert_list_size = 0;
  gnutls_x509_crt cert;

  /* This function only works for X.509 certificates.
   */
  if (gnutls_certificate_type_get (session) != GNUTLS_CRT_X509)
    return;

  cert_list = gnutls_certificate_get_peers (session, &cert_list_size);
  if (cert_list_size <= 0)
    return;

  PRINTF (STD_HANDLE, _("Server certificate info:\n"));

  /* we only print information about the first certificate. */
  gnutls_x509_crt_init (&cert);

  gnutls_x509_crt_import (cert, &cert_list[0], GNUTLS_X509_FMT_DER);

  expiration_time = gnutls_x509_crt_get_expiration_time (cert);
  activation_time = gnutls_x509_crt_get_activation_time (cert);

  PRINTF (STD_HANDLE, _("  Certificate is valid since: %s"),
			ctime (&activation_time));
  PRINTF (STD_HANDLE, _("  Certificate expires: %s"),
	  ctime (&expiration_time));

  /* Extract some of the public key algorithm's parameters
   */
  algo = gnutls_x509_crt_get_pk_algorithm (cert, &bits);
  PRINTF (STD_HANDLE, _("  Certificate public key: %s"),
	  gnutls_pk_algorithm_get_name (algo));

  /* Print the version of the X.509
   * certificate.
   */
  PRINTF (STD_HANDLE, _("  Certificate version: #%d\n"),
	  gnutls_x509_crt_get_version (cert));

  size = sizeof (dn);
  gnutls_x509_crt_get_dn (cert, dn, &size);
  PRINTF (STD_HANDLE, _("  DN: %s\n"), dn);

  size = sizeof (dn);
  gnutls_x509_crt_get_issuer_dn (cert, dn, &size);
  PRINTF (STD_HANDLE, _("  Issuer's DN: %s\n"), dn);

  PRINTF (STD_HANDLE, "\n");

  gnutls_x509_crt_deinit (cert);
}


static int
start_ssl (HANDLE long sock, int reqcert, int verbose, gnutls_session session,
	   gnutls_certificate_credentials *cred)
{
  gnutls_certificate_credentials xcred;
  DIR *dir = opendir ("/etc/ssl/certs");
  struct dirent *entry;
  int ret;

  /* Allow connections to servers that have OpenPGP keys as well. */
  const int cert_type_priority[3] =
    { GNUTLS_CRT_X509, GNUTLS_CRT_OPENPGP, 0 };


  /* X509 stuff */
  gnutls_certificate_allocate_credentials (&xcred);

  /* sets the trusted cas files from /etc/ssl/certs and try to
     add /etc/rpasswdd.pem (default from server). */
  if (dir != NULL)
    {
      while ((entry = readdir (dir)) != NULL)
	{
	  /* Skip "." and ".." directory entries.  */
	  if (strcmp (entry->d_name, ".") == 0 ||
	      strcmp (entry->d_name, "..") == 0)
	    continue;
	  else
	    {
	      char srcfile[strlen ("/etc/ssl/certs") +
			   strlen (entry->d_name) + 2];
	      struct stat st;
	      char *cp;

	      /* create source and destination filename with full path.  */
	      cp = stpcpy (srcfile, "/etc/ssl/certs");
	      *cp++ = '/';
	      strcpy (cp, entry->d_name);

	      if (lstat (srcfile, &st) != 0)
		continue;

	      if (!S_ISLNK(st.st_mode) && !S_ISDIR(st.st_mode) &&
		  !S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode))
		{
		  /* XXX error handling! */
		  gnutls_certificate_set_x509_trust_file (xcred, srcfile,
							  GNUTLS_X509_FMT_PEM);

		}
	    }
	}
      closedir (dir);
    }
  gnutls_certificate_set_x509_trust_file (xcred, "/etc/rpasswdd.pem",
					  GNUTLS_X509_FMT_PEM);

  *cred = xcred;

  /* Use default priorities */
  gnutls_set_default_priority (session);
  gnutls_certificate_type_set_priority (session, cert_type_priority);

  /* put the x509 credentials to the current session.  */
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  gnutls_transport_set_ptr (session, (gnutls_transport_ptr) sock);

  /* Perform the TLS handshake.  */
  ret = gnutls_handshake (session);

  if (ret < 0)
    {
      PRINTF (ERR_HANDLE, _("Handshake failed: %s\n"),
	      gnutls_strerror (ret));
      return E_SSL_FAILURE;
    }

  if (reqcert > 0 || verbose)
    {
      gnutls_kx_algorithm kx;
      unsigned int verify_result = 0;
      time_t now;

      /* print the key exchange's algorithm name.  */
      kx = gnutls_kx_get (session);

#ifdef HAVE_GNUTLS_CERTIFICATE_VERIFY_PEERS2
      ret = gnutls_certificate_verify_peers2 (session, &verify_result);
#else
      ret = gnutls_certificate_verify_peers (session);
      if (ret > 0)
	verify_result = ret;
#endif
      if (ret < 0)
	{
	  PRINTF (ERR_HANDLE, _("TLS certificate error: %s\n"),
		  gnutls_strerror (verify_result));
	  return E_SSL_FAILURE;
	}

      /* Following two steps are optional and not required for
         data exchange to be successful except the client couldn't verfiy
         the server certificate.  */
      if (verify_result || verbose)
	{
	  /* Get the cipher.  */
	  PRINTF (STD_HANDLE, _("%s connection using %s-%s (%s)\n\n"),
		  gnutls_protocol_get_name (gnutls_protocol_get_version
					    (session)),
		  gnutls_cipher_get_name (gnutls_cipher_get (session)),
		  gnutls_mac_get_name (gnutls_mac_get (session)),
		  gnutls_certificate_type_get_name
		  (gnutls_certificate_type_get (session)));

#if defined(IAM_PAM_MODULE)
	  print_x509_certificate_info (pamh, session);
#else
	  print_x509_certificate_info (session);
#endif

	  if (verify_result & GNUTLS_CERT_SIGNER_NOT_FOUND)
	    {
	      PRINTF (ERR_HANDLE,
		      _
		      ("TLS authentication error: server certificate issuer is unknown.\n"));
	      if (reqcert >= 2)
		return E_SSL_FAILURE;
	    }
	  else if (verify_result & GNUTLS_CERT_INVALID)
	    {
	      PRINTF (ERR_HANDLE,
		      _
		      ("TLS authentication error: server certificate is NOT trusted.\n"));
	      if (reqcert >= 2)
		return E_SSL_FAILURE;
	    }
	}

      now = time (NULL);

      if (gnutls_certificate_activation_time_peers (session) > now)
	{
	  PRINTF (ERR_HANDLE,
		  _("TLS authentication error: server certificate not yet activated.\n"));
	  if (reqcert >= 2)
	    return E_SSL_FAILURE;
	}

      if (gnutls_certificate_expiration_time_peers (session) < now)
	{
	  PRINTF (ERR_HANDLE,
		  _("TLS authentication error: server certificate expired.\n"));
	  if (reqcert >= 2)
	    return E_SSL_FAILURE;
	}
    }

  return 0;
}

#else
static int
start_ssl (HANDLE int sock, int reqcert, int verbose,
	   SSL_CTX ** ctx, SSL ** ssl)
{
  X509 *server_cert;
  char *str;
  SSL_METHOD *meth;
  long verify_result;
  int err;

  SSLeay_add_ssl_algorithms ();
  meth = SSLv3_client_method ();
  SSL_load_error_strings ();
  *ctx = SSL_CTX_new (meth);
  if (*ctx == NULL)
    {
      PRINTF (ERR_HANDLE, ERR_error_string (ERR_get_error (), NULL));
      return E_SSL_FAILURE;
    }

#if 0
  /* This is only necessary if we configure a unusual path.
     XXX Make this a program option.  */
  if (!SSL_CTX_load_verify_locations (*ctx, NULL, "/etc/ssl/certs"))
    {
      PRINTF (ERR_HANDLE, _("error loading default verify locations: %s\n"),
	      ERR_error_string (ERR_get_error (), NULL));
      if (reqcert > 1)
	return E_SSL_FAILURE;
    }
#endif
  if (!SSL_CTX_set_default_verify_paths (*ctx))
    {
      PRINTF (ERR_HANDLE, _("error setting default verify path: %s\n"),
	      ERR_error_string (ERR_get_error (), NULL));
      if (reqcert > 1)
	return E_SSL_FAILURE;
    }

  /* Now we have TCP conncetion. Start SSL negotiation. */
  *ssl = SSL_new (*ctx);
  if (*ssl == NULL)
    {
      PRINTF (ERR_HANDLE, ERR_error_string (ERR_get_error (), NULL));
      return E_SSL_FAILURE;
    }
  SSL_set_fd (*ssl, sock);

#if OPENSSL_VERSION_NUMBER >= 0x00906000L
  /* This only exists in 0.9.6 and above. Without it we may get interrupted
   *   reads or writes. Bummer. */
  SSL_set_mode (*ssl, SSL_MODE_AUTO_RETRY);
#endif

  err = SSL_connect (*ssl);
  if (err < 1)
    {
      PRINTF (ERR_HANDLE, "SSL_connect: %s", ERR_error_string (err, NULL));
      close (sock);
      return E_SSL_FAILURE;
    }

  if (reqcert > 0 || verbose)
    {
      /* Get server's certificate (note: beware of dynamic allocation).  */
      server_cert = SSL_get_peer_certificate (*ssl);
      if (!server_cert)
	{
	  PRINTF (ERR_HANDLE, _("Unable to get certificate from peer.\n"));
	  close (sock);
	  return E_SSL_FAILURE;
	}

      /* Verify severs certificate.  */
      verify_result = SSL_get_verify_result (*ssl);

      /* Following two steps are optional and not required for
         data exchange to be successful except the client couldn't verfiy
         the server certificate.  */
      if (verify_result || verbose)
	{
	  /* Get the cipher.  */
	  PRINTF (STD_HANDLE, _("SSL connection using %s\n\n"),
		  SSL_get_cipher (*ssl));

	  if (server_cert == NULL)
	    {
	      PRINTF (ERR_HANDLE, _("Server does not have a certificate?\n"));
	      if (reqcert >= 3)
		return E_SSL_FAILURE;
	    }
	  else
	    {
	      PRINTF (STD_HANDLE, _("Server certificate info:\n"));

	      str = X509_NAME_oneline (X509_get_subject_name (server_cert),
				       0, 0);
	      if (str)
		{
		  PRINTF (STD_HANDLE, _("  DN: %s\n"), str);
		  free (str);
		}
	      str = X509_NAME_oneline (X509_get_issuer_name (server_cert),
				       0, 0);
	      if (str)
		{
		  PRINTF (STD_HANDLE, _("  Issuer's DN: %s\n"), str);
		  free (str);
		}
	      /* We could do all sorts of certificate verification stuff
	         here before deallocating the certificate.  */

	      PRINTF (STD_HANDLE, "\n");
	    }
	}

      if ((verify_result = SSL_get_verify_result (*ssl)) != X509_V_OK)
	{
	  PRINTF (ERR_HANDLE, "Server certificate is not ok: %s!\n",
		  X509_verify_cert_error_string (verify_result));
	  if (reqcert >= 2)
	    return E_SSL_FAILURE;
	}

      X509_free (server_cert);
    }

  return 0;
}
#endif
