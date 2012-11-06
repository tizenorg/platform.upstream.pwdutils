/* Copyright (C) 2003, 2004, 2005, 2008 Thorsten Kukuk
   The basis of this code is from the pam_ldap-148 package written
   by Luke Howard.

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

#ifdef USE_LDAP

#define LDAP_DEPRECATED 1

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/param.h>
#include <unistd.h>
#include <syslog.h>
#include <netdb.h>
#include <errno.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif
#ifdef HAVE_LDAP_SSL_H
#include <ldap_ssl.h>
#endif

#include "i18n.h"

#define _INCLUDED_FROM_LIBLDAP_C_
#include "libldap.h"

#ifndef HAVE_LDAP_MEMFREE
#define ldap_memfree(x)	free(x)
#endif

#if LDAP_SET_REBIND_PROC_ARGS < 3
static ldap_session_t *global_session = 0;
#endif

#ifndef HAVE_LDAP_GET_LDERRNO
static int
ldap_get_lderrno (LDAP *ld, char **m, char **s)
{
#ifdef HAVE_LDAP_GET_OPTION
  int rc;
#endif
  int lderrno;

#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_ERROR_NUMBER)
  /* is this needed? */
  rc = ldap_get_option (ld, LDAP_OPT_ERROR_NUMBER, &lderrno);
  if (rc != LDAP_SUCCESS)
    return rc;
#else
  lderrno = ld->ld_errno;
#endif

  if (s != NULL)
    {
#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_ERROR_STRING)
      rc = ldap_get_option (ld, LDAP_OPT_ERROR_STRING, s);
      if (rc != LDAP_SUCCESS)
	return rc;
#else
      *s = ld->ld_error;
#endif
    }

  if (s != NULL)
    {
#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_MATCHED_DN)
      rc = ldap_get_option (ld, LDAP_OPT_MATCHED_DN, m);
      if (rc != LDAP_SUCCESS)
	return rc;
#else
      *m = ld->ld_matched;
#endif
    }

  return lderrno;
}
#endif

void
free_ldap_config (ldap_config_t **pconfig)
{
  ldap_config_t *c;

  c = *pconfig;
  if (c == NULL)
    return;

  if (c->host != NULL)
    free (c->host);

  if (c->base != NULL)
    free (c->base);

  if (c->binddn != NULL)
    free (c->binddn);

  if (c->bindpw != NULL)
    {
      memset (c->bindpw, 0, strlen (c->bindpw));
      free (c->bindpw);
    }

  if (c->rootbinddn != NULL)
    free (c->rootbinddn);

  if (c->rootbindpw != NULL)
    {
      memset (c->rootbindpw, 0, strlen (c->rootbindpw));
      free (c->rootbindpw);
    }

  if (c->sslpath != NULL)
    free (c->sslpath);

  if (c->tmplattr != NULL)
    free (c->tmplattr);

  if (c->tmpluser != NULL)
    free (c->tmpluser);

  if (c->groupattr != NULL)
    free (c->groupattr);

  if (c->groupdn != NULL)
    free (c->groupdn);

  memset (c, 0, sizeof (*c));
  free (c);
  *pconfig = NULL;

  return;
}

#if 0 /* XXX */
static void
free_bind_info (bind_info_t **info)
{
  if (*info == NULL)
    return;

  if ((*info)->dn != NULL)
    free ((*info)->dn);

  if ((*info)->pw)
    {
      memset ((*info)->pw, 0, strlen ((*info)->pw));
      free((*info)->pw);
    }

  if ((*info)->user)
    free ((*info)->user);

  free (*info);
  *info = NULL;

  return;
}
#endif

static ldap_config_t *
alloc_ldap_config (void)
{
  ldap_config_t *result = (ldap_config_t *) calloc (1, sizeof (*result));

  if (result == NULL)
    {
      errno = ENOMEM;
      return NULL;
    }

  result->scope = LDAP_SCOPE_SUBTREE;
  result->deref = LDAP_DEREF_NEVER;
  result->host = NULL;
  result->base = NULL;
  result->port = 0;
  result->binddn = NULL;
  result->bindpw = NULL;
  result->rootbinddn = NULL;
  result->rootbindpw = NULL;
  result->ssl_on = SSL_OFF;
  result->sslpath = NULL;
  result->groupattr = NULL;
  result->groupdn = NULL;
  result->getpolicy = 0;
  result->checkhostattr = 0;
#ifdef LDAP_VERSION3
  result->version = LDAP_VERSION3;
#else
  result->version = LDAP_VERSION2;
#endif /* LDAP_VERSION2 */
  result->timelimit = LDAP_NO_LIMIT;
  result->bind_timelimit = 10;
  result->referrals = 1;
  result->restart = 1;
  result->password_type = PASSWORD_CLEAR;
  result->tmplattr = NULL;
  result->tmpluser = NULL;
  result->tls_checkpeer = 0;
  result->tls_cacertfile = NULL;
  result->tls_cacertdir = NULL;
  result->tls_ciphers = NULL;
  result->tls_cert = NULL;
  result->tls_key = NULL;
  result->use_rfc2307bis = 1;
  return result;
}


#define CHECKPOINTER(ptr) do { if ((ptr) == NULL) { \
    fclose(fp); \
    free_ldap_config (&result); \
    return NULL; \
} \
} while (0)

static ldap_config_t *
read_ldap_config (const char *configFile)
{
  /* this is the same configuration file as for nss_ldap and pam_ldap */
  FILE *fp;
  char b[BUFSIZ];
  char *defaultBase, *passwdBase;
  int defaultScope, passwdScope;
  ldap_config_t *result;

  if ((result = alloc_ldap_config ()) == NULL)
    return NULL;

  /* configuration file location is configurable; default /etc/ldap.conf */
  if (configFile == NULL)
    configFile = LDAP_PATH_CONF;

  fp = fopen (configFile, "r");

  if (fp == NULL)
    {
      if (isatty (fileno(stderr)))
	fprintf (stderr, "missing file \"%s\".\n", configFile);
      else
	syslog (LOG_ERR, "missing file \"%s\"", configFile);
      return NULL;
    }

  defaultBase = NULL;
  defaultScope = LDAP_SCOPE_SUBTREE;

  passwdBase = NULL;
  passwdScope = -1;

  while (fgets (b, sizeof (b), fp) != NULL)
    {
      char *k, *v;
      int len;

      if (*b == '\n' || *b == '#')
	continue;

      k = b;
      v = k;
      while (*v != '\0' && *v != ' ' && *v != '\t')
	v++;

      if (*v == '\0')
	continue;

      *(v++) = '\0';

      /* skip all whitespaces between keyword and value */
      /* Lars Oergel <lars.oergel@innominate.de>, 05.10.2000 */
      while (*v == ' ' || *v == '\t')
	v++;

      /* kick off all whitespaces and newline at the end of value */
      /* Bob Guo <bob@mail.ied.ac.cn>, 08.10.2001 */
      len = strlen (v) - 1;
      while (v[len] == ' ' || v[len] == '\t' || v[len] == '\n')
	--len;
      v[len + 1] = '\0';

      if (!strcasecmp (k, "host"))
	{
	  CHECKPOINTER (result->host = strdup (v));
	}
      else if (!strcasecmp (k, "uri"))
	{
	  CHECKPOINTER (result->uri = strdup (v));
	}
      else if (!strcasecmp (k, "base"))
	{
	  CHECKPOINTER (defaultBase = strdup (v));
	}
      else if (!strcasecmp (k, "binddn"))
	{
	  CHECKPOINTER (result->binddn = strdup (v));
	}
      else if (!strcasecmp (k, "bindpw"))
	{
	  CHECKPOINTER (result->bindpw = strdup (v));
	}
      else if (!strcasecmp (k, "rootbinddn"))
	{
	  CHECKPOINTER (result->rootbinddn = strdup (v));
	}
      else if (!strcasecmp (k, "scope"))
	{
	  if (!strncasecmp (v, "sub", 3))
	    result->scope = LDAP_SCOPE_SUBTREE;
	  else if (!strncasecmp (v, "one", 3))
	    result->scope = LDAP_SCOPE_ONELEVEL;
	  else if (!strncasecmp (v, "base", 4))
	    result->scope = LDAP_SCOPE_BASE;
	}
      else if (!strcasecmp (k, "deref"))
	{
	  if (!strcasecmp (v, "never"))
	    result->deref = LDAP_DEREF_NEVER;
	  else if (!strcasecmp (v, "searching"))
	    result->deref = LDAP_DEREF_SEARCHING;
	  else if (!strcasecmp (v, "finding"))
	    result->deref = LDAP_DEREF_FINDING;
	  else if (!strcasecmp (v, "always"))
	    result->deref = LDAP_DEREF_ALWAYS;
	}
      else if (!strcasecmp (k, "pam_password"))
	{
	  if (!strcasecmp (v, "clear"))
	    result->password_type = PASSWORD_CLEAR;
	  else if (!strcasecmp (v, "crypt"))
	    result->password_type = PASSWORD_CRYPT;
	  else if (!strcasecmp (v, "md5"))
	    result->password_type = PASSWORD_MD5;
	  else if (!strcasecmp (v, "nds"))
	    result->password_type = PASSWORD_NDS;
	  else if (!strcasecmp (v, "ad"))
	    result->password_type = PASSWORD_AD;
	  else if (!strcasecmp (v, "exop"))
	    result->password_type = PASSWORD_EXOP;
	}
      else if (!strcasecmp (k, "pam_crypt"))
	{
	  /*
	   * we still support this even though it is
	   * deprecated, as it could be a security
	   * hole to change this behaviour on
	   * unsuspecting users of pam_ldap.
	   */
	  if (!strcasecmp (v, "local"))
	    result->password_type = PASSWORD_CRYPT;
	  else
	    result->password_type = PASSWORD_CLEAR;
	}
      else if (!strcasecmp (k, "port"))
	{
	  result->port = atoi (v);
	}
      else if (!strcasecmp (k, "timelimit"))
	{
	  result->timelimit = atoi (v);
	}
      else if (!strcasecmp (k, "bind_timelimit"))
	{
	  result->bind_timelimit = atoi (v);
	}
      else if (!strcasecmp (k, "ldap_version"))
	{
	  result->version = atoi (v);
	}
      else if (!strcasecmp (k, "sslpath"))
	{
	  CHECKPOINTER (result->sslpath = strdup (v));
	}
      else if (!strcasecmp (k, "ssl"))
	{
	  if (!strcasecmp (v, "on") || !strcasecmp (v, "yes")
	      || !strcasecmp (v, "true"))
	    {
	      result->ssl_on = SSL_LDAPS;
	    }
	  else if (!strcasecmp (v, "start_tls"))
	    {
	      result->ssl_on = SSL_START_TLS;
	    }
	}
      else if (!strcasecmp (k, "referrals"))
	{
	  result->referrals = (!strcasecmp (v, "on") || !strcasecmp (v, "yes")
			       || !strcasecmp (v, "true"));
	}
      else if (!strcasecmp (k, "restart"))
	{
	  result->restart = (!strcasecmp (v, "on") || !strcasecmp (v, "yes")
			     || !strcasecmp (v, "true"));
	}
      else if (!strcasecmp (k, "pam_template_login_attribute"))
	{
	  CHECKPOINTER (result->tmplattr = strdup (v));
	}
      else if (!strcasecmp (k, "pam_template_login"))
	{
	  CHECKPOINTER (result->tmpluser = strdup (v));
	}
      else if (!strcasecmp (k, "pam_lookup_policy"))
	{
	  result->getpolicy = !strcasecmp (v, "yes");
	}
      else if (!strcasecmp (k, "pam_check_host_attr"))
	{
	  result->checkhostattr = !strcasecmp (v, "yes");
	}
      else if (!strcasecmp (k, "pam_groupdn"))
	{
	  CHECKPOINTER (result->groupdn = strdup (v));
	}
      else if (!strcasecmp (k, "pam_member_attribute"))
	{
	  CHECKPOINTER (result->groupattr = strdup (v));
	}
      else if (!strcasecmp (k, "tls_checkpeer"))
	{
	  if (!strcasecmp (v, "on") || !strcasecmp (v, "yes")
	      || !strcasecmp (v, "true"))
	    {
	      result->tls_checkpeer = 1;
	    }
	  else if (!strcasecmp (v, "off") || !strcasecmp (v, "no")
		   || !strcasecmp (v, "false"))
	    {
	      result->tls_checkpeer = 0;
	    }
	}
      else if (!strcasecmp (k, "tls_cacertfile"))
	{
	  CHECKPOINTER (result->tls_cacertfile = strdup (v));
	}
      else if (!strcasecmp (k, "tls_cacertdir"))
	{
	  CHECKPOINTER (result->tls_cacertdir = strdup (v));
	}
      else if (!strcasecmp (k, "tls_ciphers"))
	{
	  CHECKPOINTER (result->tls_ciphers = strdup (v));
	}
      else if (!strcasecmp (k, "tls_cert"))
	{
	  CHECKPOINTER (result->tls_cert = strdup (v));
	}
      else if (!strcasecmp (k, "tls_key"))
	{
	  CHECKPOINTER (result->tls_key = strdup (v));
	}
      else if (!strcasecmp (k, "nss_schema"))
        {
          if (!strcasecmp (v, "rfc2307bis"))
            {
              result->use_rfc2307bis = 1;
            }
          else if (!strcasecmp (v, "rfc2307"))
            {
              result->use_rfc2307bis = 0;
            }
        }
    }

  if (passwdBase != NULL)
    {
      if (defaultBase != NULL)
	{
	  size_t len = strlen (passwdBase);

	  if (passwdBase[len - 1] == ',')
	    {
	      char *p;

	      p = (char *) malloc (len + strlen (defaultBase) + 1);
	      if (p == NULL)
		{
		  fclose (fp);
		  free (defaultBase);	/* leak the rest... */
		  free_ldap_config (&result);
		  return NULL;
		}

	      strcpy (p, passwdBase);
	      strcpy (&p[len], defaultBase);
	      free (passwdBase);
	      passwdBase = p;
	    }
	  free (defaultBase);
	}
      result->base = passwdBase;
    }
  else
    {
      result->base = defaultBase;
    }

  if (passwdScope != -1)
    {
      result->scope = passwdScope;
    }
  else
    {
      result->scope = defaultScope;
    }

  if (result->host == NULL
#ifdef HAVE_LDAP_INITIALIZE
      && result->uri == NULL
#endif
      )
    {
      if (isatty (fileno(stderr)))
	fprintf (stderr, "missing \"host\" in file \"ldap.conf\".\n");
      else
	syslog (LOG_ERR, "missing \"host\" in file \"ldap.conf\"");
      return NULL;
    }

  if (result->groupattr == NULL)
    {
      CHECKPOINTER (result->groupattr = strdup ("uniquemember"));
    }

  if (result->port == 0)
    {
#if defined(HAVE_LDAP_START_TLS_S)
      if (result->ssl_on == SSL_LDAPS)
	{
	  result->port = LDAPS_PORT;
	}
      else
#endif
	result->port = LDAP_PORT;
    }

  fclose (fp);

  if ((result->rootbinddn != NULL) && (geteuid () == 0))
    {
      fp = fopen (LDAP_PATH_ROOTPASSWD, "r");
      if (fp != NULL)
	{
	  if (fgets (b, sizeof (b), fp) != NULL)
	    {
	      int len;
	      len = strlen (b);
	      if (len > 0 && b[len - 1] == '\n')
		len--;

	      b[len] = '\0';
	      result->rootbindpw = strdup (b);
	    }
	  fclose (fp);
	}
      else
	{
	  int save_err = errno;

	  if (result->rootbinddn)
	    {
	      free (result->rootbinddn);
	      result->rootbinddn = NULL;
	    }
	  if (isatty (fileno(stderr)))
	    fprintf (stderr,
		     "could not open secret file %s (%s)",
		     LDAP_PATH_ROOTPASSWD, strerror (save_err));
	  else
	    syslog (LOG_WARNING,
		    "could not open secret file %s (%s)",
		    LDAP_PATH_ROOTPASSWD, strerror (save_err));
	}
    }

  memset (b, 0, BUFSIZ);
  return result;
}

ldap_session_t *
create_ldap_session (const char *configFile)
{
  ldap_session_t *session;

  session = malloc (sizeof (ldap_session_t));

  if (session == NULL)
    {
      errno = ENOMEM;
      return NULL;
    }

  memset (session, 0, sizeof (ldap_session_t));

  session->conf = read_ldap_config (configFile);
  if (session->conf == NULL)
    {
      free (session);
      return NULL;
    }

#if LDAP_SET_REBIND_PROC_ARGS < 3
  /* Ugly hack, bad idea, but not possible to solve in another way.  */
  global_session = session;
#endif

  return session;
}

#if defined HAVE_LDAP_START_TLS_S || (defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS))
/* Some global TLS-specific options need to be set before we create our
 * session context, so we set them here. */
static int
_set_ssl_default_options (ldap_session_t *session)
{
  int rc;

  /* ca cert file */
  if (session->conf->tls_cacertfile != NULL)
    {
      rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTFILE,
			    session->conf->tls_cacertfile);
      if (rc != LDAP_SUCCESS)
	{
	  if (isatty (fileno (stderr)))
	    fprintf (stderr, "ldap_set_option(LDAP_OPT_X_TLS_CACERTFILE): %s",
		     ldap_err2string (rc));
	  else
	    syslog (LOG_ERR,
		    "ldap_set_option(LDAP_OPT_X_TLS_CACERTFILE): %s",
		    ldap_err2string (rc));
	  return LDAP_OPERATIONS_ERROR;
	}
    }

  if (session->conf->tls_cacertdir != NULL)
    {
      /* ca cert directory */
      rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTDIR,
			    session->conf->tls_cacertdir);
      if (rc != LDAP_SUCCESS)
	{
	  if (isatty (fileno (stderr)))
	    fprintf (stderr, "ldap_set_option(LDAP_OPT_X_TLS_CACERTDIR): %s",
		     ldap_err2string (rc));
	  else
	    syslog (LOG_ERR,
		    "ldap_set_option(LDAP_OPT_X_TLS_CACERTDIR): %s",
		    ldap_err2string (rc));
	  return LDAP_OPERATIONS_ERROR;
	}
    }

  /* require cert? */
  rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_REQUIRE_CERT,
			&session->conf->tls_checkpeer);
  if (rc != LDAP_SUCCESS)
    {
      if (isatty (fileno (stderr)))
	fprintf (stderr, "ldap_set_option(LDAP_OPT_X_TLS_REQUIRE_CERT): %s",
		 ldap_err2string (rc));
      else
	syslog (LOG_ERR,
		"ldap_set_option(LDAP_OPT_X_TLS_REQUIRE_CERT): %s",
		ldap_err2string (rc));
      return LDAP_OPERATIONS_ERROR;
    }

  if (session->conf->tls_ciphers != NULL)
    {
      /* set cipher suite, certificate and private key: */
      rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CIPHER_SUITE,
			    session->conf->tls_ciphers);
      if (rc != LDAP_SUCCESS)
	{
	  if (isatty (fileno (stderr)))
	    fprintf (stderr,
		     "ldap_set_option(LDAP_OPT_X_TLS_CIPHER_SUITE): %s",
		     ldap_err2string (rc));
	  else
	    syslog (LOG_ERR,
		    "ldap_set_option(LDAP_OPT_X_TLS_CIPHER_SUITE): %s",
		    ldap_err2string (rc));
	  return LDAP_OPERATIONS_ERROR;
	}
    }

  if (session->conf->tls_cert != NULL)
    {
      rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CERTFILE,
			    session->conf->tls_cert);
      if (rc != LDAP_SUCCESS)
	{
	  if (isatty (fileno (stderr)))
	    fprintf (stderr, "ldap_set_option(LDAP_OPT_X_TLS_CERTFILE): %s",
		     ldap_err2string (rc));
	  else
	    syslog (LOG_ERR,
		    "ldap_set_option(LDAP_OPT_X_TLS_CERTFILE): %s",
		    ldap_err2string (rc));
	  return LDAP_OPERATIONS_ERROR;
	}
    }

  if (session->conf->tls_key != NULL)
    {
      rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_KEYFILE,
			    session->conf->tls_key);
      if (rc != LDAP_SUCCESS)
	{
	  if (isatty (fileno (stderr)))
	    fprintf (stderr,
		     "ldap_set_option(LDAP_OPT_X_TLS_KEYFILE): %s",
		     ldap_err2string (rc));
	  else
	    syslog (LOG_ERR,
		    "ldap_set_option(LDAP_OPT_X_TLS_KEYFILE): %s",
		    ldap_err2string (rc));
	  return LDAP_OPERATIONS_ERROR;
	}
    }

  return LDAP_SUCCESS;
}
#endif

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
#if LDAP_SET_REBIND_PROC_ARGS == 3
static int
_rebind_proc (LDAP * ld, LDAP_CONST char *url __attribute__ ((unused)),
              ber_tag_t request __attribute__ ((unused)),
              ber_int_t msgid __attribute__ ((unused)), void *arg)
#else
static int
_rebind_proc (LDAP * ld, LDAP_CONST char *url __attribute__ ((unused)),
              int request __attribute__ ((unused)),
              ber_int_t msgid __attribute__ ((unused)))
#endif
{
#if LDAP_SET_REBIND_PROC_ARGS == 3
  ldap_session_t *session = (ldap_session_t *) arg;
#else
  /* ugly hack */
  ldap_session_t *session = global_session;
#endif
  char *who, *cred;

  if (session->bind != NULL && session->bind->bound_as_user == 1)
    {
      who = session->bind->dn;
      cred = session->bind->pw;
    }
  else
    {
      if (session->conf->rootbinddn != NULL && geteuid () == 0)
	{
	  who = session->conf->rootbinddn;
	  cred = session->conf->rootbindpw;
	}
      else
	{
	  who = session->conf->binddn;
	  cred = session->conf->bindpw;
	}
    }

  return ldap_simple_bind_s (ld, who, cred);
}
#else
#if LDAP_SET_REBIND_PROC_ARGS == 3
static int
_rebind_proc (LDAP * ld,
              char **whop, char **credp, int *methodp, int freeit, void *arg)
#else
static int
_rebind_proc (LDAP * ld, char **whop, char **credp, int *methodp, int freeit)
#endif
{
#if LDAP_SET_REBIND_PROC_ARGS == 3
  ldap_session_t *session = (ldap_session_t *) arg;
#else
  /* ugly hack */
  ldap_session_t *session = global_session;
#endif

  if (freeit)
    {
      _pam_drop (*whop);
      _pam_overwrite (*credp);
      _pam_drop (*credp);
      return LDAP_SUCCESS;
    }

  if (session->bind != NULL && session->bind->bound_as_user == 1)
    {
      /*
       * We're authenticating as a user.
       */
      *whop = strdup (session->bind->dn);
      *credp = strdup (session->bind->pw);
    }
  else
    {
      if (session->conf->rootbinddn != NULL && geteuid () == 0)
	{
	  *whop = strdup (session->conf->rootbinddn);
	  *credp = session->conf->rootbindpw != NULL ?
	    strdup (session->conf->rootbindpw) : NULL;
	}
      else
	{
	  *whop = session->conf->binddn != NULL ?
	    strdup (session->conf->binddn) : NULL;
	  *credp = session->conf->bindpw != NULL ?
	    strdup (session->conf->bindpw) : NULL;
	}
    }

  *methodp = LDAP_AUTH_SIMPLE;

  return LDAP_SUCCESS;
}
#endif

int
open_ldap_session (ldap_session_t *session)
{
#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS)
  /* set defaults for global TLS-related options */
  _set_ssl_default_options (session);
#endif
#ifdef HAVE_LDAP_INITIALIZE
  if (session->conf->uri != NULL)
    {
      int rc = ldap_initialize (&session->ld, session->conf->uri);
      if (rc != LDAP_SUCCESS)
	{
	  if (isatty (fileno (stderr)))
	    fprintf (stderr, "ldap_initialize %s",
		     ldap_err2string (rc));
	  else
	    syslog (LOG_ERR, "ldap_initialize %s",
		    ldap_err2string (rc));
	  return rc;
	}
    }
  else
    {
#endif /* HAVE_LDAP_INTITIALIZE */
#ifdef HAVE_LDAP_INIT
      session->ld = ldap_init (session->conf->host, session->conf->port);
#else
      session->ld = ldap_open (session->conf->host, session->conf->port);
#endif /* HAVE_LDAP_INIT */
    }

  if (session->ld == NULL)
    return 1;

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS)
  if (session->conf->ssl_on == SSL_LDAPS)
    {
      int tls = LDAP_OPT_X_TLS_HARD;
      int rc = ldap_set_option (session->ld, LDAP_OPT_X_TLS, &tls);
      if (rc != LDAP_SUCCESS)
	{
	  if (isatty (fileno (stderr)))
	    fprintf (stderr, "ldap_set_option(LDAP_OPT_X_TLS) %s",
		     ldap_err2string (rc));
	  else
	    syslog (LOG_ERR, "ldap_set_option(LDAP_OPT_X_TLS) %s",
		    ldap_err2string (rc));
	  return rc;
	}
    }
#endif /* LDAP_OPT_X_TLS */

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_PROTOCOL_VERSION)
  ldap_set_option (session->ld, LDAP_OPT_PROTOCOL_VERSION,
		   &session->conf->version);
#else
  session->ld->ld_version = session->conf->version;
#endif

#if LDAP_SET_REBIND_PROC_ARGS == 3
  ldap_set_rebind_proc (session->ld, _rebind_proc, (void *) session);
#elif LDAP_SET_REBIND_PROC_ARGS == 2
  ldap_set_rebind_proc (session->ld, _rebind_proc);
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_DEREF)
  ldap_set_option (session->ld, LDAP_OPT_DEREF, &session->conf->deref);
#else
  session->ld->ld_deref = session->conf->deref;
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_TIMELIMIT)
  ldap_set_option (session->ld, LDAP_OPT_TIMELIMIT, &session->conf->timelimit);
#else
  session->ld->ld_timelimit = session->conf->timelimit;
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_REFERRALS)
  ldap_set_option (session->ld, LDAP_OPT_REFERRALS,
		   session->
		   conf->referrals ? LDAP_OPT_ON : LDAP_OPT_OFF);
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_RESTART)
  ldap_set_option (session->ld, LDAP_OPT_RESTART,
		   session->
		   conf->restart ? LDAP_OPT_ON : LDAP_OPT_OFF);
#endif

#ifdef HAVE_LDAP_START_TLS_S
  if (session->conf->ssl_on == SSL_START_TLS)
    {
      int version, rc;

      if (ldap_get_option (session->ld, LDAP_OPT_PROTOCOL_VERSION, &version)
	  == LDAP_SUCCESS)
	{
	  if (version < LDAP_VERSION3)
	    {
	      version = LDAP_VERSION3;
	      ldap_set_option (session->ld, LDAP_OPT_PROTOCOL_VERSION,
			       &version);
	    }

	  rc = ldap_start_tls_s (session->ld, NULL, NULL);
	  if (rc != LDAP_SUCCESS)
	    {
	      if (isatty (fileno (stderr)))
		fprintf (stderr, "ldap_starttls_s: %s",
			 ldap_err2string (rc));
	      else
		syslog (LOG_ERR, "ldap_starttls_s: %s",
			ldap_err2string (rc));
	      return rc;
	    }
	}
    }
#endif /* HAVE_LDAP_START_TLS_S */
  return 0;
}

int
close_ldap_session (ldap_session_t *session)
{
  if (session->ld != NULL)
    {
      ldap_unbind (session->ld);
      session->ld = NULL;
    }

  /* XXX free all the other stuff, too. */

  return 0;
}

static int
reopen_ldap_session (ldap_session_t *session)
{
  /* FYI: V3 lets us avoid five unneeded binds in a password change */
  if (session->conf->version == LDAP_VERSION2)
    {
      close_ldap_session (session);

      if (session->bind != NULL)
	session->bind->bound_as_user = 0;

      return open_ldap_session (session);
    }
  return 0;
}

static int
connect_as_nobody (ldap_session_t *session)
{
  int rc;
  int msgid;
  struct timeval timeout;
  LDAPMessage *result;

  if (session->ld == NULL)
    {
      rc = open_ldap_session (session);
      if (rc != 0)
	return rc;
    }

  if (session->conf->rootbinddn && geteuid () == 0)
    msgid = ldap_simple_bind (session->ld,
			      session->conf->rootbinddn,
			      session->conf->rootbindpw);
  else
    msgid = ldap_simple_bind (session->ld,
			      session->conf->binddn, session->conf->bindpw);

  if (msgid == -1)
    {
      if (isatty (fileno (stderr)))
	fprintf (stderr, "ldap_simple_bind %s.\n",
		 ldap_err2string (ldap_get_lderrno (session->ld, 0, 0)));
      else
	syslog (LOG_ERR, "ldap_simple_bind %s",
		ldap_err2string (ldap_get_lderrno (session->ld, 0, 0)));
      return ldap_get_lderrno (session->ld, 0, 0);
    }

  timeout.tv_sec = session->conf->bind_timelimit;	/* default 10 */
  timeout.tv_usec = 0;
  rc = ldap_result (session->ld, msgid, FALSE, &timeout, &result);
  if (rc == -1 || rc == 0)
    {
      if (isatty (fileno (stderr)))
	fprintf (stderr, "ldap_result %s.\n",
		 ldap_err2string (ldap_get_lderrno (session->ld, 0, 0)));
      else
	syslog (LOG_ERR, "ldap_result %s",
		ldap_err2string (ldap_get_lderrno (session->ld, 0, 0)));
      return ldap_get_lderrno (session->ld, 0, 0);
    }

#ifdef HAVE_LDAP_PARSE_RESULT
  ldap_parse_result (session->ld, result, &rc, 0, 0, 0, 0, TRUE);
#else
  rc = ldap_result2error (session->ld, result, TRUE);
#endif

  if (rc != LDAP_SUCCESS)
    {
      if (isatty (fileno (stderr)))
	fprintf (stderr, "error trying to bind (%s).\n",
		 ldap_err2string (rc));
      else
	syslog (LOG_ERR, "error trying to bind (%s)",
		ldap_err2string (rc));
      return rc;
    }

  if (session->bind != NULL)
    session->bind->bound_as_user = 0;

  return LDAP_SUCCESS;
}

static int
connect_with_dn (ldap_session_t *session)
{
  int rc, msgid;
  struct timeval timeout;
  LDAPMessage *result;

  /* this shouldn't ever happen */
  if (session == NULL || session->bind == NULL)
    return 1;

  /* avoid binding anonymously with a DN but no password */
  if (session->bind->pw == NULL || session->bind->pw[0] == '\0')
    return 1;

  /* if we already bound as the user don't bother retrying */
  if (session->bind->bound_as_user)
    {
      abort (); /* XXX only for debugging. */
      return 1;
    }

  if (session->ld == NULL)
    {
      rc = open_ldap_session (session);
      if (rc != LDAP_SUCCESS)
	return rc;
    }

  msgid = ldap_simple_bind (session->ld, session->bind->dn,
			    session->bind->pw);
  if (msgid == -1)
    {
      if (isatty (fileno (stderr)))
	fprintf (stderr, "ldap_simple_bind %s.\n",
		 ldap_err2string (ldap_get_lderrno (session->ld, 0, 0)));
      else
	syslog (LOG_ERR, "ldap_simple_bind %s",
		ldap_err2string (ldap_get_lderrno (session->ld, 0, 0)));
      return ldap_get_lderrno (session->ld, 0, 0);
    }

  timeout.tv_sec = 10;
  timeout.tv_usec = 0;
  rc = ldap_result (session->ld, msgid, FALSE, &timeout, &result);
  if (rc == -1 || rc == 0)
    {
      if (isatty (fileno (stderr)))
	fprintf (stderr, "ldap_result %s.\n",
		 ldap_err2string (ldap_get_lderrno (session->ld, 0, 0)));
      else
	syslog (LOG_ERR, "ldap_result %s",
		ldap_err2string (ldap_get_lderrno (session->ld, 0, 0)));
      return 1;
    }

  rc = ldap_result2error (session->ld, result, TRUE);

  if (rc != LDAP_SUCCESS)
    {
      if (isatty (fileno (stderr)))
	fprintf (stderr, "error trying to bind as \"%s\" (%s).\n",
		 session->bind->dn, ldap_err2string (rc));
      else
	syslog (LOG_ERR, "error trying to bind as \"%s\" (%s)",
		session->bind->dn, ldap_err2string (rc));
      return rc;
    }

  session->bind->bound_as_user = 1;

  return 0;
}

static int
_escape_string (const char *str, char *buf, size_t buflen)
{
  int ret = 1;
  char *p = buf;
  char *limit = p + buflen - 3;
  const char *s = str;

  while (p < limit && *s)
    {
      switch (*s)
	{
	case '*':
	  strcpy (p, "\\2a");
	  p += 3;
	  break;
	case '(':
	  strcpy (p, "\\28");
	  p += 3;
	  break;
	case ')':
	  strcpy (p, "\\29");
	  p += 3;
	  break;
	case '\\':
	  strcpy (p, "\\5c");
	  p += 3;
	  break;
	default:
	  *p++ = *s;
	  break;
	}
      s++;
    }

  if (*s == '\0')
    {
      /* got to end */
      *p = '\0';
      ret = 0;
    }

  return ret;
}

static char *
convert_to_dn (ldap_session_t *session, const char *name,
	       const char *filterformat)
{
  char *filter, escapedName[strlen (name) * 3 + 3];
  int rc;
  char *retval;
  LDAPMessage *res, *msg;

  rc = connect_as_nobody (session);
  if (rc != 0)
    return NULL;

  if (session->bind)
    session->bind->bound_as_user = 0;

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_SIZELIMIT)
  rc = 1;
  ldap_set_option (session->ld, LDAP_OPT_SIZELIMIT, &rc);
#else
  session->ld->ld_sizelimit = 1;
#endif

  rc = _escape_string (name, escapedName, sizeof (escapedName));
  if (rc != 0)
    return NULL;

  if (asprintf (&filter, filterformat, escapedName) < 1)
    return NULL;

  rc = ldap_search_s (session->ld, session->conf->base,
		      session->conf->scope, filter, NULL, 0, &res);
  free (filter);

  if (rc != LDAP_SUCCESS &&
      rc != LDAP_TIMELIMIT_EXCEEDED && rc != LDAP_SIZELIMIT_EXCEEDED)
    {
      if (isatty (fileno (stderr)))
	fprintf (stderr, "ldap_search_s: %s", ldap_err2string (rc));
      else
	syslog (LOG_ERR, "ldap_search_s: %s", ldap_err2string (rc));
      return NULL;
    }

  msg = ldap_first_entry (session->ld, res);
  if (msg == NULL)
    {
      ldap_msgfree (res);
      return NULL;
    }

  retval = ldap_get_dn (session->ld, msg);

  ldap_msgfree (res);
  return retval;
}

char *
convert_user_to_dn (ldap_session_t *session, const char *user)
{
  return convert_to_dn (session, user,
			"(&(objectClass=posixAccount)(uid=%s))");
}

static char *
convert_group_to_dn (ldap_session_t *session, const char *group)
{
  return convert_to_dn (session, group,
			"(&(objectClass=posixGroup)(cn=%s))");
}

int
ldap_authentication (ldap_session_t *session, const char *user,
		     const char *binddn, const char *password)
{
  int rc = 0;

  /* Sanity checks.  */
  if (session == NULL || (binddn == NULL && user == NULL))
    return 1;

  if (session->bind == NULL)
    {
      session->bind = malloc (sizeof (bind_info_t));
      if (session->bind == NULL)
	{
	  errno = ENOMEM;
	  return 1;
	}
      memset (session->bind, 0, sizeof (bind_info_t));
    }

  if (binddn)
    {
      if (session->bind->user)
	{
	  free (session->bind->user);
	  session->bind->user = NULL;
	}
      if (session->bind->dn)
	free (session->bind->dn);
      session->bind->dn = strdup (binddn);
    }
  else if (user)
    {
      if (session->bind->user == NULL ||
	  strcmp (session->bind->user, user) != 0)
	{
	  char *cp = convert_user_to_dn (session, user);

	  if (cp == NULL)
	    return 1;

	  if (session->bind->user)
	    free (session->bind->user);
	  session->bind->user = strdup (user);

	  if (session->bind->dn)
	    free (session->bind->dn);
	  session->bind->dn = strdup (cp);
	}
    }
  else
    return 1;

  if (session->bind->pw)
    {
      free (session->bind->pw);
      session->bind->pw = NULL;
    }
  if (password)
    session->bind->pw = strdup (password);

  rc = reopen_ldap_session (session);
  if (rc != LDAP_SUCCESS)
    return rc;

  rc = connect_with_dn (session);

  return rc;
}

/* ldap_update_user: Updates an entry in the LDAP database.
   session: pointer to struct with LDAP session data.
   user: Name of the user, from which the data should be updated.
   binddn: Optional, DN as which we should bind to the server.
           If not given, we will use the user DN for binding.
   password: Password used for binding to the LDAP server.
   field: The name of the field which we wish to update.
   new_value: The new value for the field to be updated. */
int
ldap_update_user (ldap_session_t *session, const char *user,
		  const char *binddn, const char *password,
		  const char *field, const char *new_value)
{
  LDAPMod *mods[2], mod;
  char *strvals[2];
  char *userdn;
  int rc;

  /* Sanity check.  */
  if (session == NULL || user == NULL)
    return 1;

  if (session->bind == NULL)
    {
      int i;
      /* If no binding is created yet, call ldap_authentication,
	 which creates the binding and checks the password.  */
      if ((i = ldap_authentication (session, user, binddn, password)) != 0)
	{
	  fprintf (stderr, _("Authentication failure.\n"));
	  return i;
	}
    }

  /* Check, if our user is also the user we used for binding.  */
  if (session->bind->user && strcmp (user, session->bind->user) == 0)
    userdn = session->bind->dn;
  else
    userdn = convert_user_to_dn (session, user);

  if (userdn == NULL)
    return 1;


  /* update field */
  strvals[0] = strdupa (new_value);
  strvals[1] = NULL;

  mod.mod_values = strvals;
  mod.mod_type = strdupa (field);
  mod.mod_op = LDAP_MOD_REPLACE;

  mods[0] = &mod;
  mods[1] = NULL;

  if (!session->bind->bound_as_user)
    {
      rc = reopen_ldap_session (session);
      if (rc != LDAP_SUCCESS)
	return rc;

      rc = connect_with_dn (session);
      if (rc != LDAP_SUCCESS)
	return rc;
    }

  rc = ldap_modify_s (session->ld, userdn, mods);

  return rc;
}

/* ldap_delete_user: Deletes a user entry in the LDAP database.
   session: pointer to struct with LDAP session data.
   user: Name of the user account, which should be deleted.
   binddn: DN as which we should bind to the server.
   password: Password used for binding to the LDAP server.  */
int
ldap_delete_user (ldap_session_t *session, const char *user,
		  const char *binddn, const char *password)
{
  char *userdn;
  int rc;

  /* Sanity check.  */
  if (session == NULL || user == NULL || binddn == NULL)
    return 1;

  if (session->bind == NULL)
    {
      int i;
      /* If no binding is created yet, call ldap_authentication,
	 which creates the binding and checks the password.  */
      if ((i = ldap_authentication (session, NULL, binddn, password)) != 0)
	{
	  fprintf (stderr, _("Authentication failure.\n"));
	  return i;
	}
    }

  userdn = convert_user_to_dn (session, user);

  if (userdn == NULL)
    return 1;

  if (!session->bind->bound_as_user)
    {
      rc = reopen_ldap_session (session);
      if (rc != LDAP_SUCCESS)
	return rc;

      rc = connect_with_dn (session);
      if (rc != LDAP_SUCCESS)
	return rc;
    }

  rc = ldap_delete_s (session->ld, userdn);
  return rc;
}


/* ldap_update_group: Updates an entry in the LDAP database.
   session: pointer to struct with LDAP session data.
   user: Name of the user, from which the data should be updated.
   binddn: Optional, DN as which we should bind to the server.
           If not given, we will use the user DN for binding.
   password: Password used for binding to the LDAP server.
   field: The name of the field which we wish to update.
   new_value: The new value for the field to be updated. */
int
ldap_update_group (ldap_session_t *session, const char *group,
		   const char *binddn, const char *password,
		   int op, const char *field, const char *new_value)
{
  LDAPMod *mods[2], mod;
  char *strvals[2];
  char *groupdn;
  int rc;

  /* Sanity check.  */
  if (session == NULL || group == NULL)
    return 1;

  if (session->bind == NULL)
    {
      int i;
      /* If no binding is created yet, call ldap_authentication,
	 which creates the binding and checks the password.  */
      if ((i = ldap_authentication (session, NULL, binddn, password)) != 0)
	{
	  fprintf (stderr, _("Authentication failure.\n"));
	  return i;
	}
    }

  groupdn = convert_group_to_dn (session, group);
  if (groupdn == NULL)
    return 1;


  /* update field */
  strvals[0] = strdupa (new_value);
  strvals[1] = NULL;

  mod.mod_values = strvals;
  mod.mod_type = strdupa (field);
  mod.mod_op = op;

  mods[0] = &mod;
  mods[1] = NULL;

  if (!session->bind->bound_as_user)
    {
      rc = reopen_ldap_session (session);
      if (rc != LDAP_SUCCESS)
	return rc;

      rc = connect_with_dn (session);
      if (rc != LDAP_SUCCESS)
	return rc;
    }

  rc = ldap_modify_s (session->ld, groupdn, mods);

  return rc;
}

int
ldap_add_groupmember (ldap_session_t *session, const char* group,
		       const char *binddn, const char *password,
		       const char *member, int first )
{
  int rc;

  if ( session->conf->use_rfc2307bis )
    {
      char* dn;
      dn = convert_user_to_dn ( session, member );
      if (dn == NULL)
        return 1;

      rc = ldap_update_group (session, group, binddn, password, LDAP_MOD_ADD,
                              "member", dn );
      free (dn);
      if ( first )
        {
          ldap_update_group (session, group, binddn, password, LDAP_MOD_DELETE,
                             "member", "" );
        }
    }
  else
    {
      rc = ldap_update_group (session, group, binddn, password, LDAP_MOD_ADD,
                              "memberUid", member );
    }

  return rc;
}

int
ldap_del_groupmember (ldap_session_t *session, const char* group,
		       const char *binddn, const char *password,
		       const char *member, int last )
{
  char* userdn;
  int rc;

  if ( session->conf->use_rfc2307bis )
    {
      userdn = convert_user_to_dn ( session, member );
      if (userdn == NULL)
        return 1;

      if ( last )
        {
          ldap_update_group (session, group, binddn, password, LDAP_MOD_ADD,
                              "member", "" );
        }

      rc = ldap_update_group (session, group, binddn, password, LDAP_MOD_DELETE,
                              "member", userdn );
      free (userdn);
    }
  else
    {
      rc = ldap_update_group (session, group, binddn, password, LDAP_MOD_DELETE,
                              "memberUid", member );
    }

  return rc;
}

/* ldap_delete_group: Deletes an group entry in the LDAP database.
   session: pointer to struct with LDAP session data.
   group: Name of the group, which should be removed from the LDAP database.
   binddn: Optional, DN as which we should bind to the server.
           If not given, we will use the user DN for binding.
	   password: Password used for binding to the LDAP server. */
int
ldap_delete_group (ldap_session_t *session, const char *group,
		   const char *binddn, const char *password)
{
  char *groupdn;
  int rc;

  /* Sanity check.  */
  if (session == NULL || group == NULL || binddn == NULL)
    return 1;

  if (session->bind == NULL)
    {
      int i;
      /* If no binding is created yet, call ldap_authentication,
	 which creates the binding and checks the password.  */
      if ((i = ldap_authentication (session, NULL, binddn, password)) != 0)
	{
	  fprintf (stderr, _("Authentication failure.\n"));
	  return i;
	}
    }

  groupdn = convert_group_to_dn (session, group);
  if (groupdn == NULL)
    return 1;

  if (!session->bind->bound_as_user)
    {
      rc = reopen_ldap_session (session);
      if (rc != LDAP_SUCCESS)
	return rc;

      rc = connect_with_dn (session);
      if (rc != LDAP_SUCCESS)
	return rc;
    }

  rc = ldap_delete_s (session->ld, groupdn);

  return rc;
}

/* Try to find the baseou for passwd and group in LDAP. At first we try
   to find a posixAccount or posixGroup object. If we don't find one, try
   to find a organizationalUnit with ou=People or ou=Groups. The result
   will always be a guess, there is no way to determine this without
   explicit option by the admin.  */
static char *
find_baseou (ldap_session_t *session, const char *filter, char *prefer[])
{
    int ldap_errors;
  LDAPMessage *searchresults = NULL;
  LDAPMessage *entry = NULL;
  char *dn = NULL;

  ldap_errors = ldap_search_s (session->ld, session->conf->base,
			       LDAP_SCOPE_SUBTREE,
                               "objectclass=organizationalUnit", NULL, 0,
                               &searchresults);
  if (ldap_errors)
    {
      fprintf (stderr, "ldap_search_s: %s.\n", ldap_err2string (ldap_errors));
      return NULL;
    }

  entry = ldap_first_entry (session->ld, searchresults);
  while (entry)
    {
      LDAPMessage *search2results = NULL, *entry2 = NULL;

      ldap_errors = ldap_search_s (session->ld,
				   ldap_get_dn (session->ld, entry),
				   LDAP_SCOPE_ONELEVEL, filter, NULL, 0,
                                   &search2results);
      if (ldap_errors)
        {
          fprintf (stderr, "ldap_search_s: %s.\n",
		   ldap_err2string (ldap_errors));
          return NULL;
        }

      entry2 = ldap_first_entry (session->ld, search2results);
      if (entry2)
        {
          if (dn)
            free (dn);
          dn = ldap_get_dn (session->ld, entry);
        }
      else if (dn == NULL)
        {
          BerElement *attributehandler;
          char *attribute = ldap_first_attribute (session->ld, entry,
						  &attributehandler);
          while (attribute)
            {
              char **value_collection = NULL;
	      int i;

              if (strcasecmp (attribute, "ou") == 0)
                {
                  value_collection = ldap_get_values (session->ld,
						      entry, attribute);

		  for (i = 0; prefer[i]; i++)
		    {
		      if (strcasecmp (value_collection[0], prefer[i]) == 0)
			dn = ldap_get_dn (session->ld, entry);
		    }
                  ldap_value_free (value_collection);
                }
              attribute = ldap_next_attribute (session->ld,
					       entry, attributehandler);
            }
        }
      entry = ldap_next_entry (session->ld, entry);
    }
  ldap_msgfree (searchresults);

  return dn;

}

char *
ldap_find_user_baseou (ldap_session_t *session)
{
  char *prefer[] = {"People", "User", NULL};

  return find_baseou (session, "objectclass=posixAccount", prefer);

}

char *
ldap_find_group_baseou (ldap_session_t *session)
{
  char *prefer[] = {"Group", "Groups", NULL};

  return find_baseou (session, "objectclass=posixGroup", prefer);

}

int
ldap_create_user (ldap_session_t *session, struct passwd *pw,
		  struct spwd *sp, const char *binddn, const char *password)
{
  LDAPMod *mods[9], mod[8];
  char *strvals[8][2];
  char *userdn, *baseou;
  int i, rc;

  /* Sanity check.  */
  if (session == NULL || pw == NULL)
    return 1;

  if (session->bind == NULL)
    {
      /* If no binding is created yet, call ldap_authentication,
	 which creates the binding and checks the password.  */
      if ((i = ldap_authentication (session, NULL, binddn, password)) != 0)
	{
	  fprintf (stderr, _("Authentication failure.\n"));
	  return i;
	}
    }

  baseou = ldap_find_user_baseou (session);
  if (baseou == NULL)
    {
      fprintf (stderr, _("Cannot find base ou for new users.\n"));
      return 1;
    }
  printf (_("Base DN for user account `%s' is \"%s\".\n"),
	  pw->pw_name, baseou);


  /* create top account object */
  strvals[0][0] = "account";
  strvals[0][1] = NULL;
  strvals[1][0] = pw->pw_name;
  strvals[1][1] = NULL;

  mod[0].mod_values = strvals[0];
  mod[0].mod_type = "objectClass";
  mod[0].mod_op = LDAP_MOD_ADD;
  mod[1].mod_values = strvals[1];
  mod[1].mod_type = "uid";
  mod[1].mod_op = LDAP_MOD_ADD;

  mods[0] = &mod[0];
  mods[1] = &mod[1];
  mods[2] = NULL;

  if (!session->bind->bound_as_user)
    {
      rc = reopen_ldap_session (session);
      if (rc != LDAP_SUCCESS)
	return rc;

      rc = connect_with_dn (session);
      if (rc != LDAP_SUCCESS)
	return rc;
    }

  if (asprintf (&userdn, "uid=%s,%s", pw->pw_name, baseou) < 0)
    return 1;
  rc = ldap_add_s (session->ld, userdn, mods);
  if (rc != 0)
    {
      free (userdn);
      return rc;
    }

  /* create posixAccount object */
  strvals[0][0] = "posixAccount";
  strvals[0][1] = NULL;
  strvals[1][0] = pw->pw_name;
  strvals[1][1] = NULL;
  if (sp && sp->sp_pwdp)
    strvals[2][0] = sp->sp_pwdp;
  else
    strvals[2][0] = pw->pw_passwd ?: "x";
  strvals[2][1] = NULL;
  if (asprintf (&strvals[3][0], "%u", pw->pw_uid) < 0)
    return 1;
  strvals[3][1] = NULL;
  if (asprintf (&strvals[4][0], "%u", pw->pw_gid) < 0)
    return 1;
  strvals[4][1] = NULL;
  strvals[5][0] = pw->pw_dir ?: "";
  strvals[5][1] = NULL;
  strvals[6][0] = pw->pw_shell ?: "";
  strvals[6][1] = NULL;
  strvals[7][0] = pw->pw_gecos;
  strvals[7][1] = NULL;

  mod[0].mod_values = strvals[0];
  mod[0].mod_type = "objectClass";
  mod[0].mod_op = LDAP_MOD_ADD;
  mod[1].mod_values = strvals[1];
  mod[1].mod_type = "cn";
  mod[1].mod_op = LDAP_MOD_ADD;
  mod[2].mod_values = strvals[2];
  mod[2].mod_type = "userPassword";
  mod[2].mod_op = LDAP_MOD_ADD;
  mod[3].mod_values = strvals[3];
  mod[3].mod_type = "uidNumber";
  mod[3].mod_op = LDAP_MOD_ADD;
  mod[4].mod_values = strvals[4];
  mod[4].mod_type = "gidNumber";
  mod[4].mod_op = LDAP_MOD_ADD;
  mod[5].mod_values = strvals[5];
  mod[5].mod_type = "homeDirectory";
  mod[5].mod_op = LDAP_MOD_ADD;
  mod[6].mod_values = strvals[6];
  mod[6].mod_type = "loginShell";
  mod[6].mod_op = LDAP_MOD_ADD;
  mod[7].mod_values = strvals[7];
  mod[7].mod_type = "gecos";
  mod[7].mod_op = LDAP_MOD_ADD;

  mods[0] = &mod[0];
  mods[1] = &mod[1];
  mods[2] = &mod[2];
  mods[3] = &mod[3];
  mods[4] = &mod[4];
  mods[5] = &mod[5];
  mods[6] = &mod[6];
  if (pw->pw_gecos && pw->pw_gecos[0] != '\0')
    {
      mods[7] = &mod[7];
      mods[8] = NULL;
    }
  else
    mods[7] = NULL;

  rc = ldap_modify_s (session->ld, userdn, mods);
  if (rc != 0)
    {
      ldap_delete_s (session->ld, userdn);
      free (userdn);
      return rc;
    }

  /* create shadowAccount object */
  i = 0;
  strvals[i][0] = "shadowAccount";
  strvals[i][1] = NULL;
  mod[i].mod_values = strvals[i];
  mod[i].mod_type = "objectClass";
  mod[i].mod_op = LDAP_MOD_ADD;
  mods[i] = &mod[i];
  i++;
  if (sp->sp_lstchg > 0)
    {
      if (asprintf (&strvals[i][0], "%lu", sp->sp_lstchg) < 0)
	return 1;
      strvals[i][1] = NULL;
      mod[i].mod_values = strvals[i];
      mod[i].mod_type = "shadowLastChange";
      mod[i].mod_op = LDAP_MOD_ADD;
      mods[i] = &mod[i];
      i++;
    }
  if (sp->sp_min >= 0)
    {
      if (asprintf (&strvals[i][0], "%ld", sp->sp_min) < 0)
	return 1;
      strvals[i][1] = NULL;
      mod[i].mod_values = strvals[i];
      mod[i].mod_type = "shadowMin";
      mod[i].mod_op = LDAP_MOD_ADD;
      mods[i] = &mod[i];
      i++;
    }
  if (sp->sp_max >= 0)
    {
      if (asprintf (&strvals[i][0], "%ld", sp->sp_max) < 0)
	return 1;
      strvals[i][1] = NULL;
      mod[i].mod_values = strvals[i];
      mod[i].mod_type = "shadowMax";
      mod[i].mod_op = LDAP_MOD_ADD;
      mods[i] = &mod[i];
      i++;
    }
  if (sp->sp_warn >= 0)
    {
      if (asprintf (&strvals[i][0], "%ld", sp->sp_warn) < 0)
	return 1;
      strvals[i][1] = NULL;
      mod[i].mod_values = strvals[i];
      mod[i].mod_type = "shadowWarning";
      mod[i].mod_op = LDAP_MOD_ADD;
      mods[i] = &mod[i];
    }
  if (sp->sp_inact >= 0)
    {
      if (asprintf (&strvals[i][0], "%ld", sp->sp_inact) < 0)
	return 1;
      strvals[i][1] = NULL;
      mod[i].mod_values = strvals[i];
      mod[i].mod_type = "shadowInactive";
      mod[i].mod_op = LDAP_MOD_ADD;
      mods[i] = &mod[i];
      i++;
    }
  if (sp->sp_expire >= 0)
    {
      if (asprintf (&strvals[i][0], "%ld", sp->sp_expire) < 0)
	return 1;
      strvals[i][1] = NULL;
      mod[i].mod_values = strvals[i];
      mod[i].mod_type = "shadowExpire";
      mod[i].mod_op = LDAP_MOD_ADD;
      mods[i] = &mod[i];
      i++;
    }
  if ((long int) sp->sp_flag != -1 )
    {
      if (asprintf (&strvals[i][0], "%lu", sp->sp_flag) < 0)
	return 1;
      strvals[i][1] = NULL;
      mod[i].mod_values = strvals[i];
      mod[i].mod_type = "shadowFlag";
      mod[i].mod_op = LDAP_MOD_ADD;
      mods[i] = &mod[i];
      i++;
    }

  mods[i] = NULL;

  rc = ldap_modify_s (session->ld, userdn, mods);
  if (rc != 0)
    ldap_delete_s (session->ld, userdn);

  free (userdn);

  return rc;

}

int
ldap_create_group (ldap_session_t *session, struct group *gr,
		   const char *binddn, const char *password)
{
  LDAPMod *mods[8], mod[8];
  char *strvals[8][3];
  char *groupdn, *baseou;
  int i, rc;

  /* Sanity check.  */
  if (session == NULL || gr == NULL)
    return 1;

  if (session->bind == NULL)
    {
      /* If no binding is created yet, call ldap_authentication,
	 which creates the binding and checks the password.  */
      if ((i = ldap_authentication (session, NULL, binddn, password)) != 0)
	{
	  fprintf (stderr, _("Authentication failure.\n"));
	  return i;
	}
    }

  baseou = ldap_find_group_baseou (session);
  if (baseou == NULL)
    {
      fprintf (stderr, _("Cannot find base ou for new groups.\n"));
      return 1;
    }
  printf (_("Base DN for group `%s' is \"%s\".\n"),
	  gr->gr_name, baseou);
  if (asprintf (&groupdn, "cn=%s,%s", gr->gr_name, baseou) < 0)
    return 1;

  if (!session->bind->bound_as_user)
    {
      rc = reopen_ldap_session (session);
      if (rc != LDAP_SUCCESS)
	return rc;

      rc = connect_with_dn (session);
      if (rc != LDAP_SUCCESS)
	return rc;
    }


  /* create top objectClass.  */
  strvals[0][0] = "posixGroup";
  strvals[0][1] = NULL;

  strvals[1][0] = gr->gr_name;
  strvals[1][1] = NULL;
  if (asprintf (&strvals[2][0], "%u", gr->gr_gid) < 0)
    return 1;
  strvals[2][1] = NULL;

  mod[0].mod_values = strvals[0];
  mod[0].mod_type = "objectClass";
  mod[0].mod_op = LDAP_MOD_ADD;
  mod[1].mod_values = strvals[1];
  mod[1].mod_type = "cn";
  mod[1].mod_op = LDAP_MOD_ADD;
  mod[2].mod_values = strvals[2];
  mod[2].mod_type = "gidNumber";
  mod[2].mod_op = LDAP_MOD_ADD;

  mods[0] = &mod[0];
  mods[1] = &mod[1];
  mods[2] = &mod[2];
  mods[3] = NULL;

  /* rfc2307bis uses standard LDAP groups (groupOfNames as
   * structural objectclass) */
  if ( session->conf->use_rfc2307bis )
    {
      strvals[0][1] = "groupOfNames";
      strvals[0][2] = NULL;

      /* groupOfNames requires at least one "member" attribute
       * use an empty value for groups with no members */
      strvals[3][0] = "";
      strvals[3][1] = NULL;

      mod[3].mod_values = strvals[3];
      mod[3].mod_type = "member";
      mod[3].mod_op = LDAP_MOD_ADD;
      mods[3] = &mod[3];
      mods[4] = NULL;
    }

  rc = ldap_add_s (session->ld, groupdn, mods);
  if (rc != 0)
    {
      ldap_delete_s (session->ld, groupdn);
      free (groupdn);
      return rc;
    }

  free (strvals[2][0]);

  if (rc != 0)
    ldap_delete_s (session->ld, groupdn);

  free (groupdn);

  return rc;

}

#endif /* USE_LDAP */
