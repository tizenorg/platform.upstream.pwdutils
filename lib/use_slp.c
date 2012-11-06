/* Copyright (C) 2004, 2005 Thorsten Kukuk
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

#ifdef USE_SLP

#include <netdb.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <slp.h>

#include "use_slp.h"
#include "dbg_log.h"

/*  This is the minimum we'll use, irrespective of config setting.
    definately don't set to less than about 30 seconds.  */
#define SLP_MIN_TIMEOUT 120

static void
pwdutilsSLPRegReport (SLPHandle hslp __attribute__ ((unused)),
		      SLPError errcode, void* cookie)
{
  /* return the error code in the cookie */
  *(SLPError*)cookie = errcode;
}

/* the URL we use to register.  */
static char *url = NULL;

static char hostname[1024];
static char *hname;
static struct hostent *hp = NULL;
static int saved_port;
static int saved_timeout;
static char *saved_descr = NULL;

static void
do_refresh (int sig __attribute__ ((unused)))
{
  if (debug_level)
    dbg_log ("Service registration almost expired, refreshing it");
  register_slp (saved_port, saved_timeout, saved_descr);
}

int
register_slp (int port, int slp_timeout, const char *slp_descr)
{
  SLPError err;
  SLPError callbackerr;
  SLPHandle hslp;
  char *attr;
  int timeout;

  saved_port = port;
  saved_timeout = slp_timeout;
  if (saved_descr == NULL && slp_descr != NULL)
    saved_descr = strdup (slp_descr);

  if (url != NULL)
    {
      free (url);
      url = NULL;
    }
  else
    {
      gethostname (hostname, sizeof (hostname));
      if (isdigit (hostname[0]))
	{
	  char addr[INADDRSZ];
	  if (inet_pton (AF_INET, hostname, &addr))
	    hp = gethostbyaddr (addr, sizeof (addr), AF_INET);
	}
      else
	hp = gethostbyname (hostname);
      hname = hp->h_name;
    }

  if (slp_timeout == 0)
    timeout = SLP_LIFETIME_MAXIMUM; /* don't expire, ever */
  else if (SLP_MIN_TIMEOUT > slp_timeout)
    timeout = SLP_MIN_TIMEOUT; /* use a reasonable minimum */
  else if (SLP_LIFETIME_MAXIMUM <= slp_timeout)
    timeout = (SLP_LIFETIME_MAXIMUM - 1); /* as long as possible */
  else
    timeout = slp_timeout;

  if (asprintf (&url, "service:rpasswdd://%s:%i/", hname, port) < 0)
    {
      dbg_log ("Out of memory");
      return -1;
    }

  if (slp_descr)
    {
      if (asprintf (&attr, "(description=%s)", slp_descr) < 0)
	{
	  dbg_log ("Out of memory");
	  return -1;
	}
    }
  else
    attr = strdup ("");

  err = SLPOpen ("en", SLP_FALSE, &hslp);
  if(err != SLP_OK)
    {
      dbg_log ("Error opening slp handle %i", err);
      return -1;
    }

    /* Register a service with SLP */
  err = SLPReg (hslp, url, SLP_LIFETIME_MAXIMUM, 0,
		attr,
		SLP_TRUE,
		pwdutilsSLPRegReport,
		&callbackerr);

  free (attr);

  /* err may contain an error code that occurred as the slp library    */
  /* _prepared_ to make the call.                                     */
  if ((err != SLP_OK) || (callbackerr != SLP_OK))
    {
      dbg_log ("Error registering service with slp %i", err);
      return -1;
    }

  /* callbackerr may contain an error code (that was assigned through */
  /* the callback cookie) that occurred as slp packets were sent on    */
  /* the wire */
  if( callbackerr != SLP_OK)
    {
      dbg_log ("Error registering service with slp %i",
	       callbackerr);
      return callbackerr;
    }

  /* Now that we're done using slp, close the slp handle */
  SLPClose (hslp);

  /* Set up a timer to refresh the service records */
  if (timeout != SLP_LIFETIME_MAXIMUM)
    {
      struct sigaction act;

      act.sa_handler = do_refresh;
      if (sigaction (SIGALRM, &act, NULL) != 0)
	dbg_log ("SLP: error establishing signal handler\n");

      alarm (timeout - 15);
    }

  return 0;
}

int
deregister_slp ()
{
  SLPError err;
  SLPError callbackerr;
  SLPHandle hslp;

  if (url == NULL)
    {
      dbg_log ("URL not registerd!");
      return -1;
    }

  err = SLPOpen ("en", SLP_FALSE, &hslp);
  if(err != SLP_OK)
    {
      dbg_log ("Error opening slp handle %i", err);
      return -1;
    }

  /* Disable possibel alarm call.  */
  alarm (0);

  /* DeRegister a service with SLP */
  err = SLPDereg (hslp, url, pwdutilsSLPRegReport, &callbackerr);

  free (url);
  url = NULL;


  /* err may contain an error code that occurred as the slp library    */
  /* _prepared_ to make the call.                                     */
  if ((err != SLP_OK) || (callbackerr != SLP_OK))
    {
      dbg_log ("Error unregistering service with slp %i", err);
      return -1;
    }

  /* callbackerr may contain an error code (that was assigned through */
  /* the callback cookie) that occurred as slp packets were sent on    */
  /* the wire */
  if( callbackerr != SLP_OK)
    {
      dbg_log ("Error registering service with slp %i",
	       callbackerr);
      return callbackerr;
    }

  /* Now that we're done using slp, close the slp handle */
  SLPClose (hslp);

  return 0;
}

#endif
