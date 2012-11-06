/* Copyright (C) 2004, 2005 Thorsten Kukuk
   Author: Thorsten Kukuk <kukuk@thkukuk.de>

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

#include <dlfcn.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>

#include "i18n.h"
#include "logging.h"

struct logfunc_t *logfunc_list = NULL;

/* Add a new entry to the list.  */
static int
store (const char *name, const char *options)
{
  void *handle = NULL;
  char *err_msg;
  struct logfunc_t *new = malloc (sizeof (struct logfunc_t));
  char *buf;

  if (new == NULL)
    abort ();

  if (name == NULL)
    abort ();

  if (asprintf (&buf, "%s/liblog_%s.so.1", PLUGINDIR, name) < 0)
    {
      syslog (LOG_ERR, "Out of memory");
      fputs ("running out of memory!\n", stderr);
      return -1;
    }

  new->next = NULL;

  handle = dlopen (buf, RTLD_NOW);
  free (buf);
  if (!handle)
    {
      err_msg = dlerror ();
      syslog (LOG_ERR, err_msg);
      fprintf (stderr, _("Cannot open logging plugin:\n%s\n"),
	       err_msg);
      return -1;
    }

  if (asprintf (&buf, "%s_sec_log", name) < 0)
    {
      syslog (LOG_ERR, "Out of memory");
      fputs ("running out of memory!\n", stderr);
      return -1;
    }
  dlerror ();
  new->sec_log_fnc = dlsym (handle, buf);
  if ((err_msg = dlerror ()) != NULL)
    {
      syslog (LOG_ERR, err_msg);
      fprintf (stderr, _("Cannot find symbol `%s':\n%s\n"),
	       buf, err_msg);
      dlclose (handle);
      free (buf);
      return -1;
    }
  free (buf);

  if (asprintf (&buf, "%s_open_sec_log", name) < 0)
    {
      syslog (LOG_ERR, "Out of memory");
      fputs ("running out of memory!\n", stderr);
      return -1;
    }
  new->open_sec_log_fnc = dlsym (handle, buf);
  if ((err_msg = dlerror ()) != NULL)
    {
      syslog (LOG_ERR, err_msg);
      fprintf (stderr, _("Cannot find symbol `%s':\n%s\n"),
	       buf, err_msg);
      dlclose (handle);
      free (buf);
      return -1;
    }
  free (buf);

  (*new->open_sec_log_fnc)(options);

  if (logfunc_list == NULL)
    logfunc_list = new;
  else
    {
      struct logfunc_t *ptr = logfunc_list;

      while (ptr->next != NULL)
	ptr = ptr->next;

      ptr->next = new;
    }

  return 0;
}


void
open_sec_log (const char *program)
{
  FILE *fp;
  char *buf = NULL;
  size_t buflen = 0;

  openlog (program, LOG_PID, LOG_AUTHPRIV);

  fp = fopen ("/etc/pwdutils/logging", "r");
  if (NULL == fp)
    {
#if 0 /* We should not try to load modules if none is setup */
      if (store ("syslog", NULL) < 0)
	{
	  fprintf (stderr, _("Error setting up logging subsystem!\n"));
	  return;
	}
#endif
      return;
    }

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

      tmp = strchr (cp, '#');  /* remove comments */
      if (tmp)
        *tmp = '\0';
      while (isspace ((int)*cp))    /* remove spaces and tabs */
        ++cp;
      if (*cp == '\0')        /* ignore empty lines */
        continue;

      if (cp[strlen (cp) - 1] == '\n')
        cp[strlen (cp) - 1] = '\0';

      tmp = strsep (&cp, " \t=");
      if (cp != NULL)
        while (isspace ((int)*cp) || *cp == '=')
          ++cp;

      store (tmp, cp);
    }
  fclose (fp);

  if (buf)
    free (buf);
}
