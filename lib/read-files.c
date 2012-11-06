/* Copyright (C) 2002, 2003, 2004 Thorsten Kukuk
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

#include <pwd.h>
#include <shadow.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <nss.h>
#include <bits/libc-lock.h>
#define __libc_lock_t pthread_mutex_t

#include "read-files.h"

static enum { none, getent, getby }last_use;

static enum nss_status
internal_setent (FILE **stream, const char *file)
{
  enum nss_status status = NSS_STATUS_SUCCESS;

  if (*stream == NULL)
    {
      char *filename = alloca (strlen (files_etc_dir) + strlen (file) + 1);
      strcpy (filename, files_etc_dir);
      strcat (filename, file);

      *stream = fopen (filename, "r");

      if (*stream == NULL)
	status = errno == EAGAIN ? NSS_STATUS_TRYAGAIN : NSS_STATUS_UNAVAIL;
      else
	{
	  int result, flags;

	  result = flags = fcntl (fileno (*stream), F_GETFD, 0);
	  if (result >= 0)
	    {
	      flags |= 1;
	      result = fcntl (fileno (*stream), F_SETFD, flags);
	    }

	  if (result < 0)
	    {
	      fclose (*stream);
	      stream = NULL;
	      status = NSS_STATUS_UNAVAIL;
	    }
	}
    }
  else
    rewind (*stream);

  return status;
}

static void
internal_endent (FILE **stream)
{
  if (*stream != NULL)
    {
      fclose (*stream);
      stream = NULL;
    }
}

static enum nss_status
internal_getspent (FILE *stream, struct spwd *result,
		   char *buffer, size_t buflen, int *errnop)
{
  char *p;
  char *data = (void *) buffer;
  int linebuflen = buffer + buflen - data;
  int parse_result;

  if (buflen < sizeof *data + 2)
    {
      *errnop = ERANGE;
      return NSS_STATUS_TRYAGAIN;
    }

  do {
    ((unsigned char *) data)[linebuflen - 1] = '\xff';

    p = fgets (data, linebuflen, stream);
    if (p == NULL)
      {
	*errnop = ENOENT;
	return NSS_STATUS_NOTFOUND;
      }
    else if (((unsigned char *) data)[linebuflen - 1] != 0xff)
      {
	*errnop = ERANGE;
	return NSS_STATUS_TRYAGAIN;
      }

    /* Skip leading blanks.  */
    while (isspace (*p))
      ++p;
  }
  while (*p == '\0' || *p == '#'
	 || !(parse_result = parse_spent (p, result, 0)));


  return parse_result == -1 ? NSS_STATUS_TRYAGAIN : NSS_STATUS_SUCCESS;
}

static enum nss_status
internal_getpwent (FILE *stream, struct passwd *result,
		   char *buffer, size_t buflen, int *errnop)
{
  char *p;
  char *data = (void *) buffer;
  int linebuflen = buffer + buflen - data;
  int parse_result;

  if (buflen < sizeof *data + 2)
    {
      *errnop = ERANGE;
      return NSS_STATUS_TRYAGAIN;
    }

  do {
    ((unsigned char *) data)[linebuflen - 1] = '\xff';

    p = fgets (data, linebuflen, stream);
    if (p == NULL)
      {
	*errnop = ENOENT;
	return NSS_STATUS_NOTFOUND;
      }
    else if (((unsigned char *) data)[linebuflen - 1] != 0xff)
      {
	*errnop = ERANGE;
	return NSS_STATUS_TRYAGAIN;
      }

    /* Skip leading blanks.  */
    while (isspace (*p))
      ++p;
  }
  while (*p == '\0' || *p == '#'
	 || !(parse_result = parse_pwent (p, result, 0)));


  return parse_result == -1 ? NSS_STATUS_TRYAGAIN : NSS_STATUS_SUCCESS;
}

enum nss_status
files_getspnam_r (const char *name, struct spwd *result,
		  char *buffer, size_t buflen, int *errnop)
{
  /* Locks the static variables in this file.  */
  __libc_lock_define_initialized (static, lock)
  enum nss_status status;
  FILE *stream = NULL;

  __libc_lock_lock (lock);

  status = internal_setent (&stream, "/shadow");
  if (status == NSS_STATUS_SUCCESS)
    {
      last_use = getby;
      while ((status = internal_getspent (stream, result, buffer, buflen,
					  errnop)) == NSS_STATUS_SUCCESS)
	{
	  if (name[0] != '+' && name[0] != '-'
	      && ! strcmp (name, result->sp_namp))
	    break;
	}
      internal_endent (&stream);
    }

  __libc_lock_unlock (lock);

  return status;
}

enum nss_status
files_getpwnam_r (const char *name, struct passwd *result,
		  char *buffer, size_t buflen, int *errnop)
{
  /* Locks the static variables in this file.  */
  __libc_lock_define_initialized (static, lock)
  enum nss_status status;
  FILE *stream = NULL;

  __libc_lock_lock (lock);

  status = internal_setent (&stream, "/passwd");
  if (status == NSS_STATUS_SUCCESS)
    {
      last_use = getby;
      while ((status = internal_getpwent (stream, result, buffer, buflen,
					  errnop)) == NSS_STATUS_SUCCESS)
	{
	  if (name[0] != '+' && name[0] != '-'
	      && ! strcmp (name, result->pw_name))
	    break;
	}
      internal_endent (&stream);
    }

  __libc_lock_unlock (lock);

  return status;
}

enum nss_status
files_getpwuid_r (uid_t uid, struct passwd *result, char *buffer,
		  size_t buflen, int *errnop)
{
  /* Locks the static variables in this file.  */
  __libc_lock_define_initialized (static, lock)
  enum nss_status status;
  FILE *stream = NULL;

  __libc_lock_lock (lock);

  status = internal_setent (&stream, "/passwd");
  if (status == NSS_STATUS_SUCCESS)
    {
      last_use = getby;
      while ((status = internal_getpwent (stream, result, buffer, buflen,
					  errnop)) == NSS_STATUS_SUCCESS)
	{
	  if (uid == result->pw_uid && result->pw_name[0] != '+' &&
	      result->pw_name[0] != '-')
	    break;
	}
      internal_endent (&stream);
    }

  __libc_lock_unlock (lock);

  return status;
}

/* Return the next entry from the database file, doing locking.  */
enum nss_status
files_getpwent_r (struct passwd *result, char *buffer,
		  size_t buflen, int *errnop)
{
  /* Some static variables */
  __libc_lock_define_initialized (static, lock)
  static FILE *stream;
  static fpos_t position;

  /* Return next entry in host file.  */
  enum nss_status status = NSS_STATUS_SUCCESS;

  __libc_lock_lock (lock);

  /* Be prepared that the set*ent function was not called before.  */
  if (stream == NULL)
    {
      status = internal_setent (&stream, "/passwd");

      if (status == NSS_STATUS_SUCCESS && fgetpos (stream, &position) < 0)
        {
          fclose (stream);
          stream = NULL;
          status = NSS_STATUS_UNAVAIL;
        }
    }

  if (status == NSS_STATUS_SUCCESS)
    {
      /* If the last use was not by the getent function we need the
         position the stream.  */
      if (last_use != getent)
        {
          if (fsetpos (stream, &position) < 0)
            status = NSS_STATUS_UNAVAIL;
          else
            last_use = getent;
        }

      if (status == NSS_STATUS_SUCCESS)
        {
          status = internal_getpwent (stream, result, buffer, buflen, errnop);

          /* Remember this position if we were successful.  If the
             operation failed we give the user a chance to repeat the
             operation (perhaps the buffer was too small).  */
          if (status == NSS_STATUS_SUCCESS)
            fgetpos (stream, &position);
          else
            /* We must make sure we reposition the stream the next call.  */
            last_use = none;
        }
    }

  __libc_lock_unlock (lock);

  return status;
}

/* Return the next entry from the database file, doing locking.  */
enum nss_status
files_getspent_r (struct spwd *result, char *buffer,
		  size_t buflen, int *errnop)
{
  /* Some static variables */
  __libc_lock_define_initialized (static, lock)
  static FILE *stream;
  static fpos_t position;

  /* Return next entry in host file.  */
  enum nss_status status = NSS_STATUS_SUCCESS;

  __libc_lock_lock (lock);

  /* Be prepared that the set*ent function was not called before.  */
  if (stream == NULL)
    {
      status = internal_setent (&stream, "/shadow");

      if (status == NSS_STATUS_SUCCESS && fgetpos (stream, &position) < 0)
        {
          fclose (stream);
          stream = NULL;
          status = NSS_STATUS_UNAVAIL;
        }
    }

  if (status == NSS_STATUS_SUCCESS)
    {
      /* If the last use was not by the getent function we need the
         position the stream.  */
      if (last_use != getent)
        {
          if (fsetpos (stream, &position) < 0)
            status = NSS_STATUS_UNAVAIL;
          else
            last_use = getent;
        }

      if (status == NSS_STATUS_SUCCESS)
        {
          status = internal_getspent (stream, result, buffer, buflen, errnop);

          /* Remember this position if we were successful.  If the
             operation failed we give the user a chance to repeat the
             operation (perhaps the buffer was too small).  */
          if (status == NSS_STATUS_SUCCESS)
            fgetpos (stream, &position);
          else
            /* We must make sure we reposition the stream the next call.  */
            last_use = none;
        }
    }

  __libc_lock_unlock (lock);

  return status;
}
