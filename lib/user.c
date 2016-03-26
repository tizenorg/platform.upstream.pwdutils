/* Copyright (C) 2002, 2003, 2004, 2005, 2009, 2010, 2011 Thorsten Kukuk
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

#include <nss.h>
#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>

#ifdef USE_LDAP
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif
#include "libldap.h"
#endif

#include "nsw.h"
#include "i18n.h"
#include "public.h"
#include "yppasswd.h"
#include "read-files.h"

char *files_etc_dir = "/etc";

const char *
nsw2str (service_t service)
{
  switch (service)
    {
    case S_LOCAL:
      return "files";
      break;
    case S_YP:
      return "NIS";
      break;
    case S_NISPLUS:
      return "NIS+";
      break;
#ifdef USE_LDAP
    case S_LDAP:
      return "LDAP";
      break;
#endif
    default:
      return "unknown";
      break;
    }
}

char *
getnismaster (void)
{

  char *master, *domainname;
  int port, err;

  yp_get_default_domain (&domainname);

  if ((err = yp_master (domainname, "passwd.byname", &master)) != 0)
    {
      fprintf (stderr, _("Can't find the NIS master server: %s\n"),
	       yperr_string (err));
      return NULL;
    }
  port = getrpcport (master, YPPASSWDPROG, YPPASSWDPROC_UPDATE, IPPROTO_UDP);
  if (port == 0)
    {
      fprintf (stderr, _("rpc.yppasswdd not running on NIS master %s.\n"), master);
      return NULL;
    }
  if (port >= IPPORT_RESERVED)
    {
      fprintf (stderr,
	       _("rpc.yppasswdd running on illegal port on NIS master %s.\n"),
	       master);
      return NULL;
    }

  return master;
}

void
free_user_t (user_t *data)
{
  if (data == NULL)
    return;

  if (data->pwdbuffer)
    free (data->pwdbuffer);
  if (data->spwbuffer)
    free (data->spwbuffer);
  if (data->newpassword)
    free (data->newpassword);
  if (data->new_name)
    free (data->new_name);
  if (data->new_shell)
    free (data->new_shell);
  if (data->new_gecos)
    free (data->new_gecos);
  if (data->new_home)
    free (data->new_home);
  if (data->oldclearpwd)
    free (data->oldclearpwd);
  if (data->binddn)
    free (data->binddn);
  free (data);
}

user_t *
do_getpwnam (const char *user, const char *use_service)
{
  enum nss_status (*nss_getpwnam_r)(const char *name, struct passwd *pwd,
                                    char *buffer, size_t buflen, int *errnop);
  enum nss_status (*nss_getspnam_r)(const char *name, struct spwd *sp,
                                    char *buffer, size_t buflen, int *errnop);
  enum nss_status status;
  void *nss_handle = NULL;
  user_t *data;
  struct nsw *nswp;
  int i;

  data = calloc (1, sizeof (user_t));
  if (data == NULL)
    return NULL;

  data->service = S_NONE;

  /* UNIX passwords area */
  if (use_service)
    {
      nswp = calloc (1, sizeof (struct nsw));
      if (nswp == NULL)
	return data;

      nswp->name = strdup ("passwd");
      nswp->orderc = 1;
      nswp->orders = calloc (2, sizeof (char *));
      nswp->orders[0] = strdup (use_service);
      nswp->orders[1] = NULL;
    }
  else
    nswp = _getnswbyname ("passwd");
  if (nswp == NULL)
    return data;

  for (i = 0; i < nswp->orderc; ++i)
    {
      const char *cmpptr = nswp->orders[i];

    again:

      if (nswp->orders[i][0] == '[')
	continue;
      if (strcasecmp ("files", cmpptr) == 0 ||
	  strcasecmp ("compat", cmpptr) == 0)
	{
          nss_getpwnam_r = files_getpwnam_r;
	  /* Get password file entry... */
	  do {
            errno = 0;
	    data->pwdbuflen += 1024;
	    data->pwdbuffer = realloc (data->pwdbuffer, data->pwdbuflen);
	    status = (*nss_getpwnam_r)(user, &data->pw, data->pwdbuffer,
				       data->pwdbuflen, &errno);
	  } while (status == NSS_STATUS_TRYAGAIN && errno == ERANGE);

	  if (status != NSS_STATUS_SUCCESS)
	    {
	      free (data->pwdbuffer);
	      data->pwdbuffer = NULL;
	      data->pwdbuflen = 0;
	      if (strcasecmp ("compat", cmpptr) == 0)
		{
		  struct nsw *nswp2 = _getnswbyname ("passwd_compat");

		  if (nswp2 == NULL)
		    cmpptr = "nis";
		  else
		    {
		      char *cp = alloca (strlen (nswp2->orders[0]) + 1);
		      strcpy (cp, nswp2->orders[0]);
		      cmpptr = cp;
		      nsw_free (nswp2);
		    }
		  goto again;
		}
	    }
	  else
	    {
	      data->service = S_LOCAL;
	      break;
	    }
	}
      else if (strcasecmp ("nis", cmpptr) == 0 ||
	       strcasecmp ("yp", cmpptr) == 0)
	{
          nss_handle = dlopen ("libnss_nis.so.2", RTLD_NOW);
          if (!nss_handle)
            continue;
          nss_getpwnam_r = dlsym (nss_handle, "_nss_nis_getpwnam_r");
          if (dlerror () != NULL)
            {
              dlclose (nss_handle);
              continue;
            }

	  /* Get NIS passwd entry... */
	  do {
            errno = 0;
	    data->pwdbuflen += 1024;
	    data->pwdbuffer = realloc (data->pwdbuffer, data->pwdbuflen);
	    status = (*nss_getpwnam_r)(user, &data->pw, data->pwdbuffer,
				       data->pwdbuflen, &errno);
	  } while (status == NSS_STATUS_TRYAGAIN && errno == ERANGE);

	  if (status != NSS_STATUS_SUCCESS)
	    {
	      dlclose (nss_handle);
	      free (data->pwdbuffer);
	      data->pwdbuffer = NULL;
	      data->pwdbuflen = 0;
	    }
	  else
	    {
	      data->service = S_YP;
	      break;
	    }
	}
      else if (strcasecmp ("nisplus", cmpptr) == 0 ||
	       strcasecmp ("nis+", cmpptr) == 0)
	{
	  nss_handle = dlopen ("libnss_nisplus.so.2", RTLD_NOW);
          if (!nss_handle)
            continue;
          nss_getpwnam_r = dlsym (nss_handle, "_nss_nisplus_getpwnam_r");
          if (dlerror () != NULL)
            {
              dlclose (nss_handle);
              continue;
            }

	  /* Get password NIS+ entry... */
	  do {
            errno = 0;
	    data->pwdbuflen += 1024;
	    data->pwdbuffer = realloc (data->pwdbuffer, data->pwdbuflen);
	    status = (*nss_getpwnam_r)(user, &data->pw, data->pwdbuffer,
				       data->pwdbuflen, &errno);
	  } while (status == NSS_STATUS_TRYAGAIN && errno == ERANGE);

	  if (status != NSS_STATUS_SUCCESS)
	    {
	      dlclose (nss_handle);
	      free (data->pwdbuffer);
	      data->pwdbuffer = NULL;
	      data->pwdbuflen = 0;
	    }
	  else
	    {
	      data->service = S_NISPLUS;
	      break;
	    }
	}
#ifdef USE_LDAP
      else if (strcasecmp ("ldap", cmpptr) == 0)
	{
	  nss_handle = dlopen ("libnss_ldap.so.2", RTLD_NOW);
          if (!nss_handle)
            continue;
          nss_getpwnam_r = dlsym (nss_handle, "_nss_ldap_getpwnam_r");
          if (dlerror () != NULL)
            {
              dlclose (nss_handle);
              continue;
            }

	  /* Get LDAP passwd entry... */
	  do {
            errno = 0;
	    data->pwdbuflen += 1024;
	    data->pwdbuffer = realloc (data->pwdbuffer, data->pwdbuflen);
	    status = (*nss_getpwnam_r)(user, &data->pw, data->pwdbuffer,
				       data->pwdbuflen, &errno);
	  } while (status == NSS_STATUS_TRYAGAIN && errno == ERANGE);

	  if (status != NSS_STATUS_SUCCESS)
	    {
	      dlclose (nss_handle);
	      free (data->pwdbuffer);
	      data->pwdbuffer = NULL;
	      data->pwdbuflen = 0;
	    }
	  else
	    {
	      data->service = S_LDAP;
	      break;
	    }
	}
#endif
    }

  nsw_free (nswp);

  if (data->service == S_NONE)
    return data;

  nss_getspnam_r = NULL;
  status = NSS_STATUS_NOTFOUND;

  if (data->service == S_LOCAL)
    {
      nss_getspnam_r = files_getspnam_r;
    }
  else if (data->service == S_YP)
    {
      nss_getspnam_r = dlsym (nss_handle, "_nss_nis_getspnam_r");
      if (dlerror () != NULL)
        {
          data->service = S_NONE;
          free (data->pwdbuffer);
          data->pwdbuffer = NULL;
          data->pwdbuflen = 0;
          dlclose (nss_handle);
          return data;
        }
    }
  else if (data->service == S_NISPLUS)
    {
      nss_getspnam_r = dlsym (nss_handle, "_nss_nisplus_getspnam_r");
      if (dlerror () != NULL)
        {
          data->service = S_NONE;
          free (data->pwdbuffer);
          data->pwdbuffer = NULL;
          data->pwdbuflen = 0;
          dlclose (nss_handle);
          return data;
        }
    }
#ifdef USE_LDAP
  else if (data->service == S_LDAP)
    {
      nss_getspnam_r = dlsym (nss_handle, "_nss_ldap_getspnam_r");
      if (dlerror () != NULL)
        {
          data->service = S_NONE;
          free (data->pwdbuffer);
          data->pwdbuffer = NULL;
          data->pwdbuflen = 0;
          dlclose (nss_handle);
          return data;
        }
    }
#endif

  if (nss_getspnam_r)
    {
      do {
        errno = 0;
        data->spwbuflen += 1024;
        data->spwbuffer = realloc (data->spwbuffer, data->spwbuflen);
        status = (*nss_getspnam_r)(user, &data->sp, data->spwbuffer,
                                   data->spwbuflen, &errno);
      } while (status == NSS_STATUS_TRYAGAIN && errno == ERANGE);
    }

  if (data->service != S_LOCAL && data->service != S_NONE)
    dlclose (nss_handle);

  if (status == NSS_STATUS_SUCCESS)
    {
      data->use_shadow = TRUE;
      data->spn = data->sp;
      data->sp_changed = FALSE;
    }
  else
    memset (&(data->sp), 0, sizeof (struct spwd));

  return data;
}

int
write_user_data (user_t *data, int is_locked)
{
  int retval = 0;

  if (data->service == S_LOCAL)
    {
      if (!is_locked && lock_database() != 0)
        {
	  fputs (_("Cannot lock password file: already locked.\n"), stderr);
	  retval = -1;
        }
      else if ((data->newpassword && !data->use_shadow) ||
	       data->new_shell || data->new_gecos || data->new_home ||
	       data->have_new_uid || data->have_new_gid || data->new_name ||
	       data->todo == DO_CREATE || data->todo == DO_DELETE)
	{
	  /* Only run through /etc/passwd if we really have something to
	     change.  */
	  const char *file_tmp = "/passwd.tmpXXXXXX";
	  char *passwd_tmp = alloca (strlen (files_etc_dir) + strlen (file_tmp) + 1);
	  char *passwd_orig = alloca (strlen (files_etc_dir) + 8);
	  char *passwd_old = alloca (strlen (files_etc_dir) + 12);
	  struct stat passwd_stat;
	  struct passwd *pw; /* passwd struct obtained from fgetpwent() */
	  FILE *oldpf, *newpf;
	  int gotit, newpf_fd;
	  char *cp;

	  cp = stpcpy (passwd_tmp, files_etc_dir);
	  strcpy (cp, file_tmp);
	  cp = stpcpy (passwd_orig, files_etc_dir);
	  strcpy (cp, "/passwd");
	  cp = stpcpy (passwd_old, passwd_orig);
	  strcpy (cp, ".old");

	  if ((oldpf = fopen (passwd_orig, "r")) == NULL)
	    {
	      fprintf (stderr, _("Can't open `%s': %m\n"), passwd_orig);
	      retval = -1;
	      goto error_passwd;
	    }
          if (fstat (fileno (oldpf), &passwd_stat) < 0)
            {
	      fprintf (stderr, _("Can't stat `%s': %m\n"), passwd_orig);
              fclose (oldpf);
	      retval = -1;
              goto error_passwd;
            }

#ifdef WITH_SELINUX
          security_context_t prev_context;
          if (set_default_context (passwd_orig, &prev_context) < 0)
            {
              fclose (oldpf);
              retval = -1;
              goto error_passwd;
            }
#endif
	  /* Open a temp passwd file */
	  newpf_fd = mkstemp (passwd_tmp);
#ifdef WITH_SELINUX
          if (restore_default_context (prev_context) < 0)
	    {
	      if (newpf_fd >= 0)
		close (newpf_fd);
              fclose (oldpf);
              retval = -1;
              goto error_passwd;
	    }
#endif
	  if (newpf_fd == -1)
	    {
	      fprintf (stderr, _("Can't create `%s': %m\n"),
		       passwd_orig);
	      fclose (oldpf);
	      retval = -1;
	      goto error_passwd;
	    }
          if (fchmod (newpf_fd, passwd_stat.st_mode) < 0)
	    {
	      fprintf (stderr,
		       _("Cannot change permissions for `%s': %s\n"),
		       passwd_tmp, strerror (errno));
	      fclose (oldpf);
	      close (newpf_fd);
	      unlink (passwd_tmp);
	      retval = -1;
	      goto error_passwd;
	    }
          if (fchown (newpf_fd, passwd_stat.st_uid, passwd_stat.st_gid) < 0)
	    {
	      fprintf (stderr,
		       _("Cannot change owner/group for `%s': %s\n"),
		       passwd_tmp, strerror (errno));
	      fclose (oldpf);
	      close (newpf_fd);
	      unlink (passwd_tmp);
	      retval = -1;
	      goto error_passwd;
	    }
	  if (copy_xattr (passwd_orig, passwd_tmp) != 0)
	    {
	      fclose (oldpf);
	      close (newpf_fd);
	      unlink (passwd_tmp);
	      retval = -1;
	      goto error_passwd;
	    }
	  newpf = fdopen (newpf_fd, "w+");
	  if (newpf == NULL)
	    {
	      fprintf (stderr, _("Can't open `%s': %m\n"), passwd_tmp);
	      fclose (oldpf);
	      close (newpf_fd);
	      unlink (passwd_tmp);
	      retval = -1;
	      goto error_passwd;
	    }

	  gotit = 0;

	  /* Loop over all passwd entries */
	  while ((pw = fgetpwent (oldpf)) != NULL)
	    {
	      if (data->todo == DO_CREATE)
		{
		  /* insert the new user before we find a user with a
		     higher UID or before we find a +/- character. */
		  if (!gotit &&
		      (/* data->pw.pw_uid < pw->pw_uid || XXX not yet? */
		       pw->pw_name[0] == '+' ||
		       pw->pw_name[0] == '-'))
		    {
		      /* write the passwd entry to tmp file */
		      if (putpwent (&data->pw, newpf) < 0)
			{
			  fprintf (stderr,
				   _("Error while writing `%s': %m\n"),
				   passwd_tmp);
			  fclose (oldpf);
			  fclose (newpf);
			  retval = -1;
			  goto error_passwd;
			}
		      gotit = 1;
		    }
		}
	      else if (data->todo == DO_DELETE)
		{
		  if (data->pw.pw_uid == pw->pw_uid &&
		      data->pw.pw_gid == pw->pw_gid &&
		      strcmp (data->pw.pw_name, pw->pw_name) == 0)
		    {
		      gotit = 1;
		      continue;
		    }
		}
	      else
		{
		  /* check if this is the uid we want to change. A few
		     sanity checks added for consistency. */
		  if (data->pw.pw_uid == pw->pw_uid &&
		      data->pw.pw_gid == pw->pw_gid &&
		      strcmp (data->pw.pw_name, pw->pw_name) == 0 &&
		      !gotit)
		    {
		      if (data->newpassword && !data->use_shadow)
			pw->pw_passwd = data->newpassword;
		      if (data->new_name)
			pw->pw_name = data->new_name;
		      if (data->new_shell)
			pw->pw_shell = data->new_shell;
		      if (data->new_gecos)
			pw->pw_gecos = data->new_gecos;
		      if (data->new_home)
			pw->pw_dir = data->new_home;
		      if (data->have_new_uid)
			pw->pw_uid = data->new_uid;
		      if (data->have_new_gid)
			pw->pw_gid = data->new_gid;
		      gotit = 1;
		    }
		}

	      /* write the passwd entry to tmp file */
	      if (putpwent (pw, newpf) < 0)
		{
		  fprintf (stderr,
			   _("Error while writing `%s': %m\n"), passwd_tmp);
		  fclose (oldpf);
		  fclose (newpf);
		  retval = -1;
		  goto error_passwd;
		}
	    }

	  if (data->todo == DO_CREATE && !gotit)
	    {
	      /* write the passwd entry to tmp file */
	      if (putpwent (&data->pw, newpf) < 0)
		{
		  fprintf (stderr,
			   _("Error while writing `%s': %m\n"), passwd_tmp);
		  fclose (oldpf);
		  fclose (newpf);
		  retval = -1;
		  goto error_passwd;
		}
	    }
	  else if (data->todo == DO_DELETE && !gotit)
	    {
	      fprintf (stderr,
		       _("User not found (and not deleted): %s\n"),
		       data->pw.pw_name);
	      retval = -1;
	    }

	  if (fclose (oldpf) != 0)
	    {
	      fprintf (stderr,
		       _("Error while closing `%s': %m\n"), passwd_orig);
	      fclose (newpf);
	      retval = -1;
	      goto error_passwd;
	    }

	  if (fflush (newpf) != 0)
	    {
	      fprintf (stderr,
		       _("Error while writing to disk `%s': %m\n"),
		       passwd_tmp);
	      fclose (newpf);
	      retval = -1;
	      goto error_passwd;
	    }

	  if (fsync (fileno(newpf)) != 0)
	    {
	      fprintf (stderr,
		       _("Error while syncing to disk `%s': %m\n"),
		       passwd_tmp);
	      fclose (newpf);
	      retval = -1;
	      goto error_passwd;
	    }


	  if (fclose (newpf) != 0)
	    {
	      fprintf (stderr,
		       _("Error while closing `%s': %m\n"), passwd_tmp);
	      retval = -1;
	      goto error_passwd;
	    }

	  unlink (passwd_old);
	  if (link (passwd_orig, passwd_old) < 0)
	    fprintf (stderr,
		     _("Warning: cannot create backup file `%s': %m\n"),
                     passwd_old);
	  if (rename (passwd_tmp, passwd_orig) < 0)
	    {
	      fprintf (stderr,
		       _("Error while renaming `%s': %m\n"), passwd_tmp);
	      retval = -1;
	      goto error_passwd;
	    }
	error_passwd:
	  unlink (passwd_tmp);
	}

      /* If we use shadow data, check if we need to change here
	 something, too. But do this only, if there no error occured
	 before.  */
      if (data->use_shadow && retval == 0 &&
	  (data->todo == DO_CREATE || data->todo == DO_CREATE_SHADOW ||
	   data->todo == DO_DELETE || data->todo == DO_DELETE_SHADOW ||
	   data->new_name || data->newpassword || data->sp_changed))
        {
	  const char *file_tmp = "/shadow.tmpXXXXXX";
	  char *shadow_tmp = alloca (strlen (files_etc_dir) +
				     strlen (file_tmp) + 1);
	  char *shadow_orig = alloca (strlen (files_etc_dir) + 8);
	  char *shadow_old = alloca (strlen (files_etc_dir) + 12);
          struct stat shadow_stat;
          struct spwd *sp; /* shadow struct obtained from fgetspent() */
          FILE *oldpf, *newpf;
          int gotit, newpf_fd;
	  char *cp;

	  cp = stpcpy (shadow_tmp, files_etc_dir);
	  strcpy (cp, file_tmp);
	  cp = stpcpy (shadow_orig, files_etc_dir);
	  strcpy (cp, "/shadow");
	  cp = stpcpy (shadow_old, shadow_orig);
	  strcpy (cp, ".old");

          /* Open the shadow file for reading. We can't use getspent and
             friends here, because they go through the YP maps, too. */
          if ((oldpf = fopen (shadow_orig, "r")) == NULL)
            {
	      fprintf (stderr, _("Can't open `%s': %m\n"), shadow_orig);
	      retval = -1;
              goto error_shadow;
            }
          if (fstat (fileno (oldpf), &shadow_stat) < 0)
            {
	      fprintf (stderr, _("Can't stat `%s': %m\n"), shadow_orig);
              fclose (oldpf);
	      retval = -1;
              goto error_shadow;
            }

#ifdef WITH_SELINUX
          security_context_t prev_context;
          if (set_default_context (shadow_orig, &prev_context) < 0)
            {
              fclose (oldpf);
              retval = -1;
              goto error_shadow;
            }
#endif
          /* Open a temp shadow file */
          newpf_fd = mkstemp (shadow_tmp);
#ifdef WITH_SELINUX
          if (restore_default_context (prev_context) < 0)
	    {
	      if (newpf_fd >= 0)
		close (newpf_fd);
              fclose (oldpf);
              retval = -1;
              goto error_shadow;
	    }
#endif
          if (newpf_fd == -1)
            {
	      fprintf (stderr, _("Can't create `%s': %m\n"),
		       shadow_orig);
              fclose (oldpf);
	      retval = -1;
              goto error_shadow;
            }
          if (fchmod (newpf_fd, shadow_stat.st_mode) < 0)
	    {
	      fprintf (stderr,
		       _("Cannot change permissions for `%s': %s\n"),
		       shadow_tmp, strerror (errno));
	      fclose (oldpf);
	      close (newpf_fd);
	      unlink (shadow_tmp);
	      retval = -1;
	      goto error_shadow;
	    }
          if (fchown (newpf_fd, shadow_stat.st_uid, shadow_stat.st_gid) < 0)
	    {
	      fprintf (stderr,
		       _("Cannot change owner/group for `%s': %s\n"),
		       shadow_tmp, strerror (errno));
	      fclose (oldpf);
	      close (newpf_fd);
	      unlink (shadow_tmp);
	      retval = -1;
	      goto error_shadow;
	    }
	  if (copy_xattr (shadow_orig, shadow_tmp) != 0)
	    {
	      fclose (oldpf);
	      close (newpf_fd);
	      unlink (shadow_tmp);
	      retval = -1;
	      goto error_shadow;
	    }
          newpf = fdopen (newpf_fd, "w+");
          if (newpf == NULL)
            {
	      fprintf (stderr, _("Can't open `%s': %m\n"), shadow_tmp);
              fclose (oldpf);
              close (newpf_fd);
	      unlink (shadow_tmp);
	      retval = -1;
              goto error_shadow;
            }

          gotit = 0;

          /* Loop over all passwd entries */
          while ((sp = fgetspent (oldpf)) != NULL)
            {
	      if (data->todo == DO_CREATE ||
		  data->todo == DO_CREATE_SHADOW)
		{
		  /* insert the new user before we find a +/- character
		     or an old entry from a deleted user. */
		  if (!gotit &&
		      (sp->sp_namp[0] == '+' || sp->sp_namp[0] == '-' ||
		       strcmp (sp->sp_namp, data->sp.sp_namp) == 0))
		    {
		      /* write the passwd entry to tmp file */
		      if (putspent (&data->sp, newpf) < 0)
			{
			  fprintf (stderr, _("Error while writing `%s': %m\n"),
                                  shadow_tmp);
			  fclose (oldpf);
			  fclose (newpf);
			  retval = -1;
			  goto error_shadow;
			}
		      gotit = 1;
		    }
		}
	      else if (data->todo == DO_DELETE ||
		       data->todo == DO_DELETE_SHADOW)
		{
		  if (strcmp (data->pw.pw_name, sp->sp_namp) == 0)
		    {
		      gotit = 1;
		      continue;
		    }
		}
	      else
		/* check if this is the uid we want to change. A few
		   sanity checks added for consistency. */
		if (!gotit && strcmp (data->pw.pw_name, sp->sp_namp) == 0)
		  {
		    if (data->newpassword)
		      sp->sp_pwdp = data->newpassword;

		    if (data->new_name)
		      sp->sp_namp = data->new_name;

		    if (data->sp_changed)
		      {
			/* if they have changed, they are different. If not,
			   they are equal, so copying them doesn't matter.  */
			sp->sp_max = data->spn.sp_max;
			sp->sp_min = data->spn.sp_min;
			sp->sp_warn = data->spn.sp_warn;
			sp->sp_inact = data->spn.sp_inact;
			sp->sp_lstchg = data->spn.sp_lstchg;
			sp->sp_expire = data->spn.sp_expire;
		      }

		    gotit = 1;
		  }

	      /* Write the entry only if we don't create a new
		 account or if this is not a duplicate of the new
		 user account.  */
	      if ((data->todo != DO_CREATE &&
		   data->todo != DO_CREATE_SHADOW) ||
		  strcmp (sp->sp_namp, data->sp.sp_namp) != 0)
		{
		  /* write the passwd entry to tmp file */
		  if (putspent (sp, newpf) < 0)
		    {
		      fprintf (stderr, _(" Error while writing `%s': %m\n"),
                               shadow_tmp);
		      fclose (oldpf);
		      fclose (newpf);
		      retval = -1;
		      goto error_shadow;
		    }
		}
            }
	  if ((data->todo == DO_CREATE || data->todo == DO_CREATE_SHADOW)
	      && !gotit)
	    {
	      /* Add the new user at the end. */
	      if (putspent (&data->sp, newpf) < 0)
		{
		  fprintf (stderr, _("Error while writing `%s': %m\n"),
			   shadow_tmp);
		  fclose (oldpf);
		  fclose (newpf);
		  retval = -1;
		  goto error_shadow;
		}
	    }
	  if (fclose (oldpf) != 0)
	    {
	      fprintf (stderr, _("Error while closing `%s': %m\n"),
		       shadow_orig);
	      fclose (newpf);
	      retval = -1;
	      goto error_shadow;
	    }

	  if (fflush (newpf) != 0)
	    {
	      fprintf (stderr,
		       _("Error while writing to disk `%s': %m\n"),
		       shadow_tmp);
	      fclose (newpf);
	      retval = -1;
	      goto error_shadow;
	    }

	  if (fsync (fileno(newpf)) != 0)
	    {
	      fprintf (stderr,
		       _("Error while syncing to disk `%s': %m\n"),
		       shadow_tmp);
	      fclose (newpf);
	      retval = -1;
	      goto error_shadow;
	    }

	  if (fclose (newpf) != 0)
	    {
	      fprintf (stderr, _("Error while closing `%s': %m\n"),
		       shadow_tmp);
	      retval = -1;
	      goto error_shadow;
	    }
          unlink (shadow_old);
	  if (link (shadow_orig, shadow_old) < 0)
	    fprintf (stderr, _("Warning: cannot create backup file `%s': %m\n"),
		     shadow_old);
          if (rename (shadow_tmp, shadow_orig) < 0)
	    {
	      fprintf (stderr, _("Error while renaming `%s': %m\n"),
		       shadow_tmp);
	      retval = -1;
	      goto error_shadow;
	    }
        error_shadow:
          unlink (shadow_tmp);
        }

      /* Don't unlock if program itself helds lock.  */
      if (!is_locked)
	ulckpwdf ();
    }
  else if (data->service == S_YP)
    {
      struct yppasswd yppwd;
      CLIENT *clnt;
      char *master = getnismaster();
      struct timeval TIMEOUT = {25, 0}; /* total timeout */
      int error, status;

      /* Changing shadow information is not supported.  */
      if (data->sp_changed)
	return -1;

      if (master == NULL)
	return -1;

      /* Initialize password information */
      memset (&yppwd, '\0', sizeof (yppwd));
      yppwd.newpw.pw_passwd = data->pw.pw_passwd;
      yppwd.newpw.pw_name = data->pw.pw_name;
      yppwd.newpw.pw_uid = data->pw.pw_uid;
      yppwd.newpw.pw_gid = data->pw.pw_gid;
      if (data->new_gecos)
	yppwd.newpw.pw_gecos = data->new_gecos;
      else
	yppwd.newpw.pw_gecos = data->pw.pw_gecos;
      yppwd.newpw.pw_dir = data->pw.pw_dir;
      if (data->new_shell)
	yppwd.newpw.pw_shell = data->new_shell;
      else
	yppwd.newpw.pw_shell = data->pw.pw_shell;
      if (data->oldclearpwd != NULL)
	yppwd.oldpass = data->oldclearpwd;
      else
	yppwd.oldpass = (char *)"";

      clnt = clnt_create (master, YPPASSWDPROG, YPPASSWDVERS, "udp");
      clnt->cl_auth = authunix_create_default ();
      memset (&status, '\0', sizeof (status));
      error = clnt_call (clnt, YPPASSWDPROC_UPDATE,
			 (xdrproc_t) xdr_yppasswd, (caddr_t) &yppwd,
			 (xdrproc_t) xdr_int, (caddr_t) &status, TIMEOUT);
      if (error || status)
	{
	  if (error)
	    clnt_perrno (error);
	  else
	    fprintf (stderr, _("Error while changing the NIS data.\n"));
	  retval = -1;
	}
    }
  else if (data->service == S_NISPLUS)
    {
      retval = npd_upd_pwd ("", data);
      if (retval != 0)
	{
	  fprintf (stderr, _("Error while changing the NIS+ data.\n"));
	  retval = -1;
	}
    }
#ifdef USE_LDAP
  else if (data->service == S_LDAP)
    {
      ldap_session_t *session = NULL;

      session = create_ldap_session (LDAP_PATH_CONF);

      if (session == NULL)
	retval = -1;
      else
	{
	  if (data->todo == DO_CREATE)
	    retval = ldap_create_user (session, &(data->pw), &(data->sp),
				       data->binddn, data->oldclearpwd);
	  else if (data->todo == DO_DELETE)
	    retval = ldap_delete_user (session, data->pw.pw_name,
				       data->binddn, data->oldclearpwd);
	  else
	    {
	      /* XXX retval will be overwritten!!! */
	      if (data->new_shell)
		retval = ldap_update_user (session, data->pw.pw_name,
					   data->binddn, data->oldclearpwd,
					   "loginShell", data->new_shell);
	      if (data->new_gecos)
		retval = ldap_update_user (session, data->pw.pw_name,
					   data->binddn, data->oldclearpwd,
					   "gecos", data->new_gecos);
	      if (data->new_name)
		retval = ldap_update_user (session, data->pw.pw_name,
					   data->binddn, data->oldclearpwd,
					   "uid", data->new_name);
	      if (data->have_new_uid)
		{
		  char buf[100];

		  snprintf (buf, sizeof (buf), "%u", data->new_uid);
		  retval = ldap_update_user (session, data->pw.pw_name,
					     data->binddn, data->oldclearpwd,
					     "uidNumber", buf);
		}
	      if (data->have_new_gid)
		{
		  char buf[100];

		  snprintf (buf, sizeof (buf), "%u", data->new_gid);
		  retval = ldap_update_user (session, data->pw.pw_name,
					     data->binddn, data->oldclearpwd,
					     "gidNumber", buf);
		}
	      if (data->new_home)
		retval = ldap_update_user (session, data->pw.pw_name,
					   data->binddn, data->oldclearpwd,
					   "homeDirectory", data->new_home);

	      if (data->sp_changed)
		{
		  char buf[200];

		  snprintf (buf, sizeof (buf), "%ld", data->spn.sp_min);
		  retval = ldap_update_user (session, data->pw.pw_name,
					     data->binddn, data->oldclearpwd,
					     "shadowMin", buf);
		  snprintf (buf, sizeof (buf),"%ld", data->spn.sp_max);
		  retval = ldap_update_user (session, data->pw.pw_name,
					     data->binddn, data->oldclearpwd,
					     "shadowMax", buf);
		  snprintf (buf, sizeof (buf),"%ld", data->spn.sp_warn);
		  retval = ldap_update_user (session, data->pw.pw_name,
					     data->binddn, data->oldclearpwd,
					     "shadowWarning", buf);
		  snprintf (buf, sizeof (buf),"%ld", data->spn.sp_inact);
		  retval = ldap_update_user (session, data->pw.pw_name,
					     data->binddn, data->oldclearpwd,
					     "shadowInactive", buf);
		  snprintf (buf, sizeof (buf),"%ld", data->spn.sp_lstchg);
		  retval = ldap_update_user (session, data->pw.pw_name,
					     data->binddn, data->oldclearpwd,
					     "shadowLastChange", buf);
		  snprintf (buf, sizeof (buf),"%ld", data->spn.sp_expire);
		  retval = ldap_update_user (session, data->pw.pw_name,
					     data->binddn, data->oldclearpwd,
					     "shadowExpire", buf);
		}

	      if (data->newpassword)
		{
		  const char *cryptstr = "{crypt}";
		  char buffer[strlen (data->newpassword) +
			      strlen (cryptstr) + 1];
		  snprintf (buffer, sizeof (buffer), "%s%s", cryptstr,
			    data->newpassword);
		  retval = ldap_update_user (session, data->pw.pw_name,
					     data->binddn, data->oldclearpwd,
					     "userPassword", buffer);
		}
	    }
	  if (retval != 0)
	    fprintf (stderr,
		     _("LDAP information update failed: %s\n"),
		     ldap_err2string (retval));

	  close_ldap_session (session);
	}
    }
#endif
  else
    {
      fprintf (stderr, _("Unknown service %d.\n"), data->service);
      retval = -1;
    }

  return retval;
}
