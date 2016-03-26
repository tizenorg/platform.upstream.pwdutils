/* Copyright (C) 2003, 2005, 2010 Thorsten Kukuk
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
#include "group.h"
#include "yppasswd.h"
#include "read-files.h"

void
free_group_t (group_t *data)
{
  unsigned int i;

  if (data == NULL)
    return;

  if (data->new_name)
    free (data->new_name);
  if (data->grpbuffer)
    free (data->grpbuffer);
  if (data->newpassword)
    free (data->newpassword);
  if (data->oldclearpwd)
    free (data->oldclearpwd);
  if (data->new_gr_mem)
    {
      for (i = 0; data->new_gr_mem[i]; i++)
	{
	  if (data->new_gr_mem[i])
	    free (data->new_gr_mem[i]);
	}
      free (data->new_gr_mem);
    }
  if (data->binddn)
    free (data->binddn);
  free (data);
}

group_t *
find_group_data (const char *name, gid_t gid, const char *use_service)
{
  enum nss_status (*nss_getgrnam_r)(const char *gr_name, struct group *grp,
                                    char *buffer, size_t buflen, int *errnop);
  enum nss_status (*nss_getgrgid_r)(gid_t grpid, struct group *grp,
                                    char *buffer, size_t buflen, int *errnop);
  enum nss_status status;
  void *nss_handle = NULL;
  group_t *data;
  struct nsw *nswp;
  int i;

  data = calloc (1, sizeof (group_t));
  if (data == NULL)
    return NULL;

  data->service = S_NONE;

  /* UNIX passwords area */
  if (use_service)
    {
      nswp = calloc (1, sizeof (struct nsw));
      if (nswp == NULL)
	return data;

      nswp->name = strdup ("group");
      nswp->orderc = 1;
      nswp->orders = calloc (2, sizeof (char *));
      nswp->orders[0] = strdup (use_service);
      nswp->orders[1] = NULL;
    }
  else
    nswp = _getnswbyname ("group");
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
          nss_getgrnam_r = files_getgrnam_r;
	  nss_getgrgid_r = files_getgrgid_r;
	  /* Get group file entry... */
	  do {
	    errno = 0;
	    data->grpbuflen += 1024;
	    data->grpbuffer = realloc (data->grpbuffer, data->grpbuflen);
	    if (name)
	      status = (*nss_getgrnam_r)(name, &data->gr, data->grpbuffer,
					 data->grpbuflen, &errno);
	    else
	      status = (*nss_getgrgid_r)(gid, &data->gr, data->grpbuffer,
					 data->grpbuflen, &errno);

	  } while (status == NSS_STATUS_TRYAGAIN && errno == ERANGE);

	  if (status != NSS_STATUS_SUCCESS)
	    {
	      free (data->grpbuffer);
	      data->grpbuffer = NULL;
	      data->grpbuflen = 0;
	      if (strcasecmp ("compat", cmpptr) == 0)
		{
		  struct nsw *nswp2 = _getnswbyname ("group_compat");

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
          nss_getgrnam_r = dlsym (nss_handle, "_nss_nis_getgrnam_r");
          nss_getgrgid_r = dlsym (nss_handle, "_nss_nis_getgrgid_r");
          if (dlerror () != NULL)
            {
              dlclose (nss_handle);
              continue;
            }

	  /* Get NIS group entry... */
	  do {
	    errno = 0;
	    data->grpbuflen += 1024;
	    data->grpbuffer = realloc (data->grpbuffer, data->grpbuflen);
	    if (name)
	      status = (*nss_getgrnam_r)(name, &data->gr, data->grpbuffer,
					 data->grpbuflen, &errno);
	    else
	      status = (*nss_getgrgid_r)(gid, &data->gr, data->grpbuffer,
					 data->grpbuflen, &errno);
	  } while (status == NSS_STATUS_TRYAGAIN && errno == ERANGE);

	  if (status != NSS_STATUS_SUCCESS)
	    {
	      dlclose (nss_handle);
	      free (data->grpbuffer);
	      data->grpbuffer = NULL;
	      data->grpbuflen = 0;
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
          nss_getgrnam_r = dlsym (nss_handle, "_nss_nisplus_getgrnam_r");
          nss_getgrgid_r = dlsym (nss_handle, "_nss_nisplus_getgrgid_r");
          if (dlerror () != NULL)
            {
              dlclose (nss_handle);
              continue;
            }

	  /* Get group NIS+ entry... */
	  do {
            errno = 0;
	    data->grpbuflen += 1024;
	    data->grpbuffer = realloc (data->grpbuffer, data->grpbuflen);
	    if (name)
	      status = (*nss_getgrnam_r)(name, &data->gr, data->grpbuffer,
					 data->grpbuflen, &errno);
	    else
	      status = (*nss_getgrgid_r)(gid, &data->gr, data->grpbuffer,
					 data->grpbuflen, &errno);

	  } while (status == NSS_STATUS_TRYAGAIN && errno == ERANGE);

	  if (status != NSS_STATUS_SUCCESS)
	    {
	      dlclose (nss_handle);
	      free (data->grpbuffer);
	      data->grpbuffer = NULL;
	      data->grpbuflen = 0;
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
          nss_getgrnam_r = dlsym (nss_handle, "_nss_ldap_getgrnam_r");
          nss_getgrgid_r = dlsym (nss_handle, "_nss_ldap_getgrgid_r");
          if (dlerror () != NULL)
            {
              dlclose (nss_handle);
              continue;
            }

	  /* Get LDAP group entry... */
	  do {
            errno = 0;
	    data->grpbuflen += 1024;
	    data->grpbuffer = realloc (data->grpbuffer, data->grpbuflen);
	    if (name)
	      status = (*nss_getgrnam_r)(name, &data->gr, data->grpbuffer,
					 data->grpbuflen, &errno);
	    else
	      status = (*nss_getgrgid_r)(gid, &data->gr, data->grpbuffer,
					 data->grpbuflen, &errno);
	  } while (status == NSS_STATUS_TRYAGAIN && errno == ERANGE);

	  if (status != NSS_STATUS_SUCCESS)
	    {
	      dlclose (nss_handle);
	      free (data->grpbuffer);
	      data->grpbuffer = NULL;
	      data->grpbuflen = 0;
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

  if (data->service != S_LOCAL && data->service != S_NONE)
    dlclose (nss_handle);

  return data;
}

int
write_group_data (group_t *data, int is_locked)
{
  int retval = 0;

  if (data->service == S_LOCAL)
    {
      if (!is_locked && lock_database() != 0)
        {
	  fputs (_("Cannot lock group file: already locked.\n"), stderr);
	  retval = -1;
        }
      else if ((data->newpassword && !data->use_gshadow) ||
	       data->new_gr_mem || data->have_new_gid ||
	       data->new_name || data->todo == DO_CREATE ||
	       data->todo == DO_DELETE)
	{
	  /* Only run through /etc/group if we really have something to
	     change.  */
	  const char *file_tmp = "/group.tmpXXXXXX";
	  char *group_tmp = alloca (strlen (files_etc_dir) + strlen (file_tmp) + 1);
	  char *group_orig = alloca (strlen (files_etc_dir) + 8);
	  char *group_old = alloca (strlen (files_etc_dir) + 12);
	  struct stat group_stat;
	  struct group *gr; /* group struct obtained from fgetgrent() */
	  FILE *oldgf, *newgf;
	  int gotit, newgf_fd;
	  char *cp;

	  cp = stpcpy (group_tmp, files_etc_dir);
	  strcpy (cp, file_tmp);
	  cp = stpcpy (group_orig, files_etc_dir);
	  strcpy (cp, "/group");
	  cp = stpcpy (group_old, group_orig);
	  strcpy (cp, ".old");

	  if ((oldgf = fopen (group_orig, "r")) == NULL)
	    {
	      fprintf (stderr, _("Can't open `%s': %m\n"), group_orig);
	      retval = -1;
	      goto error_group;
	    }
          if (fstat (fileno (oldgf), &group_stat) < 0)
            {
	      fprintf (stderr, _("Can't stat `%s': %m\n"), group_orig);
              fclose (oldgf);
	      retval = -1;
              goto error_group;
            }

#ifdef WITH_SELINUX
	  security_context_t prev_context;
	  if (set_default_context (group_orig, &prev_context) < 0)
	    {
	      fclose (oldgf);
	      retval = -1;
	      goto error_group;
	    }
#endif
	  /* Open a temp group file */
	  newgf_fd = mkstemp (group_tmp);
#ifdef WITH_SELINUX
          if (restore_default_context (prev_context) < 0)
	    {
	      if (newgf_fd >= 0)
		close (newgf_fd);
	      fclose (oldgf);
	      retval = -1;
	      goto error_group;
	    }
#endif
	  if (newgf_fd == -1)
	    {
	      fprintf (stderr, _("Can't create `%s': %m\n"),
		       group_orig);
	      fclose (oldgf);
	      retval = -1;
	      goto error_group;
	    }
          if (fchmod (newgf_fd, group_stat.st_mode) < 0)
            {
              fprintf (stderr,
                       _("Cannot change permissions for `%s': %s\n"),
                       group_tmp, strerror (errno));
              fclose (oldgf);
              close (newgf_fd);
              unlink (group_tmp);
              retval = -1;
              goto error_group;
            }
          if (fchown (newgf_fd, group_stat.st_uid, group_stat.st_gid) < 0)
	                {
              fprintf (stderr,
                       _("Cannot change owner/group for `%s': %s\n"),
                       group_tmp, strerror (errno));
              fclose (oldgf);
              close (newgf_fd);
              unlink (group_tmp);
              retval = -1;
              goto error_group;
            }
	  if (copy_xattr (group_orig, group_tmp) != 0)
	    {
	      fclose (oldgf);
	      close (newgf_fd);
	      unlink (group_tmp);
	      retval = -1;
	      goto error_group;
	    }

	  newgf = fdopen (newgf_fd, "w+");
	  if (newgf == NULL)
	    {
	      fprintf (stderr, _("Can't open `%s': %m\n"), group_tmp);
	      fclose (oldgf);
	      close (newgf_fd);
	      unlink (group_tmp);
	      retval = -1;
	      goto error_group;
	    }

	  gotit = 0;

	  /* Loop over all group entries */
	  while ((gr = fgetgrent (oldgf)) != NULL)
	    {
	      if (data->todo == DO_CREATE)
		{
		  /* insert the new group before we find a group with a
		     higher GID or before we find a +/- character. */
		  if (!gotit &&
		      (/* data->gr.gr_gid < gr->gr_gid || XXX not yet? */
		       gr->gr_name[0] == '+' ||
		       gr->gr_name[0] == '-'))
		    {
		      /* write the group entry to tmp file */
		      if (putgrent (&data->gr, newgf) < 0)
			{
			  fprintf (stderr,
				   _("Error while writing `%s': %m\n"),
                                   group_tmp);
			  fclose (oldgf);
			  fclose (newgf);
			  retval = -1;
			  goto error_group;
			}
		      gotit = 1;
		    }
		}
	      else if (data->todo == DO_DELETE)
		{
		  if (data->gr.gr_gid == gr->gr_gid &&
                      strcmp (data->gr.gr_name, gr->gr_name) == 0)
                    {
                      gotit = 1;
                      continue;
                    }

		}
	      else
		{
		  /* check if this is the gid we want to change. A few
		     sanity checks added for consistency. */
		  if (data->gr.gr_gid == gr->gr_gid &&
		      !strcmp (data->gr.gr_name, gr->gr_name) && !gotit)
		    {
		      if (data->newpassword && !data->use_gshadow)
			gr->gr_passwd = data->newpassword;
		      if (data->new_gr_mem)
			gr->gr_mem = data->new_gr_mem;
		      if (data->have_new_gid)
			gr->gr_gid = data->new_gid;
		      if (data->new_name)
			gr->gr_name = data->new_name;
		      gotit = 1;
		    }
		}

	      /* write the group entry to tmp file */
	      if (putgrent (gr, newgf) < 0)
		{
		  fprintf (stderr,
			   _("Error while writing `%s': %m\n"),
                           group_tmp);
		  fclose (oldgf);
		  fclose (newgf);
		  retval = -1;
		  goto error_group;
		}
	    }
	  if (data->todo == DO_CREATE && !gotit)
	    {
	      /* write the group entry to tmp file */
	      if (putgrent (&data->gr, newgf) < 0)
		{
		  fprintf (stderr,
			   _("Error while writing `%s': %m\n"),
                           group_tmp);
		  fclose (oldgf);
		  fclose (newgf);
		  retval = -1;
		  goto error_group;
		}
	    }
          else if (data->todo == DO_DELETE && !gotit)
            {
              fprintf (stderr,
                       _("Group not found (and not deleted): %s\n"),
                       data->gr.gr_name);
              retval = -1;
            }

	  if (fclose (oldgf) != 0)
	    {
	      fprintf (stderr,
		       _("Error while closing `%s': %m\n"), group_orig);
	      fclose (newgf);
	      retval = -1;
	      goto error_group;
	    }

          if (fflush (newgf) != 0)
            {
              fprintf (stderr,
                       _("Error while writing to disk `%s': %m\n"),
                       group_tmp);
              fclose (newgf);
              retval = -1;
              goto error_group;
            }

          if (fsync (fileno(newgf)) != 0)
            {
              fprintf (stderr,
                       _("Error while syncing to disk `%s': %m\n"),
                       group_tmp);
              fclose (newgf);
              retval = -1;
              goto error_group;
            }

	  if (fclose (newgf) != 0)
	    {
	      fprintf (stderr,
		       _("Error while closing `%s': %m\n"), group_tmp);
	      retval = -1;
	      goto error_group;
	    }
	  unlink (group_old);
	  if (link (group_orig, group_old) < 0)
	    fprintf (stderr,
                     _("Warning: cannot create backup file `%s': %m\n"),
		     group_old);
	  if (rename (group_tmp, group_orig) < 0)
	    {
	      fprintf (stderr,
                       _("Error while renaming `%s': %m\n"), group_tmp);
              retval = -1;
              goto error_group;
            }
	error_group:
	  unlink (group_tmp);
	}

      if (!is_locked)
	ulckpwdf ();
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
            {
	      retval = ldap_create_group (session, &data->gr,
					  data->binddn, data->oldclearpwd);
            }
          else if (data->todo == DO_DELETE)
	    {
	      retval = ldap_delete_group (session, data->gr.gr_name,
					  data->binddn, data->oldclearpwd);
	    }
          else
            {
	      if (data->new_name)
		{
#if 0 /* XXX does not work */
		  retval = ldap_update_group (session, data->gr.gr_name,
					      data->binddn, data->oldclearpwd,
					      LDAP_MOD_REPLACE, "cn",
					      data->new_name);
#else
		  retval = -1;
#endif
		}
	      if (data->have_new_gid)
		{
		  char *buf;

		  if (asprintf (&buf, "%u", data->new_gid) < 1)
		    {
		      if (retval == 0)
			retval = LDAP_OTHER;
		    }
		  else
		    {
		      int rc;
		      rc = ldap_update_group (session, data->gr.gr_name,
					      data->binddn, data->oldclearpwd,
					      LDAP_MOD_REPLACE, "gidNumber",
					      buf);
		      free (buf);
		      if (retval == 0 && rc != LDAP_SUCCESS)
			retval = rc;
		    }
		}
	      if (data->new_gr_mem)
		{
		  unsigned int i;

		  /* At first, check if there is a new member and add this. */
		  for (i = 0; data->new_gr_mem[i] != 0; i++)
		    {
		      unsigned int j;
		      int found = 0;

		      for (j = 0; data->gr.gr_mem[j]; j++)
			{
			  if (strcmp (data->new_gr_mem[i],
				      data->gr.gr_mem[j]) == 0)
			    {
			      found = 1;
			      break;
			    }
			}
		      if (!found)
			{
			  int rc;
                          int first = 0;

                          if ( data->new_gr_mem[0] && !data->new_gr_mem[1] )
                            {
                              first = 1;
                            }
                          rc = ldap_add_groupmember (session, data->gr.gr_name,
			  		             data->binddn,
						     data->oldclearpwd,
						     data->new_gr_mem[i],first);
			  if (retval == 0 && rc != 0)
			    retval = rc;
			}
		    }

		  /* Now check, if there are entries missing and delete
		     them.  */
		  for (i = 0; data->gr.gr_mem[i] != 0; i++)
		    {
		      unsigned int j;
		      int found = 0;

		      for (j = 0; data->new_gr_mem[j]; j++)
			{
			  if (strcmp (data->gr.gr_mem[i],
				      data->new_gr_mem[j]) == 0)
			    {
			      found = 1;
			      break;
			    }
			}
		      if (!found)
			{
			  int rc;
                          int last = 0;

                          if (! data->new_gr_mem[0] )
                            {
                              last = 1;
                            }
                          rc = ldap_del_groupmember (session, data->gr.gr_name,
			  		             data->binddn,
					             data->oldclearpwd,
					             data->gr.gr_mem[i], last);
			  if (retval == 0 && rc != 0)
			    retval = rc;
			}
		    }
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
  else if (data->service == S_YP)
    {
      fprintf (stderr, _("Cannot modify/add NIS group entries.\n"));
      retval = -1;
    }
  else
    {
      fprintf (stderr, _("Unknown service %d.\n"), data->service);
      retval = -1;
    }

  return retval;
}
