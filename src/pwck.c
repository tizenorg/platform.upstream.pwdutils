/* Copyright (C) 2004, 2005, 2010, 2011 Thorsten Kukuk
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

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "i18n.h"
#include "yesno.h"
#include "public.h"
#include "read-files.h"

#define E_SUCCESS 0
#define E_USAGE 1
#define E_BAD_ENTRY 2
#define E_NO_FILE 3
#define E_PWDBUSY 4
#define E_FAILURE 5

#define SCALE DAY

char *files_etc_dir = "/etc";
int readonly = 0;

static void
print_usage (FILE *stream, const char *program)
{
  fprintf (stream, _("Usage: %s [-P path] [-q|-r|-s]\n"),
           program);
}

static void
print_help (const char *program)
{
  print_usage (stdout, program);
  fprintf (stdout, _("%s - check integrity of password files\n\n"), program);

  fputs (_("  -P path        Search passwd, shadow and group file in \"path\"\n"),
         stdout);
  fputs (_("  -q, --quiet    Don't print warnings, only errors\n"), stdout);
  fputs (_("  -r, --read-only Run in read-only mode, don't make changes\n"),
	 stdout);
  fputs (_("  -s, --sort     Sort the password file, no checks are done\n"),
	 stdout);
  fputs (_("      --help     Give this help list\n"), stdout);
  fputs (_("  -u, --usage    Give a short usage message\n"), stdout);
  fputs (_("  -v, --version  Print program version\n"), stdout);
}

static int
answer_yes (void)
{
  if (readonly)
    {
      printf (_("No\n"));
      return 0;
    }
  else
    return yesno ();
}

#define BLACKLIST_INITIAL_SIZE 512
#define BLACKLIST_INCREMENT 256
struct blacklist_t
{
  char *data;
  int current;
  int size;
};

/* returns TRUE if ent->blacklist contains name, else FALSE */
static bool_t
in_blacklist (const char *name, int namelen, struct blacklist_t *ent)
{
  char buf[namelen + 3];
  char *cp;

  if (ent->data == NULL)
    return FALSE;

  buf[0] = '|';
  cp = stpcpy (&buf[1], name);
  *cp++ = '|';
  *cp = '\0';
  return strstr (ent->data, buf) != NULL;
}

/* Support routines for remembering login names. The names are stored
   in a single string with `|' as separator. */
static void
blacklist_store_name (const char *name, struct blacklist_t *ent)
{
  int namelen = strlen (name);
  char *tmp;

  /* first call, setup cache */
  if (ent->size == 0)
    {
      ent->size = MAX (BLACKLIST_INITIAL_SIZE, 2 * namelen);
      ent->data = malloc (ent->size);
      if (ent->data == NULL)
        return;
      ent->data[0] = '|';
      ent->data[1] = '\0';
      ent->current = 1;
    }
  else
    {
      if (in_blacklist (name, namelen, ent))
        return;                 /* no duplicates */

      if (ent->current + namelen + 1 >= ent->size)
        {
          ent->size += MAX (BLACKLIST_INCREMENT, 2 * namelen);
          tmp = realloc (ent->data, ent->size);
          if (tmp == NULL)
            {
              free (ent->data);
              ent->size = 0;
              return;
            }
          ent->data = tmp;
        }
    }

  tmp = stpcpy (ent->data + ent->current, name);
  *tmp++ = '|';
  *tmp = '\0';
  ent->current += namelen + 1;

  return;
}

/* XXX move into the library.  */
static struct group *
files_getgrgid (gid_t gid)
{
  enum nss_status status;
  static int buflen = 256;
  static char *buffer = NULL;
  static struct group resultbuf;

  if (buffer == NULL)
    buffer = malloc (buflen);

  while ((status = files_getgrgid_r (gid, &resultbuf, buffer, buflen, &errno))
         == NSS_STATUS_TRYAGAIN && errno == ERANGE)
    {
      errno = 0;
      buflen += 256;
      buffer = realloc (buffer, buflen);
    }
  if (status == NSS_STATUS_SUCCESS)
    return &resultbuf;
  else
    return NULL;
}

static struct passwd *
files_getpwnam (const char *name)
{
  enum nss_status status;
  static int buflen = 256;
  static char *buffer = NULL;
  static struct passwd resultbuf;

  if (buffer == NULL)
    buffer = malloc (buflen);

  while ((status =
          files_getpwnam_r (name, &resultbuf, buffer, buflen,
                            &errno)) == NSS_STATUS_TRYAGAIN
         && errno == ERANGE)
    {
      errno = 0;
      buflen += 256;
      buffer = realloc (buffer, buflen);
    }
  if (status == NSS_STATUS_SUCCESS)
    return &resultbuf;
  else
    return NULL;
}

static int
loop_over_passwd_file (int quiet)
{
  struct stat passwd_stat;
  FILE *input, *output;
  int output_fd;
  char *buf = NULL;
  size_t buflen = 0;
  struct passwd res;
  int result = 0;
  struct blacklist_t blacklist = {NULL, 0, 0};
  int modified = 0;
  char *inputname = alloca (strlen (files_etc_dir) + 8);
  char *outputname = alloca (strlen (files_etc_dir) + 20);

  strcpy (inputname, files_etc_dir);
  strcat (inputname, "/passwd");
  strcpy (outputname, files_etc_dir);
  strcat (outputname, "/passwd.tmpXXXXXX");

  if (!quiet)
    printf (_("Checking `%s'\n"), inputname);

  input = fopen (inputname, "r");
  if (input == NULL)
    {
      fprintf (stderr, _("Can't open `%s': %m\n"), inputname);
      return E_NO_FILE;
    }

  if (fstat (fileno (input), &passwd_stat) < 0)
    {
      fprintf (stderr, _("Can't stat `%s': %m\n"), inputname);
      fclose (input);
      return E_NO_FILE;
    }

#ifdef WITH_SELINUX
  security_context_t prev_context;
  if (set_default_context (inputname, &prev_context) < 0)
    {
      fclose (input);
      return E_NO_FILE;
    }
#endif
  /* Open a temp passwd file */
  output_fd = mkstemp (outputname);
#ifdef WITH_SELINUX
  if (restore_default_context (prev_context) < 0)
    {
      if (output_fd >= 0)
	close (output_fd);
      fclose (input);
      return E_FAILURE;
    }
#endif
  if (output_fd == -1)
    {
      fprintf (stderr, _("Can't create `%s': %m\n"),
	       inputname);
      fclose (input);
      return E_NO_FILE;
    }
  if (fchmod (output_fd, passwd_stat.st_mode) < 0)
    {
      fprintf (stderr,
	       _("Cannot change permissions for `%s': %s\n"),
	       outputname, strerror (errno));
      fclose (input);
      close (output_fd);
      unlink (outputname);
      return E_NO_FILE;
    }
  if (fchown (output_fd, passwd_stat.st_uid, passwd_stat.st_gid) < 0)
    {
      fprintf (stderr,
	       _("Cannot change owner/group for `%s': %s\n"),
	       outputname, strerror (errno));
      fclose (input);
      close (output_fd);
      unlink (outputname);
      return E_NO_FILE;
    }
  if (copy_xattr (inputname, outputname) != 0)
    {
      fclose (input);
      close (output_fd);
      unlink (outputname);
      return E_NO_FILE;
    }
  output = fdopen (output_fd, "w+");
  if (output == NULL)
    {
      fprintf (stderr, _("Can't open `%s': %m\n"), outputname);
      fclose (input);
      close (output_fd);
      unlink (outputname);
      return E_NO_FILE;
    }

  while (!feof (input))
    {
      char *cp;
#if defined(HAVE_GETLINE)
      ssize_t n = getline (&buf, &buflen, input);
#elif defined (HAVE_GETDELIM)
      ssize_t n = getdelim (&buf, &buflen, '\n', input);
#else
      ssize_t n;

      if (buf == NULL)
        {
          buflen = 8096;
          buf = malloc (buflen);
        }
      buf[0] = '\0';
      fgets (buf, buflen - 1, input);
      if (buf != NULL)
        n = strlen (buf);
      else
        n = 0;
#endif /* HAVE_GETLINE / HAVE_GETDELIM */

      if (buf)
	cp = strdup (buf);
      else
	cp = strdup ("");

      /* Remove trailing '\n'.  */
      if (strlen(cp) > 0 && cp[strlen (cp) - 1] == '\n')
	cp[strlen (cp) - 1] = '\0';

      if (n < 1)
	{
	  if (feof (input))
	    continue;
	  result = E_BAD_ENTRY;
	  printf (_("Invalid password entry.\n"));
	  printf (_("Delete empty line? "));
	  if (answer_yes ())
	    {
	      free (cp);
	      modified = 1;
	      continue;
	    }
	  else
	    goto write_pw;
	}

      if (strcmp (cp, "+") == 0 || strcmp (cp, "-") == 0)
	goto write_pw;

      /* Comments are not allowed in /etc/passwd.  */
      if (strchr (cp, '#') != NULL)
	{
	  result = E_BAD_ENTRY;
	  printf (_("Invalid password entry with comment.\n"));
	  printf (_("Delete line `%s'? "), cp);
	  if (answer_yes ())
	    {
	      modified = 1;
	      free (cp);
	      continue;
	    }
	  else
	    goto write_pw;
	}

      /* Parse string in strict mode and report error.  */
      if (parse_pwent (buf, &res, 1) != 1)
	{
	  result = E_BAD_ENTRY;
	  printf (_("Invalid password entry.\n"));
	  printf (_("Delete line `%s'? "), cp);
	  if (answer_yes ())
	    {
	      modified = 1;
	      free (cp);
	      continue;
	    }
	  else
	    goto write_pw;
	}

      /* Check for invalid characters in username.  */
      if (cp[0] != '+' && cp[0] != '-' && check_name (res.pw_name) < 0)
	{
	  result = E_BAD_ENTRY;
	  printf (_("Invalid account name `%s'.\n"), res.pw_name);
	  printf (_("Delete line `%s'? "), cp);
	  if (answer_yes ())
	    {
	      modified = 1;
	      free (cp);
	      continue;
	    }
	  else
	    goto write_pw;
	}

      /* Check, if we saw this user name already.  */
      if (in_blacklist (res.pw_name, strlen (res.pw_name), &blacklist))
	{
	  result = E_BAD_ENTRY;
	  printf (_("Duplicate password entry\n"));
	  printf (_("Delete line `%s'? "), cp);
	  if (answer_yes ())
	    {
	      modified = 1;
	      free (cp);
	      continue;
	    }
	  else
	    goto write_pw;
	}
      /* Mark the username as seen, but after checking for duplicate!  */
      blacklist_store_name (res.pw_name, &blacklist);

      /* Check, if primary group exists.  */
      if (!quiet && getgrgid (res.pw_gid) == NULL &&
	  files_getgrgid (res.pw_gid) == NULL)
	{
	  result = E_BAD_ENTRY;
	  printf (_("User `%s': unknown group `%u'\n"),
		  res.pw_name, res.pw_gid);
	}

      /* Check, if the home directory exists.  */
      if (!quiet && cp[0] != '+' && cp[0] != '=' &&
	  access (res.pw_dir, F_OK))
	{
	  result = E_BAD_ENTRY;
	  printf (_("User `%s': directory `%s' does not exist.\n"),
		  res.pw_name, res.pw_dir);
	}

      /* Check, if shell is executable.  */
      if (!quiet && res.pw_shell && res.pw_shell[0]
	  && access (res.pw_shell, X_OK))
	{
	  result = E_BAD_ENTRY;
	  printf (_("User `%s': shell `%s' is not executable.\n"),
		  res.pw_name, res.pw_shell);
	}
    write_pw:
      fprintf (output, "%s\n", cp);
      free (cp);
    }


  fclose (input);
  fclose (output);
  if (modified)
    {
      char *oldname = alloca (strlen (files_etc_dir) + 20);
      strcpy (oldname, files_etc_dir);
      strcat (oldname, "/passwd.old");
      unlink (oldname);
      if (link (inputname, oldname) < 0)
	fprintf (stderr,
		 _("Warning: cannot create backup file `%s': %m\n"),
                 oldname);
      rename (outputname, inputname);
    }
  else
    unlink (outputname);

  return result;
}

static int
loop_over_shadow_file (int quiet)
{
  struct stat shadow_stat;
  FILE *input, *output;
  int output_fd;
  char *buf = NULL;
  size_t buflen = 0;
  struct spwd res;
  int result = 0;
  struct blacklist_t blacklist = {NULL, 0, 0};
  int modified = 0;
  char *inputname = alloca (strlen (files_etc_dir) + 8);
  char *outputname = alloca (strlen (files_etc_dir) + 20);

  strcpy (inputname, files_etc_dir);
  strcat (inputname, "/shadow");
  strcpy (outputname, files_etc_dir);
  strcat (outputname, "/shadow.tmpXXXXXX");

  input = fopen (inputname, "r");
  if (input == NULL)
    {
      /* fprintf (stderr, _("Can't open `%s': %m\n"), inputname); */
      return E_NO_FILE;
    }

  if (!quiet)
    printf (_("Checking `%s'.\n"), inputname);

  if (fstat (fileno (input), &shadow_stat) < 0)
    {
      fprintf (stderr, _("Can't stat `%s': %m\n"), inputname);
      fclose (input);
      return E_NO_FILE;
    }

#ifdef WITH_SELINUX
  security_context_t prev_context;
  if (set_default_context (inputname, &prev_context) < 0)
    {
      fclose (input);
      return E_NO_FILE;
    }
#endif
  /* Open a temp shadow file */
  output_fd = mkstemp (outputname);
#ifdef WITH_SELINUX
  if (restore_default_context (prev_context) < 0)
    {
      if (output_fd >= 0)
	close (output_fd);
      fclose (input);
      return E_FAILURE;
    }
#endif
  if (output_fd == -1)
    {
      fprintf (stderr, _("Can't create `%s': %m\n"),
	       inputname);
      fclose (input);
      return E_NO_FILE;
    }
  if (fchmod (output_fd, shadow_stat.st_mode) < 0)
    {
      fprintf (stderr,
	       _("Cannot change permissions for `%s': %s\n"),
	       outputname, strerror (errno));
      fclose (input);
      close (output_fd);
      unlink (outputname);
      return E_NO_FILE;
    }
  if (fchown (output_fd, shadow_stat.st_uid, shadow_stat.st_gid) < 0)
    {
      fprintf (stderr,
	       _("Cannot change owner/group for `%s': %s\n"),
	       outputname, strerror (errno));
      fclose (input);
      close (output_fd);
      unlink (outputname);
      return E_NO_FILE;
    }
  if (copy_xattr (inputname, outputname) != 0)
    {
      fclose (input);
      close (output_fd);
      unlink (outputname);
      return E_NO_FILE;
    }
  output = fdopen (output_fd, "w+");
  if (output == NULL)
    {
      fprintf (stderr, _("Can't open `%s': %m\n"), outputname);
      fclose (input);
      close (output_fd);
      unlink (outputname);
      return E_NO_FILE;
    }

  while (!feof (input))
    {
      char *cp;
#if defined(HAVE_GETLINE)
      ssize_t n = getline (&buf, &buflen, input);
#elif defined (HAVE_GETDELIM)
      ssize_t n = getdelim (&buf, &buflen, '\n', input);
#else
      ssize_t n;

      if (buf == NULL)
        {
          buflen = 8096;
          buf = malloc (buflen);
        }
      buf[0] = '\0';
      fgets (buf, buflen - 1, input);
      if (buf != NULL)
        n = strlen (buf);
      else
        n = 0;
#endif /* HAVE_GETLINE / HAVE_GETDELIM */

      if (buf)
	cp = strdup (buf);
      else
	cp = strdup ("");

      /* Remove trailing '\n'.  */
      if (strlen (cp) > 0 && cp[strlen (cp) - 1] == '\n')
	cp[strlen (cp) - 1] = '\0';

      if (n < 1)
	{
	  if (feof (input))
	    continue;
	  result = E_BAD_ENTRY;
	  printf (_("Invalid shadow entry.\n"));
	  printf (_("Delete empty line? "));
	  if (answer_yes ())
	    {
	      modified = 1;
	      free (cp);
	      continue;
	    }
	  else
	    goto write_pw;
	}

      if (strcmp (cp, "+") == 0 || strcmp (cp, "-") == 0)
        goto write_pw;

      /* Comments are not allowed in /etc/shadow.  */
      if (strchr (cp, '#') != NULL)
	{
	  result = E_BAD_ENTRY;
	  printf (_("Invalid shadow entry with comment.\n"));
	  printf (_("Delete line `%s'? "), cp);
	  if (answer_yes ())
	    {
	      modified = 1;
	      continue;
	    }
	  else
	    goto write_pw;
	}

      /* Parse string in strict mode and report error.  */
      if (parse_spent (buf, &res, 1) != 1)
	{
	  result = E_BAD_ENTRY;
	  printf (_("Invalid shadow entry.\n"));
	  printf (_("Delete line `%s'? "), cp);
	  if (answer_yes ())
	    {
	      modified = 1;
	      free (cp);
	      continue;
	    }
	  else
	    goto write_pw;
	}

      /* Check for invalid characters in username.  */
      if (cp[0] != '+' && cp[0] != '-' && check_name (res.sp_namp) < 0)
	{
	  result = E_BAD_ENTRY;
	  printf (_("Invalid account name `%s'.\n"), res.sp_namp);
	  printf (_("Delete line `%s'? "), cp);
	  if (answer_yes ())
	    {
	      modified = 1;
	      free (cp);
	      continue;
	    }
	  else
	    goto write_pw;
	}

      /* Check, if we saw this user name already.  */
      if (in_blacklist (res.sp_namp, strlen (res.sp_namp), &blacklist))
	{
	  result = E_BAD_ENTRY;
	  printf (_("Duplicate shadow entry\n"));
	  printf (_("Delete line `%s'? "), cp);
	  if (answer_yes ())
	    {
	      modified = 1;
	      free (cp);
	      continue;
	    }
	  else
	    goto write_pw;
	}
      /* Mark the username as seen, but after checking for duplicate!  */
      blacklist_store_name (res.sp_namp, &blacklist);

      /* Check, if a passwd entry exist.  */
      if (cp[0] != '+' && cp[0] != '-' && files_getpwnam (res.sp_namp) == NULL)
	{
	  result = E_BAD_ENTRY;
	  printf (_("No matching password file entry.\n"));
	  printf (_("Delete line `%s'? "), cp);
	  if (answer_yes ())
	    {
	      modified = 1;
	      free (cp);
	      continue;
	    }
	  else
	    goto write_pw;
	}

      if (!quiet && res.sp_lstchg > time ((time_t *) 0) / SCALE)
	{
	  result = E_BAD_ENTRY;
	  printf (_("User `%s': last password change in the future.\n"),
		  res.sp_namp);
	}

    write_pw:
      fprintf (output, "%s\n", cp);
      free (cp);
    }


  fclose (input);
  fclose (output);
  if (modified)
    {
      char *oldname = alloca (strlen (files_etc_dir) + 20);
      strcpy (oldname, files_etc_dir);
      strcat (oldname, "/shadow.old");
      unlink (oldname);
      if (link (inputname, oldname) < 0)
	fprintf (stderr,
		 _("Warning: cannot create backup file `%s': %m\n"),
                 oldname);
      rename (outputname, inputname);
    }
  else
    unlink (outputname);

  return result;
}

/* XXX move n library.  */
static struct passwd *
files_getpwent (void)
{
  enum nss_status status;
  int buflen = 256;
  char *buffer = NULL;
  struct passwd *resultbuf = malloc (sizeof (struct passwd));

  if (buffer == NULL)
    buffer = malloc (buflen);

  while ((status = files_getpwent_r (resultbuf, buffer, buflen, &errno))
         == NSS_STATUS_TRYAGAIN && errno == ERANGE)
    {
      errno = 0;
      buflen += 256;
      buffer = realloc (buffer, buflen);
    }
  if (status == NSS_STATUS_SUCCESS)
    return resultbuf;
  else
    return NULL;
}

struct passwd_list {
  struct passwd *pwd;
  struct passwd_list *next;
};

static int
sort_passwd_file (void)
{
  struct passwd *pwd;
  struct passwd_list *ptr = NULL;
  int retval = 0;

  while ((pwd = files_getpwent ()))
    {
      if (pwd->pw_name[0] == '+' || pwd->pw_name[0] == '-')
	break;

      if (ptr == NULL)
	{
	  ptr = malloc (sizeof (struct passwd_list));
	  if (ptr == NULL)
	    {
	      fputs ("running out of memory!\n", stderr);
	      exit (E_FAILURE);
	    }

	  ptr->pwd = pwd;
	  ptr->next = NULL;
	}
      else
	{
	  struct passwd_list *next = ptr;

	  while (next->next && next->pwd->pw_uid < pwd->pw_uid)
	    next = next->next;

	  if (next->next == NULL)
	    {
	      next->next = malloc (sizeof (struct passwd_list));

	      if (next->next == NULL)
		{
		  fputs ("running out of memory!\n", stderr);
		  exit (E_FAILURE);
		}
	      next->next->next = NULL;

	      if (pwd->pw_uid > next->pwd->pw_uid)
		next->next->pwd = pwd;
	      else
		{
		  next->next->pwd = next->pwd;
		  next->pwd = pwd;
		}
	    }
	  else
	    {
	      struct passwd_list *tmp;
	      tmp = malloc (sizeof (struct passwd_list));

	      if (tmp == NULL)
		{
		  fputs ("running out of memory!\n", stderr);
		  exit (E_FAILURE);
		}
	      tmp->next = next->next;
	      next->next = tmp;
	      tmp->pwd = next->pwd;
	      next->pwd = pwd;
	    }
	}
    }

  const char *file_tmp = "/passwd.tmpXXXXXX";
  char *passwd_tmp = alloca (strlen (files_etc_dir) + strlen (file_tmp) + 1);
  char *passwd_orig = alloca (strlen (files_etc_dir) + 8);
  char *passwd_old = alloca (strlen (files_etc_dir) + 12);
  struct stat passwd_stat;
  FILE *oldgf, *newgf;
  int newgf_fd;
  char *cp;


  cp = stpcpy (passwd_tmp, files_etc_dir);
  strcpy (cp, file_tmp);
  cp = stpcpy (passwd_orig, files_etc_dir);
  strcpy (cp, "/passwd");
  cp = stpcpy (passwd_old, passwd_orig);
  strcpy (cp, ".old");

  if ((oldgf = fopen (passwd_orig, "r")) == NULL)
    {
      fprintf (stderr, _("Can't open `%s': %m\n"), passwd_orig);
      retval = -1;
      goto error_passwd;
    }
  if (fstat (fileno (oldgf), &passwd_stat) < 0)
    {
      fprintf (stderr, _("Can't stat `%s': %m\n"), passwd_orig);
      fclose (oldgf);
      retval = -1;
      goto error_passwd;
    }

#ifdef WITH_SELINUX
  security_context_t prev_context;
  if (set_default_context (passwd_orig, &prev_context) < 0)
    {
      fclose (oldgf);
      retval = -1;
      goto error_passwd;
    }
#endif
  /* Open a temp passwd file */
  newgf_fd = mkstemp (passwd_tmp);
#ifdef WITH_SELINUX
  if (restore_default_context (prev_context) < 0)
    {
      if (newgf_fd >= 0)
	close (newgf_fd);
      fclose (oldgf);
      retval = -1;
      goto error_passwd;
    }
#endif
  if (newgf_fd == -1)
    {
      fprintf (stderr, _("Can't create `%s': %m\n"),
	       passwd_orig);
      fclose (oldgf);
      retval = -1;
      goto error_passwd;
    }
  if (fchmod (newgf_fd, passwd_stat.st_mode) < 0)
    {
      fprintf (stderr,
	       _("Cannot change permissions for `%s': %s\n"),
	       passwd_tmp, strerror (errno));
      fclose (oldgf);
      close (newgf_fd);
      unlink (passwd_tmp);
      retval = -1;
      goto error_passwd;
    }
  if (fchown (newgf_fd, passwd_stat.st_uid, passwd_stat.st_gid) < 0)
    {
      fprintf (stderr,
	       _("Cannot change owner/group for `%s': %s\n"),
	       passwd_tmp, strerror (errno));
      fclose (oldgf);
      close (newgf_fd);
      unlink (passwd_tmp);
      retval = -1;
      goto error_passwd;
    }
  if (copy_xattr (passwd_orig, passwd_tmp) != 0)
    {
      fclose (oldgf);
      close (newgf_fd);
      unlink (passwd_tmp);
      retval = -1;
      goto error_passwd;
    }

  newgf = fdopen (newgf_fd, "w+");
  if (newgf == NULL)
    {
      fprintf (stderr, _("Can't open `%s': %m\n"), passwd_tmp);
      fclose (oldgf);
      close (newgf_fd);
      unlink (passwd_tmp);
      retval = -1;
      goto error_passwd;
    }

  while (ptr != NULL)
    {
      /* write the passwd entry to tmp file */
      if (putpwent (ptr->pwd, newgf) < 0)
	goto write_error_passwd;
      ptr = ptr->next;
    }

  /* Check if we have entries starting with +/- and copy
     the rest of the passwd file without sorting it. */
  if (pwd != NULL)
    {
      /* write the passwd entry to tmp file */
      if (putpwent (pwd, newgf) < 0)
	goto write_error_passwd;
      while ((pwd = files_getpwent ()))
      /* write the passwd entry to tmp file */
      if (putpwent (pwd, newgf) < 0)
	{
	write_error_passwd:
	  fprintf (stderr,
		   _("Error while writing `%s': %m\n"),
                   passwd_tmp);
	  fclose (oldgf);
	  fclose (newgf);
	  retval = -1;
	  goto error_passwd;
	}
    }

  if (fclose (oldgf) != 0)
    {
      fprintf (stderr,
	       _("Error while closing `%s': %m\n"), passwd_orig);
      fclose (newgf);
      retval = -1;
      goto error_passwd;
    }
  if (fclose (newgf) != 0)
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
  rename (passwd_tmp, passwd_orig);
 error_passwd:
  unlink (passwd_tmp);

  return retval;
}

int
main (int argc, char *argv[])
{
  const char *program = "pwck";
  int quiet = 0;
  int sort = 0;

#ifdef ENABLE_NLS
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] = {
	{"path",     required_argument, NULL, 'P'},
        {"quiet",    no_argument,       NULL, 'q' },
        {"readonly", no_argument,       NULL, 'r' },
        {"read-only", no_argument,       NULL, 'r' },
	{"sort",     no_argument,       NULL, 's' },
        {"version",  no_argument,       NULL, 'v' },
        {"usage",    no_argument,       NULL, 'u' },
        {"help",     no_argument,       NULL, '\255' },
        {NULL,       0,                 NULL, '\0'}
      };

      c = getopt_long (argc, argv, "P:qrsvu",
                       long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
	{
	case 'P':
	  files_etc_dir = strdup (optarg);
	  break;
	case 'q':
	  quiet = 1;
	  break;
	case 'r':
	  readonly = 1;
	  break;
	case 's':
	  sort = 1;
	  break;
	case '\255':
          print_help (program);
          return 0;
        case 'v':
          print_version (program, "2005");
          return 0;
        case 'u':
          print_usage (stdout, program);
	  return 0;
	default:
	  print_error (program);
	  return E_USAGE;
	}
    }

  argc -= optind;
  argv += optind;

  if (argc > 0)
    {
      fprintf (stderr, _("%s: Too many arguments.\n"), program);
      print_error (program);
      return E_USAGE;
    }
  else if (readonly && sort)
    {
      fprintf (stderr, _("%s: -s and -r are incompatibile.\n"),
	       program);
      return E_USAGE;
    }

  if (lock_database () != 0)
    {
      fprintf (stderr,
	       _("Cannot lock password file: already locked.\n"));
      return E_PWDBUSY;
    }

  if (sort)
    return sort_passwd_file ();
  else
    {
      int rp, rs;

      rp = loop_over_passwd_file (quiet);
      rs = loop_over_shadow_file (quiet);

      if (rs == 0 || rs == E_NO_FILE)
	return rp;

      if (rp == 0 || rp == E_NO_FILE)
	return rs;

      if (rp > rs)
	return rp;
      else
	return rs;
    }
}
