/* Copyright (C) 2003, 2004, 2005 Thorsten Kukuk
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
#include <paths.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include "i18n.h"
#include "public.h"
#include "error_codes.h"

#ifndef _PATH_PASSWD
#define _PATH_PASSWD "/etc/passwd"
#endif

#ifndef _PATH_GROUP
#define _PATH_GROUP "/etc/group"
#endif

#ifndef _PATH_SHADOW
#define _PATH_SHADOW "/etc/shadow"
#endif

#ifndef _PATH_GSHADOW
#define _PATH_GSHADOW "/etc/gshadow"
#endif

static void
print_usage (FILE *stream, const char *program)
{
  fprintf (stream, _("Usage: %s [-g|-p|-s]\n"),
           program);
}

static void
print_help (const char *program)
{
  print_usage (stdout, program);
  fprintf (stdout, _("%s - edit the password, group or shadow file\n\n"),
	   program);

  fputs (_("  -g, --group    Edit the /etc/group file\n"), stdout);
  fputs (_("  -p, --passwd   Edit the /etc/passwd file\n"), stdout);
  fputs (_("  -s, --shadow   Edit the /etc/shadow file\n"), stdout);
  fputs (_("      --help     Give this help list\n"), stdout);
  fputs (_("  -u, --usage    Give a short usage message\n"), stdout);
  fputs (_("  -v, --version  Print program version\n"), stdout);
}

static int
call_editor (const char *file)
{
  char *editor;
  pid_t pid;

  if ((editor = getenv("EDITOR")) == NULL)
    editor = strdup(_PATH_VI);

  pid = fork();
  if (pid < 0) /* Error */
    {
      fprintf (stderr, _("Cannot fork: %s\n"), strerror (errno));
      return E_FAILURE;
    }
  else if (pid == 0) /* Child */
    {
      char *argp[] = {"sh", "-c", NULL, NULL};
      char *buffer;
      int i;

      for (i = 3; i < getdtablesize (); i++)
	close (i);

      /* Reset all signals which parent ignores.  */
      signal (SIGALRM, SIG_DFL);
      signal (SIGXFSZ, SIG_DFL);
      signal (SIGHUP, SIG_DFL);
      signal (SIGINT, SIG_DFL);
      signal (SIGPIPE, SIG_DFL);
      signal (SIGQUIT, SIG_DFL);
      signal (SIGTERM, SIG_DFL);
      signal (SIGTSTP, SIG_DFL);
      signal (SIGTTOU, SIG_DFL);

      if (asprintf (&buffer, "%s %s", editor, file) < 0)
	{
	  fputs ("running out of memory!\n", stderr);
	  return E_FAILURE;
        }
      argp[2] = buffer;

      execv (_PATH_BSHELL, argp);
      _exit (127);
    }
  else /* Parent */
    {
      int status;

      while ((pid = waitpid (pid, &status, WUNTRACED)) > 0)
	{
	  /* the editor suspended, so suspend us as well */
	  if (WIFSTOPPED (status))
	    {
	      kill (getpid (), SIGSTOP);
	      kill (pid, SIGCONT);
	    }
	  else
	    break;
        }

      if (pid == -1 || !WIFEXITED (status) || WEXITSTATUS (status))
	return E_FAILURE;
    }

  return 0;
}

static int
edit (const char *file, const char *program, int shadow)
{
  struct stat before, after, orig;
  int new_fd, old_fd;
  char *tmpname;
  int retval = 0;
#ifdef WITH_SELINUX
  security_context_t prev_context;
#endif

  if (asprintf (&tmpname, "%s.%sXXXXXX", file, program) < 0)
    {
      fputs ("running out of memory!\n", stderr);
      return E_FAILURE;
    }

  if (lock_database () != 0)
    {
      fprintf (stderr, _("Cannot lock `%s': already locked.\n"), file);
      return E_PWDBUSY;
    }

#ifdef WITH_SELINUX
  if (set_default_context (file, &prev_context) < 0)
    {
      ulckpwdf ();
      free (tmpname);
      return E_FAILURE;
    }
#endif
  new_fd = mkstemp (tmpname);
#ifdef WITH_SELINUX
  if (restore_default_context (prev_context) < 0)
    {
      if (new_fd >= 0)
	close (new_fd);
      ulckpwdf ();
      free (tmpname);
      return E_FAILURE;
    }
#endif
  if (new_fd == -1)
    {
      fprintf (stderr, _("Can't create `%s': %m\n"), tmpname);
      ulckpwdf ();
      free (tmpname);
      return E_FAILURE;
    }
  /* for the case somebody uses really an old glibc with
     insecure mkstemp.  */
  fchmod (new_fd, S_IRUSR|S_IWUSR);

  old_fd = open (file, O_RDONLY);
  if (old_fd == -1)
    {
      /* if the file does not exist, it could be that the
	 user will create them.  */
      if (errno != ENOENT)
	{
	  fprintf (stderr, "%s: %s\n", file, strerror (errno));
	  close (new_fd);
	  unlink (tmpname);
	  ulckpwdf ();
	  free (tmpname);
	  return E_FAILURE;
	}
      /* Set orig struct for chmod/chown to usefull values for
	 new files.  */
      orig.st_uid = 0;
      orig.st_gid = 0;
      if (shadow)
	orig.st_mode = S_IRUSR|S_IWUSR;
      else
	orig.st_mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
    }
  else
    {
      char buffer[4096];
      int cnt;

      while ((cnt = read (old_fd, buffer, sizeof (buffer))) > 0)
	{
	  if (write (new_fd, buffer, cnt) != cnt)
	    {
	      fprintf (stderr, _("Cannot copy `%s': %s\n"),
		       file, strerror (errno));
	      cnt = -1;
	      break;
	    }
	}
      if (cnt < 0) /* Remove file if copy failed. */
	{
	  fprintf (stderr, _("Cannot copy `%s': %s\n"),
		   file, strerror (errno));
	  close (old_fd);
	  close (new_fd);
	  unlink (tmpname);
	  ulckpwdf ();
	  free (tmpname);
	  return E_FAILURE;
	}
      if (fstat (old_fd, &orig))
	{
	  fprintf (stderr, _("Can't stat `%s': %m\n"), file);
	  return E_FAILURE;
	}
      close (old_fd);
    }
  close (new_fd);

  if (stat (tmpname, &before))
    {
      fprintf (stderr, _("Can't stat `%s': %m\n"), tmpname);
      return E_FAILURE;
    }

  if (call_editor (tmpname) != 0)
    {
      unlink (tmpname);
      free (tmpname);
      ulckpwdf ();
      return E_FAILURE;
    }

  if (stat (tmpname, &after))
    {
      fprintf (stderr, _("Can't stat `%s': %m\n"), tmpname);
      return E_FAILURE;
    }

  if (before.st_mtime == after.st_mtime &&
      before.st_size == after.st_size)
    fprintf (stderr, _("%s: no changes made\n"), program);
  else
    {
      char *old;

      /* Set modes of temporary file to the from the original one.  */
      if (chmod (tmpname, orig.st_mode) < 0)
	{
	  fprintf (stderr,
		   _("Cannot change permissions for `%s': %s\n"),
		   tmpname, strerror (errno));
	  unlink (tmpname);
	  return E_FAILURE;
	}
      if (chown (tmpname, orig.st_uid, orig.st_gid) < 0)
	{
	  fprintf (stderr,
		   _("Cannot change owner/group for `%s': %s\n"),
		   tmpname, strerror (errno));
	  unlink (tmpname);
	  return E_FAILURE;
	}

      if (copy_xattr (file, tmpname) != 0)
	{
	  unlink (tmpname);
	  retval = E_FAILURE;
	}
      else if (asprintf (&old, "%s.old", file) < 0)
	{
	  fputs ("running out of memory!\n", stderr);
	  unlink (tmpname);
	  retval = E_FAILURE;
	}
      else
	{
	  /* Replace original file with edited one.  */
	  unlink (old);
	  if (link (file, old) < 0)
	    fprintf (stderr,
		     _("Warning: cannot create backup file: %m\n"));
	  rename (tmpname, file);
	}
    }

  ulckpwdf ();
  free (tmpname);
  return retval;
}

int
main (int argc, char *argv[])
{
  char *program;
  int vipw;
  int shadow = 0;
  char *cp;

#ifdef ENABLE_NLS
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  /* Before going any further, raise the ulimit and ignore
     signals.  */
  init_environment ();

  /* determine name of binary, which specifies edit mode.  */
  program = ((cp = strrchr (*argv, '/')) ? cp + 1 : *argv);
  if (strcmp (program, "vigr") == 0)
    vipw = 0; /* Edit group file.  */
  else
    {
      /* Edit passwd or shadow file. */
      program = "vipw";
      vipw = 1;
    }

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] = {
        {"group",   no_argument, NULL, 'g' },
        {"passwd",  no_argument, NULL, 'p' },
        {"shadow",  no_argument, NULL, 's' },
        {"version", no_argument, NULL, 'v' },
        {"usage",   no_argument, NULL, 'u' },
        {"help",    no_argument, NULL, '\255' },
        {NULL,      0,           NULL, '\0'}
      };

      c = getopt_long (argc, argv, "gpsVvu",
                       long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
	{
	case 'g':
	  vipw = 0;
	  break;
	case 'p':
	  vipw = 1;
	  break;
	case 's':
	  /* Yes, vigr -s will edit gshadow, not shadow!
	     Undocumented feature to be compatible with other
	     implementations. */
	  shadow = 1;
	  break;
	case '\255':
          print_help (program);
          return 0;
	case 'V': /* RH compatibility.  */
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

  if (vipw)
    {
      if (shadow)
	return edit (_PATH_SHADOW, program, shadow);
      else
	return edit (_PATH_PASSWD, program, shadow);
    }
  else
    {
      if (shadow)
	return edit (_PATH_GSHADOW, program, shadow);
      else
	return edit (_PATH_GROUP, program, shadow);
    }

  /* never reached!  */
  return E_FAILURE;
}
