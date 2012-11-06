/* Copyright (C) 2004, 2005, 2006 Thorsten Kukuk
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
#if defined(HAVE_XCRYPT_H)
#include <xcrypt.h>
#elif defined(HAVE_CRYPT_H)
#include <crypt.h>
#endif

#include "i18n.h"
#include "public.h"
#include "logindefs.h"
#include "error_codes.h"
#include "utf8conv.h"

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

static void
print_usage (FILE *stream, const char *program)
{
  fprintf (stream, _("Usage: %s [-l|-c command] [group]\n"),
	   program);
}

static void
print_help (const char *program)
{
  print_usage (stdout, program);
  fprintf (stdout, _("%s - change the effective group id\n\n"),
	   program);

  fputs (_("  -l, --login    reinitialize environment as if logged in\n"),
	 stdout);
  fputs (_("  -c  command    Execute `command' with new group\n"), stdout);
  fputs (_("      --help     Give this help list\n"), stdout);
  fputs (_("  -u, --usage    Give a short usage message\n"), stdout);
  fputs (_("  -v, --version  Print program version\n"), stdout);
}

int
main (int argc, char *argv[])
{
  struct passwd *pw;
  char *program;
  char *cp, *shell;
  char *c_flag = NULL;
  int l_flag = 0;
  int ngroups_max = MIN (sysconf (_SC_NGROUPS_MAX), INT_MAX);

#ifdef ENABLE_NLS
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  /* determine name of binary, which specifies edit mode.  */
  program = ((cp = strrchr (*argv, '/')) ? cp + 1 : *argv);

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] = {
        {"login",   no_argument, NULL, 'l' },
	{"command", required_argument, NULL, 'c'},
        {"version", no_argument, NULL, 'v' },
        {"usage",   no_argument, NULL, 'u' },
        {"help",    no_argument, NULL, '\255' },
        {NULL,      0,           NULL, '\0'}
      };

      c = getopt_long (argc, argv, "lvuc:",
                       long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
	{
	case '-':
	case 'l':
	  l_flag = 1;
	  break;
	case 'c':
	  c_flag = optarg;
	  break;
	case '\255':
	  print_help (program);
	  return 0;
        case 'v':
          print_version (program, "2006");
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

  /* Special hack for compatibility with "newgrp - group" and
     "sg group command".  */
  if (argc == 2)
    {
      /* User called "newgrp - group" instead of "newgrp -l group".  */
      if (argv[0][0] == '-' && argv[0][1] == '\0')
	{
	  l_flag = 1;
	  argc--;
	  argv++;
	}
      /* User called "sg group command" instead of "sg group -c command". */
      else if (strcmp (program, "sg") == 0)
	{
	  c_flag = argv[1];
	  argc--;
	}
    }

  if (argc > 1)
    {
      fprintf (stderr, _("%s: Too many arguments.\n"), program);
      print_error (program);
      return E_USAGE;
    }
  else if (c_flag && l_flag)
    {
      fprintf (stderr, _("%s: -l and -c are exclusive\n"), program);
      print_error (program);
      return E_USAGE;
    }
  else if (c_flag && argc != 1)
    {
      fprintf (stderr, _("%s: -c requires a group argument\n"), program);
      print_error (program);
      return E_USAGE;
    }

  if ((pw = getpwuid (getuid())) == NULL)
    {
      fprintf (stderr, _("%s: Unknown user.\n"), program);
      exit (E_FAILURE);
    }

  shell = (pw->pw_shell[0] ? pw->pw_shell : _PATH_BSHELL);

  if (argc == 1) /* Change primary group to new one.  */
    {
      struct group *grp;
      gid_t gid;
      gid_t egid;
      int is_member = 0;
      int ngroups, ngroups_allocated, i;
      gid_t *grouplist;
      char *utf8_arg = locale_to_utf8 (argv[0]);

      /* Try it as a group name, then a group id. */
      if ((grp = getgrnam (utf8_arg)) == NULL &&
	  (strtoid (utf8_arg, &gid) == -1 ||
	   (grp = getgrgid (gid)) == NULL))
	{
	  fprintf (stderr, _("%s: bad group `%s'.\n"), program, argv[0]);
	  return E_USAGE;
	}

      if (getuid () != 0) /* root is allowed to do everything.  */
	{
	  if (grp->gr_gid == pw->pw_gid) /* primary group.  */
	    is_member = 1;
	  else
            {
              /* check with getgroup() if were member already */
              gid_t *groupIDs;
              int count;

              if ((count = getgroups(0,0)) == -1)
                count = ngroups_max;
              if ((groupIDs = (gid_t*) malloc(count * sizeof(gid_t))) == NULL)
                {
                  fputs ("running out of memory!\n", stderr);
                  return E_FAILURE;
                }
              if ((count = getgroups(count, groupIDs)) < 0)
                {
                  fprintf (stderr, _("%s: calling getgroups failed: %s\n"),
                        program, strerror (errno));
                        return E_FAILURE;
                }
              for (i = 0; i < count; i++ )
                {   
                  if (grp->gr_gid == groupIDs[i])
                    {
                      is_member = 1;
                      break;
                    }
                }
              free(groupIDs);
            }

          /* check in databases if not already found */
          if (!is_member) 
            { 
	      struct group *g;
	      char **gp;
	      gid_t search_gid;

	      /* grp will be no longer valid after setgrent() call.  */
	      search_gid = grp->gr_gid;
	      grp = NULL;

	      /* Normally it is enough to check only, if the user is in
		 grp->gr_mem. But some people split the groups into multiple
		 one with the same group ID, but different members. So we have
		 to step through all group entries and search for the correct
		 one.  */
	      setgrent ();
	      while (!is_member && (g = getgrent ()) != NULL)
		{
		  if (g->gr_gid != search_gid)
		    continue;

		  for (gp = g->gr_mem; *gp != NULL; gp++)
		    {
		      if (strcmp (pw->pw_name, *gp) == 0)
			{
			  grp = g; /* let point grp to the new group entry. */
			  is_member = 1;
			  break;
			}
		    }
		}
	      /* endgrent (); */ /* Don't invalidate grp pointer.  */
	      if (grp == NULL)
		{ /* restore grp pointer, user is no member. */
		  if ((grp = getgrgid (search_gid)) == NULL)
		    {
		      fprintf (stderr,
			       _("%s: failure to get group entry for %d.\n"),
			       program, search_gid);
		      return E_FAILURE;
		    }
		}
	    }

	  if (!is_member && grp->gr_passwd && grp->gr_passwd[0] != '\0')
	    {
	      if (strcmp (grp->gr_passwd,
			  crypt (getpass(_("Password: ")),
				 grp->gr_passwd)) != 0)
		{
		  fprintf (stderr, _("%s: password incorrect.\n"),
			   program);
		  return E_NOPERM;
		}
	    }
	}

      egid = getegid();

      /* Find out, how many sumplementary groups exists and allocate
	 enough memory for one additional group.  */
      ngroups = getgroups (0, 0);
      if (ngroups == -1)
	ngroups = ngroups_max;
      if ((ngroups+1) <= 0)
	  /* Overflow, don't allocate more. */
	  ngroups_allocated = ngroups;
      else
	ngroups_allocated = ngroups + 1;

      grouplist = malloc (ngroups_allocated * sizeof (gid_t *));
      if (grouplist == NULL)
	{
	  fputs ("running out of memory!\n", stderr);
	  return E_FAILURE;
	}

      if ((ngroups = getgroups (ngroups, grouplist)) < 0)
	{
	  fprintf (stderr, _("%s: calling getgroups failed: %s\n"),
		   program, strerror (errno));
	  return E_FAILURE;
	}

#if 0 /* Use this, if effictive group is normally notin supp. list.  */
      /* If the new group is already part of the supplementary
	 group list, remove it.  */
      int found = 0;
      for (i = 0; i < ngroups; i++)
	{
	  if (found == 1) /* move next gid in previous empty slot.  */
	    grouplist[i - 1] = grouplist[i];
	  else if (grp->gr_gid == grouplist[i])
	    found = 1;
	}
      if (found)
	ngroups--;

      /* Add old effective gid to supp. list if it does not exist.  */
      for (i = 0; i < ngroups; i++)
	if (egid == grouplist[i])
	  break;

      if (i == ngroups)
	grouplist[ngroups++] = egid;

#else
      /* Add new gid to supp. list if it does not exist yet.  */
      for (i = 0; i < ngroups; i++)
	if (grp->gr_gid == grouplist[i])
	  break;

      if (i == ngroups)
	{
	  if (ngroups < ngroups_allocated && ngroups < ngroups_max)
	    grouplist[ngroups++] = grp->gr_gid;
	  else
	    fprintf (stderr, _("%s: too many groups, not added.\n"),
		     program);
	}
#endif

      if (setgroups (ngroups, (grouplist)) < 0)
	{
	  fprintf (stderr, _("%s: calling setgroups failed: %s\n"),
		   program, strerror (errno));
	  return E_FAILURE;
	}

      if (setgid (grp->gr_gid) < 0)
	{
	  fprintf (stderr, _("%s: calling setgid failed: %s\n"),
		   program, strerror (errno));
	  return E_FAILURE;
	}
    }
  else /* Reset groups to default one.  */
    {
      if (initgroups (pw->pw_name, pw->pw_gid) != 0)
	{
	  fprintf (stderr, _("%s: calling initgroups failed: %s\n"),
		   program, strerror (errno));
	  return E_FAILURE;
	}
      if (setgid (pw->pw_gid) != 0)
	{
	  fprintf (stderr, _("%s: calling setgid failed: %s\n"),
		   program, strerror (errno));
	  return E_FAILURE;
	}
    }

  /* Drop root privilegs.  */
  if (setuid (getuid ()) != 0)
    {
      fprintf (stderr, _("%s: calling setuid failed: %s\n"),
	       program, strerror (errno));
      return E_FAILURE;
    }

  if (l_flag)
    {
      /* extern char **environ; */
      char *args[2], **cleanenv, *term;

      if (chdir (pw->pw_dir) != 0)
	{
	  fprintf (stderr, _("Cannot change to directory %s: %s\n"),
		   pw->pw_dir, strerror (errno));
	  if (!getlogindefs_bool ("DEFAULT_HOME", 1))
	    return E_FAILURE;
	  if (chdir ("/") < 0)
	    return E_FAILURE;
	}

      term = getenv("TERM");

      if ((cleanenv = calloc (20, sizeof (char *))) == NULL)
	{
	  fputs ("running out of memory!\n", stderr);
	  return E_FAILURE;
	}
      *cleanenv = NULL;
      environ = cleanenv;
      setenv("USER", pw->pw_name, 1);
      setenv("SHELL", shell, 1);
      setenv("HOME", pw->pw_dir, 1);
      if (term != NULL)
	setenv("TERM", term, 1);

      if (asprintf (&args[0], "-%s", basename (shell)) < 0)
	{
	  fputs ("running out of memory!\n", stderr);
	  return E_FAILURE;
	}
      args[1] = NULL;

      execvp (shell, args);
    }
  else if (c_flag)
    execl ("/bin/sh", "sh", "-c", c_flag, (char *) 0);
  else
    execl (shell, basename (shell), NULL);

  /* execv or execl failed.  */
  fprintf (stderr, _("%s: execl failed: %s\n"),
	   program, strerror (errno));

  /* should never be reached!  */
  return E_FAILURE;
}
