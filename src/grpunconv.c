/* Copyright (C) 2004, 2005 Thorsten Kukuk
   Author: Thorsten Kukuk <kukuk@suse.de>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pwd.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>
#ifdef HAVE_LIBNSCD_H
#include <libnscd.h>
#endif

#include "i18n.h"
#include "group.h"
#include "public.h"
#include "logindefs.h"
#include "read-files.h"
#include "error_codes.h"


struct sgrp {
  char *sg_namp;
  char *sg_pwdp;
};

static void
print_usage (FILE *stream, const char *program)
{
  fprintf (stream, _("Usage: %s\n"), program);
}

static void
print_help (const char *program)
{
  print_usage (stdout, program);
  fprintf (stdout, _("%s - convert from shadow groups\n\n"),
	   program);

  fputs (_("  -P path        Search group and gshadow file in \"path\"\n"),
         stdout);
  fputs (_("      --help     Give this help list\n"), stdout);
  fputs (_("  -u, --usage    Give a short usage message\n"), stdout);
  fputs (_("  -v, --version  Print program version\n"), stdout);
}

static FILE *sg_stream;

static int
setsgent (void)
{
  char *filename = alloca (strlen (files_etc_dir) + 10);
  strcpy (filename, files_etc_dir);
  strcat (filename, "/gshadow");

  sg_stream = fopen (filename, "r");

  if (sg_stream == NULL)
    return -1;

  return 0;
}

static struct sgrp *
getsgent (void)
{
  static struct sgrp sg;
  static char *buf = NULL;
  static size_t buflen = 0;

  while (!feof (sg_stream))
    {
      char *tmp, *cp;
#if defined(HAVE_GETLINE)
      ssize_t n = getline (&buf, &buflen, sg_stream);
#elif defined (HAVE_GETDELIM)
      ssize_t n = getdelim (&buf, &buflen, '\n', sg_stream);
#else
      ssize_t n;

      if (buf == NULL)
        {
          buflen = 8096;
          buf = malloc (buflen);
        }
      buf[0] = '\0';
      fgets (buf, buflen - 1, sg_stream);
      if (buf != NULL)
        n = strlen (buf);
      else
        n = 0;
#endif /* HAVE_GETLINE / HAVE_GETDELIM */

      cp = buf;

      if (n < 1)
        break;

      tmp = strchr (cp, ':');
      if (tmp)
        *tmp++ = '\0';
      else
	continue;

      sg.sg_namp = cp;
      sg.sg_pwdp = tmp;

      tmp = strchr (tmp, ':');
      if (tmp)
        *tmp = '\0';

      return &sg;
    }
  return NULL;
}

int
main (int argc, char *argv[])
{
  struct sgrp *sg;
  char *program;
  char *cp;
  char *tmpgroup = NULL;
  char *gshadow_path;

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
	{"path",    required_argument, NULL, 'P'},
        {"version", no_argument, NULL, 'v' },
        {"usage",   no_argument, NULL, 'u' },
        {"help",    no_argument, NULL, '\255' },
        {NULL,      0,           NULL, '\0'}
      };

      c = getopt_long (argc, argv, "vuP:",
                       long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
	{
        case 'P':
          files_etc_dir = strdup (optarg);
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
  else
    {
      /* Check, if /etc/gshadow file exist. If not, exit.  */
      char *path;
      struct stat st;

      if (asprintf (&gshadow_path, "%s/gshadow", files_etc_dir) < 0)
        {
          fputs ("running out of memory!\n", stderr);
          return E_FAILURE;
        }

      if (lstat (gshadow_path, &st) < 0)
	{
	  /* ENOENT means, the file does not exist and we have
	     to create it. Else report an error and abort.  */
	  if (errno == ENOENT)
	    {
	      fprintf (stderr, _("%s: No gshadow file found.\n"),
		       program);
	      return E_FAILURE;
	    }
	  else
	    {
	      fprintf (stderr, _("Can't stat `%s': %m\n"), gshadow_path);
	      return E_FAILURE;
	    }
	}

      /* Now create a copy of the original group file.  */
      if (asprintf (&path, "%s/group", files_etc_dir) < 0)
	{
	  fputs ("running out of memory!\n", stderr);
	  return E_FAILURE;
	}
      if (asprintf (&tmpgroup, "%s/group.grpunconv", files_etc_dir) < 0)
	{
	  fputs ("running out of memory!\n", stderr);
	  return E_FAILURE;
	}
      if (link (path, tmpgroup) < 0)
	{
	  fprintf (stderr, _("Cannot create backup file `%s': %m\n"),
		   tmpgroup);
	  return E_FAILURE;
	}
      free (path);
    }


  /* Step through /etc/gshadow and move the password into the group
     file.  */
  setsgent ();
  while ((sg = getsgent ()) != NULL)
    {
      group_t *gr_data = find_group_data (sg->sg_namp, 0, NULL);
      /* Only change password in group file, if we have a
	 corresponding group entry and this is 'x'.  */
      if (gr_data != NULL && gr_data->service != S_NONE &&
	  strcmp (gr_data->gr.gr_passwd, "x") == 0)
	{
	  gr_data->newpassword = strdup (sg->sg_pwdp);
	  if (write_group_data (gr_data, 0) != 0)
	    {
	      fprintf (stderr,
		       _("Error while moving password for `%s'.\n"),
		       gr_data->gr.gr_name);
	      free (gr_data);
	      return E_FAILURE;
	    }
	}
      free_group_t (gr_data);
    }
  fclose (sg_stream);
#ifdef HAVE_NSCD_FLUSH_CACHE
  nscd_flush_cache ("group");
#endif

  /* Rename original gshadow file to gshadow.old.  */
  {
    char *oldgshadow;
    if (asprintf (&oldgshadow, "%s/gshadow.old", files_etc_dir) < 0)
      {
	fputs ("running out of memory!\n", stderr);
	return E_FAILURE;
      }
    unlink (oldgshadow);
    rename (gshadow_path, oldgshadow);
    free (oldgshadow);
    free (gshadow_path);
  }

  /* Rename our own copy to group.old. As result, /etc/group.old
     will have the contents of /etc/group when starting this program.  */
  if (tmpgroup)
    {
      char *oldgroup;

      if (asprintf (&oldgroup, "%s/group.old", files_etc_dir) < 0)
	{
	  fputs ("running out of memory!\n", stderr);
	  return E_FAILURE;
	}
      unlink (oldgroup);
      rename (tmpgroup, oldgroup);
      free (oldgroup);
      free (tmpgroup);
    }

  return E_SUCCESS;
}
