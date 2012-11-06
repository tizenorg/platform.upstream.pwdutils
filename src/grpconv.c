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


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include "i18n.h"
#include "public.h"
#include "error_codes.h"

static void
print_usage (FILE *stream, const char *program)
{
  fprintf (stream, _("Usage: %s\n"), program);
}

static void
print_help (const char *program)
{
  print_usage (stdout, program);
  fprintf (stdout, _("%s - convert to shadow group\n\n"),
	   program);

  fputs (_("      --help     Give this help list\n"), stdout);
  fputs (_("  -u, --usage    Give a short usage message\n"), stdout);
  fputs (_("  -v, --version  Print program version\n"), stdout);
}

int
main (int argc, char *argv[])
{
  char *program;
  char *cp;

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
        {"version", no_argument, NULL, 'v' },
        {"usage",   no_argument, NULL, 'u' },
        {"help",    no_argument, NULL, '\255' },
        {NULL,      0,           NULL, '\0'}
      };

      c = getopt_long (argc, argv, "vu",
                       long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
	{
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

  fprintf (stderr, _("%s: /etc/gshadow is not supported by this system.\n"),
	   program);

  return E_FAILURE;
}
