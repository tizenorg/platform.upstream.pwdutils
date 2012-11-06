/* Copyright (C) 2003 Thorsten Kukuk
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
#include "config.h"
#endif

#include <signal.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include "public.h"

void
init_environment (void)
{
  struct rlimit rlim;

  /* Don't create a core file.  */
  rlim.rlim_cur = rlim.rlim_max = 0;
  setrlimit (RLIMIT_CORE, &rlim);

  /* Set all limits to unlimited to avoid to run in any
     problems later.  */
  rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
  setrlimit (RLIMIT_AS, &rlim);
  setrlimit (RLIMIT_CPU, &rlim);
  setrlimit (RLIMIT_DATA, &rlim);
  setrlimit (RLIMIT_FSIZE, &rlim);
  setrlimit (RLIMIT_NOFILE, &rlim);
  setrlimit (RLIMIT_RSS, &rlim);
  setrlimit (RLIMIT_STACK, &rlim);

  /* Ignore all signals which can make trouble later.  */
  signal (SIGALRM, SIG_IGN);
  signal (SIGXFSZ, SIG_IGN);
  signal (SIGHUP, SIG_IGN);
  signal (SIGINT, SIG_IGN);
  signal (SIGPIPE, SIG_IGN);
  signal (SIGQUIT, SIG_IGN);
  signal (SIGTERM, SIG_IGN);
  signal (SIGTSTP, SIG_IGN);
  signal (SIGTTOU, SIG_IGN);

  umask (077);
}

