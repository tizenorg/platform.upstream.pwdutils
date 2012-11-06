/* Copyright (C) 2004 Thorsten Kukuk
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

#ifndef __PARSE_CRYPT_ARG_H__
#define __PARSE_CRYPT_ARG_H__

enum crypt_t {DES, MD5, BLOWFISH};
typedef enum crypt_t crypt_t;

extern crypt_t parse_crypt_arg (const char *arg);

extern char *make_crypt_salt (const char *crypt_prefix, int crypt_rounds);

#endif

