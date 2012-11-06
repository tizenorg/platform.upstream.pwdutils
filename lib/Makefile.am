#
# Copyright (c) 2003-2005 Thorsten Kukuk, Germany
#
# Author: Thorsten Kukuk <kukuk@thkukuk.de>
#
AUTOMAKE_OPTIONS = 1.8 gnits
MAINT_CHARSET = latin1

noinst_LIBRARIES = libpwdutils.a

AM_CFLAGS = -fPIC @EXTRA_CFLAGS@

noinst_HEADERS = error_codes.h libldap.h logindefs.h nispasswd.h nsw.h \
		public.h read-files.h yppasswd.h group.h use_slp.h \
		dbg_log.h yesno.h parse_crypt_arg.h utf8conv.h logging.h \
		msg_table.h i18n.h

libpwdutils_a_SOURCES = authentication.c get_value.c libldap.c logindefs.c \
			nsw.c passwd_nisplus.c read-files.c user.c \
			yppasswd_xdr.c group.c read-files-group.c \
			call_script.c copy_dir_rec.c remove_dir_rec.c \
			is_logged_in.c lock_database.c copy_xattr.c \
			selinux_utils.c init_environment.c print_error.c \
			print_version.c date2str.c str2date.c check_name.c \
			chown_dir_rec.c check_home.c use_slp.c dbg_log.c \
			parse_pwent.c yesno.c parse_grent.c strtoid.c \
			parse_crypt_arg.c utf8conv.c get_ldap_password.c \
			get_caller_dn.c logging.c remove_gr_mem.c

localedir = $(datadir)/locale
plugindir = $(libdir)/pwdutils
INCLUDES = -DLOCALEDIR=\"$(localedir)\" -DPLUGINDIR=\"$(plugindir)\"

CLEANFILES = *~
