#
# Copyright (c) 2004-2005 Thorsten Kukuk, Germany
#
# Author: Thorsten Kukuk <kukuk@thkukuk.de>
#
AUTOMAKE_OPTIONS = 1.8 gnits
MAINT_CHARSET = latin1

plugindir = $(libdir)/pwdutils
localedir = $(datadir)/locale

AM_CFLAGS = @EXTRA_CFLAGS@

plugin_LTLIBRARIES = liblog_syslog.la

if build_LAUS_PLUGIN
plugin_LTLIBRARIES += liblog_laus.la
endif

if build_AUDIT_PLUGIN
plugin_LTLIBRARIES += liblog_audit.la
endif

liblog_laus_la_SOURCES=liblog_laus.c
liblog_laus_la_LIBADD = @LAUS_LIBS@

liblog_audit_la_SOURCES=liblog_audit.c
liblog_audit_la_LIBADD = @AUDIT_LIBS@

INCLUDES = -I$(top_srcdir)/lib -DLOCALEDIR=\"$(localedir)\" -DPLUGINDIR=\"$(plugindir)\"

CLEANFILES = *~

EXTRA_DIST = liblog_audit.map liblog_laus.map liblog_syslog.map

liblog_audit_la_LDFLAGS = -version-info 1:0:0 -Wl,--version-script=$(srcdir)/liblog_audit.map
liblog_laus_la_LDFLAGS = -version-info 1:0:0 -Wl,--version-script=$(srcdir)/liblog_laus.map
liblog_syslog_la_LDFLAGS = -version-info 1:0:0 -Wl,--version-script=$(srcdir)/liblog_syslog.map
