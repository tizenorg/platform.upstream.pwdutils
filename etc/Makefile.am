#
# Copyright (c) 2003-2005 Thorsten Kukuk, Germany
#
# Author: Thorsten Kukuk <kukuk@thkukuk.de>
#
AUTOMAKE_OPTIONS = 1.8 gnits
MAINT_CHARSET = latin1
#
CLEANFILES = *~ */*~
#
EXTRA_DIST = ${SCRIPTS} ${DATA} ${MANS}

initddir = ${sysconfdir}/init.d
pamddir = ${sysconfdir}/pam.d
defaultdir = ${sysconfdir}/default
pwdutilsdir = ${sysconfdir}/pwdutils

initd_SCRIPTS = init.d/rpasswdd

sysconf_DATA = login.defs rpasswd.conf

default_DATA = default/useradd default/passwd

pwdutils_DATA = pwdutils/logging

pamd_DATA = pam.d/chage pam.d/chfn pam.d/chsh pam.d/passwd \
		pam.d/rpasswd pam.d/useradd pam.d/shadow

man_MANS = login.defs.5

sbin_SCRIPTS = useradd.local userdel-pre.local userdel-post.local \
		groupadd.local

