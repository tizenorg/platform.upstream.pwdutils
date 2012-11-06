#
# Copyright (c) 2002-2005, 2009 Thorsten Kukuk, Germany
#
# Author: Thorsten Kukuk <kukuk@thkukuk.de>
#
AUTOMAKE_OPTIONS = 1.7 gnits
MAINT_CHARSET = latin1
#
LN_F = ln -f
RM_F = rm -f

AM_CFLAGS = @EXTRA_CFLAGS@
DEFS = @DEFS@ -DLOCALEDIR=\"$(localedir)\"
LDADD = @LIBINTL@

localedir = $(datadir)/locale
pamdir = $(libdir)/security

INCLUDES = -I$(srcdir) -I$(top_srcdir)/lib -I$(top_srcdir) \
		-DLOCALEDIR=\"$(localedir)\"

CLEANFILES = *~ tst-chage.* tst-passwd.* tst-group.* tst-groupadd.* \
		tst-long-group-entry.* tst-32bit-uid-gid.* tst-userdel.* \
		tst-groupmod.* tst-pwconv.* tst-pwunconv.* tst-pwck.* \
		tst-grpck.* tst-usermod.* tst-gpasswd.* ${EXTRA_PRGRAMS}

bin_PROGRAMS = chage chfn chsh expiry gpasswd newgrp passwd rpasswd

sbin_PROGRAMS = chpasswd groupadd groupdel groupmod grpconv grpunconv \
		pwconv pwunconv rpasswdd useradd userdel usermod vipw \
		pwck grpck

if build_PAM_RPASSWD
pam_LTLIBRARIES = pam_rpasswd.la
endif


TESTS = tst-useradd tst-chage tst-passwd tst-groupadd tst-long-group-entry \
	tst-32bit-uid-gid tst-userdel tst-groupmod tst-pwconv tst-pwunconv \
	tst-pwck tst-grpck tst-usermod tst-gpasswd

EXTRA_DIST = ${MANS} ${TESTS} rpasswd-client.c pam_rpasswd.map pam_rpasswd.8

man_MANS = chfn.1 chsh.1 expiry.1 passwd.1 rpasswd.conf.5 rpasswd.1 sg.1 \
	rpasswdd.8 chage.1 chpasswd.8 useradd.8 userdel.8 usermod.8 pwconv.8 \
	pwunconv.8 gpasswd.1 groupadd.8 groupdel.8 groupmod.8 grpconv.8 \
	grpunconv.8 vigr.8 vipw.8 newgrp.1 grpck.8 pwck.8

if build_PAM_RPASSWD
man_MANS += pam_rpasswd.8
endif

noinst_HEADERS = rpasswd-client.h

pam_rpasswd_la_LDFLAGS = -Wl,--version-script=$(srcdir)/pam_rpasswd.map \
	-Wl,-no-undefined -no-undefined -avoid-version -module -shared \
	-Wl,-soname,pam_rpasswd.so
pam_rpasswd_la_CFLAGS = @EXTRA_CFLAGS@ -fPIC
pam_rpasswd_la_LIBADD = @PAM_LIBS@ @TLS_LIBS@ @SLP_LIBS@

chage_SOURCES = chage.c
chage_CFLAGS = @PIE_CFLAGS@
chage_LDADD = ../lib/libpwdutils.a @PAM_LIBS@ @LDAP_LIBS@ @NSL_LIB@ @SELINUX_LIB@ @ATTR_LIB@ @NSCD_LIB@
chage_LDFLAGS = @PIE_LDFLAGS@

chfn_SOURCES = chfn.c
chfn_CFLAGS = @PIE_CFLAGS@
chfn_LDADD = ../lib/libpwdutils.a @PAM_LIBS@ @LDAP_LIBS@ @NSL_LIB@ @SELINUX_LIB@ @ATTR_LIB@ @NSCD_LIB@ @NSCD_LIB@
chfn_LDFLAGS = @PIE_LDFLAGS@

chsh_SOURCES = chsh.c
chsh_CFLAGS = @PIE_CFLAGS@
chsh_LDADD = ../lib/libpwdutils.a @PAM_LIBS@ @LDAP_LIBS@ @NSL_LIB@ @SELINUX_LIB@ @ATTR_LIB@ @NSCD_LIB@
chsh_LDFLAGS = @PIE_LDFLAGS@

chpasswd_SOURCES = chpasswd.c
chpasswd_LDADD = ../lib/libpwdutils.a @LDAP_LIBS@ @NSL_LIB@ @CRYPT_LIB@ @SELINUX_LIB@ @ATTR_LIB@ @NSCD_LIB@

passwd_SOURCES = passwd.c
passwd_CFLAGS = @PIE_CFLAGS@
passwd_LDADD = ../lib/libpwdutils.a @PAM_LIBS@ @LDAP_LIBS@ @NSL_LIB@ @SELINUX_LIB@ @ATTR_LIB@ @NSCD_LIB@ @BIOAPI_LIB@
passwd_LDFLAGS = @PIE_LDFLAGS@

rpasswd_SOURCES = rpasswd.c
rpasswd_LDADD = ../lib/libpwdutils.a @TLS_LIBS@ @SLP_LIBS@

rpasswdd_SOURCES = rpasswdd.c
rpasswdd_LDADD = ../lib/libpwdutils.a @PAM_LIBS@ @TLS_LIBS@ @SLP_LIBS@
rpasswdd_CFLAGS = @EXTRA_CFLAGS@ @PIE_CFLAGS@
rpasswdd_LDFLAGS = @PIE_LDFLAGS@

expiry_SOURCES = expiry.c
expiry_CFLAGS = @EXTRA_CFLAGS@ @PIE_CFLAGS@ \
		-DPASSWD_PROGRAM=\"$(bindir)/passwd\"
expiry_LDADD = ../lib/libpwdutils.a @DL_LIBS@
expiry_LDFLAGS = @PIE_LDFLAGS@

gpasswd_SOURCES = gpasswd.c
gpasswd_CFLAGS = @PIE_CFLAGS@
gpasswd_LDADD = ../lib/libpwdutils.a @CRYPT_LIB@ @NSL_LIB@ @LDAP_LIBS@ @SELINUX_LIB@ @ATTR_LIB@ @NSCD_LIB@
gpasswd_LDFLAGS = @PIE_LDFLAGS@

groupadd_SOURCES = groupadd.c
groupadd_LDADD = ../lib/libpwdutils.a @PAM_LIBS@ @LDAP_LIBS@ @NSL_LIB@ @SELINUX_LIB@ @ATTR_LIB@ @NSCD_LIB@

groupdel_SOURCES = groupdel.c
groupdel_LDADD = ../lib/libpwdutils.a @PAM_LIBS@ @LDAP_LIBS@ @NSL_LIB@ @SELINUX_LIB@ @ATTR_LIB@ @NSCD_LIB@

groupmod_SOURCES = groupmod.c
groupmod_LDADD = ../lib/libpwdutils.a @PAM_LIBS@ @LDAP_LIBS@ @NSL_LIB@ @SELINUX_LIB@ @ATTR_LIB@ @NSCD_LIB@

grpck_SOURCES = grpck.c
grpck_LDADD = ../lib/libpwdutils.a @SELINUX_LIB@ @ATTR_LIB@

grpconv_SOURCES = grpconv.c
grpconv_LDADD = ../lib/libpwdutils.a

grpunconv_SOURCES = grpunconv.c
grpunconv_LDADD = ../lib/libpwdutils.a @LDAP_LIBS@ @NSL_LIB@ @SELINUX_LIB@ @ATTR_LIB@ @NSCD_LIB@

pwck_SOURCES = pwck.c
pwck_LDADD = ../lib/libpwdutils.a @SELINUX_LIB@ @ATTR_LIB@

pwconv_SOURCES = pwconv.c
pwconv_LDADD = ../lib/libpwdutils.a @LDAP_LIBS@ @NSL_LIB@ @SELINUX_LIB@ @ATTR_LIB@ @NSCD_LIB@

pwunconv_SOURCES = pwunconv.c
pwunconv_LDADD = ../lib/libpwdutils.a @LDAP_LIBS@ @NSL_LIB@ @SELINUX_LIB@ @ATTR_LIB@ @NSCD_LIB@

useradd_SOURCES = useradd.c
useradd_LDADD = ../lib/libpwdutils.a @PAM_LIBS@ @LDAP_LIBS@ @NSL_LIB@ @SELINUX_LIB@ @ATTR_LIB@ @NSCD_LIB@

userdel_SOURCES = userdel.c
userdel_LDADD = ../lib/libpwdutils.a @PAM_LIBS@ @LDAP_LIBS@ @NSL_LIB@ @SELINUX_LIB@ @ATTR_LIB@ @NSCD_LIB@

usermod_SOURCES = usermod.c
usermod_LDADD = ../lib/libpwdutils.a @PAM_LIBS@ @LDAP_LIBS@ @NSL_LIB@ @SELINUX_LIB@ @ATTR_LIB@ @NSCD_LIB@

vipw_SOURCES = vipw.c
vipw_LDADD = ../lib/libpwdutils.a @SELINUX_LIB@ @ATTR_LIB@

newgrp_SOURCES = newgrp.c
newgrp_CFLAGS = @PIE_CFLAGS@
newgrp_LDADD = ../lib/libpwdutils.a @CRYPT_LIB@
newgrp_LDFLAGS = @PIE_LDFLAGS@

install-exec-hook:
	$(LN_F) $(DESTDIR)$(sbindir)/vipw  $(DESTDIR)$(sbindir)/vigr
	$(LN_F) $(DESTDIR)$(bindir)/newgrp $(DESTDIR)$(bindir)/sg
	if test $$UID == 0; then \
	  list='chage chfn chsh expiry passwd'; \
	  for p in $$list ; do \
	    chgrp shadow $(DESTDIR)$(bindir)/$$p; \
	    chmod g+s $(DESTDIR)$(bindir)/$$p; \
	  done ; \
	fi

uninstall-hook:
	$(RM_F) $(DESTDIR)$(sbindir)/vigr $(DESTDIR)$(bindir)/sg