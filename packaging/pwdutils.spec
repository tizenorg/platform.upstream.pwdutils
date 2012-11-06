Name:           pwdutils
Version:        3.2.19
Release:        0
License:        GPL-2.0
Summary:        Utilities to Manage User and Group Accounts
Url:            http://www.thkukuk.de/pam/pwdutils/
Group:          System/Base
Source:         pwdutils-%{version}.tar.bz2
Source3:        useradd.default
Patch0:         pam.patch
Patch1:         pwdutils-no-add-needed.patch
Patch2:         pwdutils-glibc216.patch
BuildRequires:  gettext-tools
BuildRequires:  libtool
BuildRequires:  openssl-devel
BuildRequires:  pam-devel

%description
This package includes the necessary programs for converting plain
password files to the shadow password format, and managing user and
group accounts in both local files and in an LDAP database.

%prep
%setup -q
%patch0 -p1
%patch1
%patch2 -p1

%build
%reconfigure --disable-ldap --libdir=%{_libdir} --disable-nls --disable-pam_rpasswd
make %{?_smp_mflags}

%install
%make_install
rm -f %{buildroot}%{_libdir}/pwdutils/lib*.so
#mkdir %{buildroot}/%{_lib}
#mv %{buildroot}%{_libdir}/security %{buildroot}/%{_lib}
/sbin/ldconfig -n %{_libdir}/pwdutils
rm -f %{buildroot}%{_libdir}/pwdutils/*a
rm -f %{buildroot}/%{_lib}/security/*a

rm -f %{buildroot}%{_initddir}/rpasswdd
rm -f %{buildroot}%{_sysconfdir}/pam.d/rpasswd
rm -f %{buildroot}%{_sysconfdir}/rpasswd.conf
rm -f %{buildroot}/usr/bin/rpasswd
rm -f %{buildroot}/usr/sbin/rpasswdd
ln -sf newgrp %{buildroot}%{_bindir}/sg
install -m 644 $RPM_SOURCE_DIR/useradd.default %{buildroot}%{_sysconfdir}/default/useradd
echo ".so man8/useradd.8" > %{buildroot}%{_mandir}/man8/adduser.8

%docs_package

%files
%defattr(-,root,root,755)
%config %{_sysconfdir}/login.defs
%config %{_sysconfdir}/pam.d/chage
%config %{_sysconfdir}/pam.d/chfn
%config %{_sysconfdir}/pam.d/chsh
%config %{_sysconfdir}/pam.d/passwd
%config %{_sysconfdir}/pam.d/shadow
%config %{_sysconfdir}/pam.d/useradd
%config(noreplace) %{_sysconfdir}/default/useradd
%config(noreplace) %{_sysconfdir}/default/passwd
%dir %{_sysconfdir}/pwdutils
%config(noreplace) %{_sysconfdir}/pwdutils/logging
%attr (4755,root,shadow) %{_bindir}/chage
%attr (4755,root,shadow) %{_bindir}/chfn
%attr (4755,root,shadow) %{_bindir}/chsh
%attr (4755,root,shadow) %{_bindir}/expiry
%attr (4755,root,shadow) %{_bindir}/gpasswd
%attr (4755,root,root) %{_bindir}/newgrp
%attr (4755,root,shadow) %{_bindir}/passwd
%{_bindir}/sg
%{_sbindir}/chpasswd
%{_sbindir}/groupadd
%{_sbindir}/groupdel
%{_sbindir}/groupmod
%{_sbindir}/grpck
%{_sbindir}/grpconv
%{_sbindir}/grpunconv
%{_sbindir}/pwck
%{_sbindir}/pwconv
%{_sbindir}/pwunconv
%{_sbindir}/useradd
%verify(not md5 size mtime) %config(noreplace) %{_sbindir}/groupadd.local
%verify(not md5 size mtime) %config(noreplace) %{_sbindir}/useradd.local
%verify(not md5 size mtime) %config(noreplace) %{_sbindir}/userdel-pre.local
%verify(not md5 size mtime) %config(noreplace) %{_sbindir}/userdel-post.local
%{_sbindir}/userdel
%{_sbindir}/usermod
%{_sbindir}/vigr
%{_sbindir}/vipw
%dir %{_libdir}/pwdutils
%{_libdir}/pwdutils/liblog_syslog.so.1*

