Name:           pwdutils
BuildRequires:  libtool
BuildRequires:  openssl-devel
BuildRequires:  pam-devel
BuildRequires:  gettext-tools
Url:            http://www.thkukuk.de/pam/pwdutils/
Version:        3.2.19
Release:        0
Summary:        Utilities to Manage User and Group Accounts
License:        GPL-2.0
Group:          Security/Accounts
Source:         pwdutils-%{version}.tar.bz2
Source3:        useradd.default
Source1001:     pwdutils.manifest

%description
This package includes the necessary programs for converting plain
password files to the shadow password format, and managing user and
group accounts in both local files and in an LDAP database.

%prep
%setup -q
cp %{SOURCE1001} .

%build
%reconfigure --disable-ldap --libdir=%{_libdir} --disable-nls --disable-pam_rpasswd
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}
rm -f %{buildroot}%{_libdir}/pwdutils/lib*.so
/sbin/ldconfig -n %{_libdir}/pwdutils

rm -f %{buildroot}%{_libdir}/pwdutils/*a
rm -f %{buildroot}%{_lib}/security/*a
rm -f %{buildroot}%{_sysconfdir}/init.d/rpasswdd
rm -f %{buildroot}%{_sysconfdir}/pam.d/rpasswd
rm -f %{buildroot}%{_sysconfdir}/rpasswd.conf
rm -f %{buildroot}%{_bindir}/rpasswd
rm -f %{buildroot}%{_sbindir}/rpasswdd

ln -sf newgrp %{buildroot}%{_bindir}/sg
install -m 644 %{SOURCE3} %{buildroot}%{_sysconfdir}/default/useradd
echo ".so man8/useradd.8" > %{buildroot}%{_mandir}/man8/adduser.8

%docs_package

%files 
%manifest %{name}.manifest
%license COPYING
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

