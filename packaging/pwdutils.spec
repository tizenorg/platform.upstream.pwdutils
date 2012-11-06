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
Group:          System/Base
Source:         pwdutils-%{version}.tar.bz2
Source3:        useradd.default
Patch0:         pam.patch
Patch1:         pwdutils-no-add-needed.patch

%description
This package includes the necessary programs for converting plain
password files to the shadow password format, and managing user and
group accounts in both local files and in an LDAP database.




%prep
%setup -q
%patch0 -p1
%patch1

%build
%reconfigure --disable-ldap --libdir=%{_libdir} --disable-nls --disable-pam_rpasswd
make %{?_smp_mflags}

%install
make install DESTDIR=$RPM_BUILD_ROOT
rm -f $RPM_BUILD_ROOT%{_libdir}/pwdutils/lib*.so
mkdir $RPM_BUILD_ROOT/%{_lib}
mv $RPM_BUILD_ROOT%{_libdir}/security $RPM_BUILD_ROOT/%{_lib}
/sbin/ldconfig -n %{_libdir}/pwdutils
rm -f $RPM_BUILD_ROOT%{_libdir}/pwdutils/*a
rm -f $RPM_BUILD_ROOT/%{_lib}/security/*a

rm -f %{buildroot}/etc/init.d/rpasswdd
rm -f %{buildroot}/etc/pam.d/rpasswd
rm -f %{buildroot}/etc/rpasswd.conf
rm -f %{buildroot}/usr/bin/rpasswd
rm -f %{buildroot}/usr/sbin/rpasswdd
ln -sf newgrp $RPM_BUILD_ROOT%{_bindir}/sg
install -m 644 $RPM_SOURCE_DIR/useradd.default $RPM_BUILD_ROOT/etc/default/useradd
echo ".so man8/useradd.8" > $RPM_BUILD_ROOT%{_mandir}/man8/adduser.8

%docs_package

%files 
%defattr(-,root,root,755)
%config /etc/login.defs
%config /etc/pam.d/chage
%config /etc/pam.d/chfn
%config /etc/pam.d/chsh
%config /etc/pam.d/passwd
%config /etc/pam.d/shadow
%config /etc/pam.d/useradd
%config(noreplace) /etc/default/useradd
%config(noreplace) /etc/default/passwd
%dir /etc/pwdutils
%config(noreplace) /etc/pwdutils/logging
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

