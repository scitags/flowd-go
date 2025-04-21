Name:		flowd-go
Version:	2.0
Release:	1
Summary:	SciTags flowd-go Daemon
BuildArch:	x86_64

URL: https://github.com/scitags/flowd-go

Source0: flowd-go-2.0.tar.gz

License:	ASL 2.0

# Note libbpf-static already depends on the needed libbpf-devel
BuildRequires:	libbpf-static = 2:1.4.0-1.el9

# We would need bpftool to generate vmlinux.h when building. We'll
# simply include it in the SRPM instead as we might face some
# problems when trying to access /sys/kernel/btf/vmlinux...
# BuildRequires:	bpftool >= 7.4.0

# Any version of Make should do, so don't ask for a particular one...
BuildRequires:	make >= 1:4.3-8.el9

# Any (recent) version of clang and llvm should do
BuildRequires:	clang >= 18.1.8-3.el9
BuildRequires:	llvm  >= 18.1.8-3.el9

BuildRequires:	golang >= 1.22.9
BuildRequires:	gzip >= 1.12

# Needed for all the SystemD-related macros and such
BuildRequires:	systemd
BuildRequires:	systemd-rpm-macros

# Let's try not to impose any restriction for now. Besides, this shouldn't
# even be necessary given libbpf should be bundled with the output binary!
# Requires:	libbpf = 2:1.4.0-1.el9
# Requires:	libbpf

# Longer description on what the package is/does
%description
Reimplementation of the flowd daemon in Go.

The flowd-go daemon serves as the backbone for HEPiX's
SciTags initiative as seen on https://www.scitags.org

# For some reason (we're invoking clang?) the RPM package will want to build
# a debuginfo package. As there's no information for that, it'll fail with
# an error... The following overrides that behaviour so that no debuginfo
# packages are built whatsoever.
%define debug_package %{nil}

%prep
%setup

%build
make build

GOBIN=$(pwd) go install github.com/cpuguy83/go-md2man/v2@latest
$(pwd)/go-md2man -in rpm/${RPM_PACKAGE_NAME}.1.md | gzip > ${RPM_PACKAGE_NAME}.1.gz

# Time to copy the binary file!
%install
# Delete the previos build root
rm -rf %{buildroot}

# Create the necessary directories
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_sysconfdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

# And install the necessary files
install -m 0775 bin/%{name}         %{buildroot}%{_bindir}/%{name}
install -m 0644 rpm/conf.json       %{buildroot}%{_sysconfdir}/%{name}/conf.json
install -m 0664 rpm/%{name}.service %{buildroot}%{_unitdir}/%{name}.service
install -m 0664 rpm/%{name}.1.gz    %{buildroot}%{_mandir}/man1/%{name}.1.gz

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

# Files provided by the package. Check https://docs.fedoraproject.org/en-US/packaging-guidelines/#_manpages too!
%files
%defattr(-,root,root)
%attr(755, root, root) %{_bindir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/conf.json
%{_unitdir}/%{name}.service
%doc %{_mandir}/man1/%{name}.1*

# Changes introducd with each version
%changelog
* Thu Nov 14 2024 Pablo Collado Soto <pablo.collado.soto@cern.ch> - 2.0-1
- Update to flowd-go-2.0

* Wed Nov 6 2024 Pablo Collado Soto <pablo.collado.soto@cern.ch> - 1.0-1
- Release flowd-go-1.0
