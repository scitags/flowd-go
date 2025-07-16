Name:		flowd-go
Version:	2.1.0
Release:	1
Summary:	SciTags flowd-go Daemon

URL: https://github.com/scitags/flowd-go

Source0: flowd-go-%{version}.tar.gz

License:	ASL 2.0

# Note libbpf-static already depends on the needed libbpf-devel
BuildRequires:	libbpf-static = 2:1.5.0-1.el9

# We would need bpftool to generate vmlinux.h when building. Including
# vmlinux.h can be quite a headache given the file's size, but it might
# be what we need to do in the end as we're now relying on the machine
# building the RPMs to expose the correct types on /sys/kernel/btf/vmlinux,
# which is quite an assumption...
BuildRequires:	bpftool >= 7.4.0

# Any version of Make should do, so don't ask for a particular one...
BuildRequires:	make >= 1:4.3-8.el9

# Any (recent) version of clang and llvm should do
BuildRequires:	clang >= 18.1.8-3.el9
BuildRequires:	llvm  >= 18.1.8-3.el9

BuildRequires:	golang >= 1.23.9
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
# Note how we must specify the architecture we're building the RPM for
# so that we can configure GOARCH accordingly. The _target macro is
# populated by rpmbuild(1) through its --target option which is set
# by mock(1) when building the package. For the moment, it'll either
# be x86_64 or aarch64.
make build TARGET_ARCH=%{_target}

# Time to copy the binary file!
%install
# Delete the previous build root
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

# Changes introduced with each version
%changelog
* Wed Jul 16 2025 Pablo Collado Soto <pablo.collado.soto@cern.ch> - 2.1.0-1
- Support specifying collectors through hostnames

* Thu Apr 24 2025 Pablo Collado Soto <pablo.collado.soto@cern.ch> - 2.1-1
- Revamp the RPM building logic
- Enhance the eBPF-based enrichment logic

* Thu Nov 14 2024 Pablo Collado Soto <pablo.collado.soto@cern.ch> - 2.0-1
- Update to flowd-go-2.0

* Wed Nov 6 2024 Pablo Collado Soto <pablo.collado.soto@cern.ch> - 1.0-1
- Release flowd-go-1.0
