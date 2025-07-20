config_opts['chroot_setup_cmd'] = 'install bash bzip2 coreutils cpio diffutils redhat-release findutils gawk glibc-minimal-langpack grep gzip info patch redhat-rpm-config rpm-build sed tar unzip util-linux which xz'
config_opts['dist'] = 'el9.alma'  # only useful for --resultdir variable subst
config_opts['releasever'] = '9'
config_opts['package_manager'] = 'dnf'
config_opts['extra_chroot_dirs'] = [ '/run/lock', ]
config_opts['bootstrap_image'] = 'quay.io/almalinuxorg/almalinux:9'

config_opts['dnf.conf'] = """
[main]
keepcache=1
debuglevel=2
reposdir=/dev/null
logfile=/var/log/yum.log
retries=20
obsoletes=1
gpgcheck=0
assumeyes=1
syslog_ident=mock
syslog_device=
metadata_expire=0
mdpolicy=group:primary
best=1
install_weak_deps=0
protected_packages=
module_platform_id=platform:el9
user_agent={{ user_agent }}


[baseos]
name=AlmaLinux $releasever CERN - BaseOS
baseurl=https://linuxsoft.cern.ch/cern/alma/$releasever/BaseOS/$basearch/os/
enabled=1
countme=1
gpgcheck=1
gpgkey=file:///usr/share/distribution-gpg-keys/alma/RPM-GPG-KEY-AlmaLinux-9
skip_if_unavailable=False

[appstream]
name=AlmaLinux $releasever CERN - AppStream
baseurl=https://linuxsoft.cern.ch/cern/alma/$releasever/AppStream/$basearch/os/
enabled=1
countme=1
gpgcheck=1
gpgkey=file:///usr/share/distribution-gpg-keys/alma/RPM-GPG-KEY-AlmaLinux-9

[crb]
name=AlmaLinux $releasever CERN - CRB
baseurl=https://linuxsoft.cern.ch/cern/alma/$releasever/CRB/$basearch/os/
enabled=1
countme=1
gpgcheck=1
gpgkey=file:///usr/share/distribution-gpg-keys/alma/RPM-GPG-KEY-AlmaLinux-9

[extras]
name=AlmaLinux $releasever CERN - Extras
baseurl=https://linuxsoft.cern.ch/cern/alma/$releasever/extras/$basearch/os/
enabled=1
countme=1
gpgcheck=1
gpgkey=file:///usr/share/distribution-gpg-keys/alma/RPM-GPG-KEY-AlmaLinux-9

[devel]
name=AlmaLinux $releasever CERN - Devel (WARNING: UNSUPPORTED - FOR BUILDROOT USE ONLY!)
baseurl=https://linuxsoft.cern.ch/cern/alma/$releasever/devel/$basearch/os/
enabled=0
gpgcheck=1
gpgkey=file:///usr/share/distribution-gpg-keys/alma/RPM-GPG-KEY-AlmaLinux-9

[baseos-debuginfo]
name=AlmaLinux $releasever CERN - BaseOS debuginfo
baseurl=https://linuxsoft.cern.ch/cern/alma/$releasever/BaseOS/debug/$basearch/
enabled=0
gpgcheck=1
gpgkey=file:///usr/share/distribution-gpg-keys/alma/RPM-GPG-KEY-AlmaLinux-9

[appstream-debuginfo]
name=AlmaLinux $releasever CERN - AppStream debuginfo
baseurl=https://linuxsoft.cern.ch/cern/alma/$releasever/AppStream/debug/$basearch/
enabled=0
gpgcheck=1
gpgkey=file:///usr/share/distribution-gpg-keys/alma/RPM-GPG-KEY-AlmaLinux-9

[crb-debuginfo]
name=AlmaLinux $releasever CERN - CRB debuginfoo
baseurl=https://linuxsoft.cern.ch/cern/alma/$releasever/CRB/debug/$basearch/
enabled=0
gpgcheck=1
gpgkey=file:///usr/share/distribution-gpg-keys/alma/RPM-GPG-KEY-AlmaLinux-9

[extras-debuginfo]
name=AlmaLinux $releasever CERN - Extras debuginfo
baseurl=https://linuxsoft.cern.ch/cern/alma/$releasever/extras/debug/$basearch/
enabled=0
gpgcheck=1
gpgkey=file:///usr/share/distribution-gpg-keys/alma/RPM-GPG-KEY-AlmaLinux-9

[devel-debuginfo]
name=AlmaLinux $releasever CERN - Devel debuginfo
baseurl=https://linuxsoft.cern.ch/cern/alma/$releasever/devel/debug/$basearch/
enabled=0
gpgcheck=1
gpgkey=file:///usr/share/distribution-gpg-keys/alma/RPM-GPG-KEY-AlmaLinux-9

"""
