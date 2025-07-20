# Let's try to build a small image!
FROM almalinux:minimal

# Add handy metadata
LABEL \
    org.opencontainers.image.vendor="SciTags Organization"                                  \
    org.opencontainers.image.source="https://github.com/scitags/flowd-go"                   \
    org.opencontainers.image.title="flowd-go"                                               \
    org.opencontainers.image.description="Container for packaging flowd-go up with mock(1)" \
    org.opencontainers.image.authors="Pablo Collado Soto"

# Add the vault repo so that we can pull older versions of packages
COPY vault.repo /etc/yum.repos.d/

# Pull EPEL
RUN microdnf --refresh --enablerepo=crb --nodocs --setopt=install_weak_deps=0 -y install epel-release

# Get all the necessary dependencies
RUN microdnf --refresh --enablerepo=crb --nodocs --setopt=install_weak_deps=0 -y install \
        mock          \
        rpm-build     \
        git           \
        tar           \
        make          \
        golang-1.23.9 \
    && microdnf clean all

# Copy the necessary mock(1) configurations
COPY almalinux-9-cern-x86_64.cfg            /etc/mock/
COPY almalinux-9-cern-x86_64-to-aarch64.cfg /etc/mock/
COPY almalinux-9-cern.tpl                   /etc/mock/templates

# Specify a sane working directory
WORKDIR /root
