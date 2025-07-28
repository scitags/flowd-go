# Let's try to build a small image!
FROM almalinux:latest

# Add handy metadata
LABEL \
    org.opencontainers.image.vendor="SciTags Organization"                                  \
    org.opencontainers.image.source="https://github.com/scitags/flowd-go"                   \
    org.opencontainers.image.title="flowd-go"                                               \
    org.opencontainers.image.description="Container for packaging flowd-go up with mock(1)" \
    org.opencontainers.image.authors="Pablo Collado Soto"

RUN mkdir -p /etc/yum.repos.ours

COPY yum.conf /etc/yum.conf

# Add the vault repo so that we can pull older versions of packages
COPY cern.repo /etc/yum.repos.ours/

# Get all the necessary dependencies
RUN dnf --refresh --enablerepo=crb -y install \
        rpm-build     \
        dnf-plugins-core \
        which         \
        git           \
        tar           \
        make          \
        golang \
    && dnf clean all

# Specify a sane working directory
WORKDIR /root
