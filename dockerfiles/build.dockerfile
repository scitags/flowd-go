# Let's try to build a small image!
FROM almalinux:9

# Add handy metadata
LABEL \
    org.opencontainers.image.vendor="SciTags Organization"                 \
    org.opencontainers.image.source="https://github.com/scitags/flowd-go"  \
    org.opencontainers.image.title="flowd-go"                              \
    org.opencontainers.image.description="Container for building flowd-go" \
    org.opencontainers.image.authors="Pablo Collado Soto"

RUN dnf config-manager --enable crb
RUN dnf check-update || true
RUN dnf update -y
RUN dnf install -y epel-release

# Get all the necessary dependencies.
RUN dnf install -y   \
        libbpf-devel \
        clang        \
        golang       \
        make         \
        git          \
        tar          \
        which        \
    && dnf clean all

# Specify a sane working directory
WORKDIR /root
