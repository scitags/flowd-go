# Pull the general AlmaLimux 9.4 image. Be sure to check
# https://hub.docker.com/_/almalinux for more info!
FROM almalinux:9.4

# Add handy metadata
LABEL \
    org.opencontainers.image.vendor="SciTags Organization"                   \
    org.opencontainers.image.source="https://github.com/scitags/flowd-go"    \
    org.opencontainers.image.title="flowd-go-cont"                           \
    org.opencontainers.image.description="Container for developing flowd-go" \
    org.opencontainers.image.authors="Pablo Collado Soto"
    # org.opencontainers.image.created=$BUILD_DATE                           \
    # org.opencontainers.image.version=$BUILD_VERSION

# Add the vault repo so that we can pull older versions of packages
COPY vault.repo /etc/yum.repos.d/

# Get DNF dependencies
RUN dnf --refresh --nodocs -y --setopt=install_weak_deps=False --enablerepo=crb install \
        libbpf-devel-2:1.4.0  \
        libbpf-static-2:1.4.0 \
        bpftool-7.4.0         \
        clang-18.1.8          \
        llvm-18.1.8           \
        golang>=1.24          \
        make-1:4.3            \
        git-2.43.5            \
        tcpdump-4.99.0        \
        iproute-6.2.0         \
        iproute-tc-6.2.0      \
        iperf3                \
    && dnf clean all

# As we'll be using multi-arch images we'll need a reference telling us what our
# architecture is! Check https://docs.docker.com/reference/dockerfile/#automatic-platform-args-in-the-global-scope
# ARG TARGETARCH

# TODO: Consider compiling a given version of libbpf to link against
# TODO: a explained on https://github.com/libbpf/libbpf

# Move to the home directory
WORKDIR /root
