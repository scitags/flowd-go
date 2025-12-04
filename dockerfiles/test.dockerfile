# Let's try to build a small image!
FROM almalinux:9.4-minimal

# Add handy metadata
LABEL \
    org.opencontainers.image.vendor="SciTags Organization"                          \
    org.opencontainers.image.source="https://github.com/scitags/flowd-go"           \
    org.opencontainers.image.title="flowd-go"                                       \
    org.opencontainers.image.description="Container for testing flowd-go on the CI" \
    org.opencontainers.image.authors="Pablo Collado Soto"
    # org.opencontainers.image.created=$BUILD_DATE                                  \
    # org.opencontainers.image.version=$BUILD_VERSION

# Add the vault repo so that we can pull older versions of packages
COPY vault.repo /etc/yum.repos.d/

# Get all the necessary dependencies.
RUN microdnf --refresh --enablerepo=crb --nodocs --setopt=install_weak_deps=0 -y install \
        libbpf-devel-2:1.4.0  \
        libbpf-static-2:1.4.0 \
        bpftool-7.4.0         \
        clang-18.1.8          \
        llvm-18.1.8           \
        golang>=1.24          \
        make-1:4.3            \
        git-2.43.5            \
        tar                   \
        which                 \
    && microdnf clean all

# Specify a sane working directory
WORKDIR /root
