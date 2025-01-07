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
        libbpf-devel-2:1.3.0  \
        libbpf-static-2:1.3.0 \
        bpftool-7.3.0         \
        clang-17.0.6          \
        make-1:4.3            \
        git-2.43.5            \
        tar                   \
    && microdnf clean all

# Versions of manually-installed tools. Note the provided value is a default that
# can be overridden when invoking the build procedure.
ARG GO_VERSION=1.23.0

# Get Go
RUN curl -o go.tar.gz https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go.tar.gz && \
    rm -rf go.tar.gz

# Update the path so as to include Go
ENV PATH="/usr/local/go/bin:${PATH}"

# Specify a sane working directory
WORKDIR /root
