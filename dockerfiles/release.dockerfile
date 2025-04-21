# Version of the test image we'll use as base
ARG BASE_VERSION=2.59.0

# We'll simply add on to the CI image for testing
FROM ghcr.io/scitags/flowd-go:test-${BASE_VERSION}

# Add handy metadata
LABEL \
    org.opencontainers.image.vendor="SciTags Organization"                            \
    org.opencontainers.image.source="https://github.com/scitags/flowd-go"             \
    org.opencontainers.image.title="flowd-go"                                         \
    org.opencontainers.image.description="Container for releasing flowd-go on the CI" \
    org.opencontainers.image.authors="Pablo Collado Soto"
    # org.opencontainers.image.created=$BUILD_DATE                                    \
    # org.opencontainers.image.version=$BUILD_VERSION

# Get the EPEL repo
RUN microdnf --refresh --enablerepo=crb --nodocs --setopt=install_weak_deps=0 -y install \
    epel-release

# Add the additional dependencies needed for releasing. Note the dependency on systemd is
# introduced by the fact that the resulting package carries a SystemD unit file.
RUN microdnf --refresh --enablerepo=crb --nodocs --setopt=install_weak_deps=0 -y install \
        rpm-build   \
        rpmdevtools \
        systemd     \
    && microdnf clean all

# Versions of the GH CLI to use. Note the provided value is a default that can be overridden
# by passing the argument when invoking the build.
ARG GH_CLI_VERSION=2.59.0

# Install GH CLI for making releases in an easier fashion
RUN curl -LO https://github.com/cli/cli/releases/download/v${GH_CLI_VERSION}/gh_${GH_CLI_VERSION}_linux_amd64.tar.gz && \
    tar -xzf gh_${GH_CLI_VERSION}_linux_amd64.tar.gz && \
    cp gh_${GH_CLI_VERSION}_linux_amd64/bin/gh /bin && \
    rm -rf gh_${GH_CLI_VERSION}_linux_amd64*

# Setup the RPM build tree
RUN rpmdev-setuptree
