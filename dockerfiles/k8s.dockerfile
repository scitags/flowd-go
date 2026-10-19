FROM ghcr.io/scitags/flowd-go:build AS builder

# Add handy metadata
LABEL \
    org.opencontainers.image.vendor="SciTags Organization"                \
    org.opencontainers.image.source="https://github.com/scitags/flowd-go" \
    org.opencontainers.image.title="flowd-go"                             \
    org.opencontainers.image.description="Container for running flowd-go" \
    org.opencontainers.image.authors="Pablo Collado Soto"

# Directory's created if it doesn't exist
WORKDIR /root/flowd-go

COPY . .

# See https://docs.docker.com/reference/dockerfile#automatic-platform-args-in-the-global-scope
ARG TARGETPLATFORM
ARG TARGETARCH
RUN echo "building for TARGETPLATFORM: ${TARGETPLATFORM}, TARGETARCH: ${TARGETARCH}"

RUN make build TARGET_ARCH=$(if [ "${TARGETARCH}" = "amd64" ]; then echo "x86_64"; else echo "aarch64"; fi)

FROM alpine:latest

COPY --from=builder /root/flowd-go/bin/flowd-go /bin/flowd-go
COPY --from=builder /root/flowd-go/rpm/conf.yaml /etc/flowd-go/conf.yaml

ENTRYPOINT [ "/bin/flowd-go" ]
