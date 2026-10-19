# Dockerfiles for various purposes
Flowd-go relies heavily on eBPF, which introduces a clear dependency on Linux.
In order to carry out several tasks we rely on Docker containers: we use them
for the CI/CD pipelines, to run binaries on platforms other than Linux and to
distribute it to k8s-centric sites and deployments.

Most of the Dockerfiles contained in this directory are meant to be used
implicitly through the Makefile at the repo's root.

## Building the k8s images
We prepare some images bundling flowd-go on Alpine so that they are lean and
easily usable by k8s clusters. In order to build these images we must first
build the base image (i.e. the one we use to build the binary)

    $ docker build --platform linux/amd64,linux/arm64 -f build.dockerfile -t ghcr.io/scitags/flowd-go:build .

and them from the repo's root we can build the release image

    $ docker build --platform linux/arm64,linux/amd64 -f dockerfiles/k8s.dockerfile -t ghcr.io/scitags/flowd-go:v2.6.0 .

After that a simple

    $ docker push ghcr.io/scitags/flowd-go:v2.6.0

will make it readily available.
