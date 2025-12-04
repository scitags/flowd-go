# Simply define the image version in case we're running standalone. Otherwise this
# variable will be overridden by the one exported from the top-level Makefile.
DOCKER_IMG_VERSION ?= v2.2

GO_VERSION = $(shell awk '/^go[[:space:]]/ {print $$2}' ../go.mod)

# Just build the development image
all: dev
	@echo If you want to build the test and release images, please do so manually"

# Build the Docker image for development. We'll build a multi-arch file given
# some devs might be working with ARM-based machines...
.PHONY: dev
dev: vault.repo
	@docker buildx build --platform linux/amd64 \
		--progress plain \
		-t ghcr.io/scitags/flowd-go:dev-$(DOCKER_IMG_VERSION) -f dev.dockerfile .

# Build the CI image we'll be using when running tests on the CI.
# At one point we tried to compile and statically link clang with:
#   $ git clone --depth=1 --branch llvmorg-17.0.6 https://github.com/llvm/llvm-project.git llvm-17.0.6
#   $ cd llvm-17.0.6
#   $ mkdir build; cd build
#   $ cmake -DLLVM_ENABLE_PROJECTS="clang;lld" -DCMAKE_BUILD_TYPE=MinSizeRel -DLLVM_ENABLE_THREADS=True -DLLVM_TARGETS_TO_BUILD="X86;BPF" -G "Unix Makefiles" ../llvm
#   $ make -j$(nproc)
# Please check the following for (much) more info:
#   https://clang.llvm.org/get_started.html
#   https://llvm.org/docs/GettingStarted.html
#   https://llvm.org/docs/CMake.html#llvm-related-variables
.PHONY: test
test: vault.repo
	docker buildx build --platform linux/amd64 \
		--progress plain --no-cache \
		-t ghcr.io/scitags/flowd-go:test-$(DOCKER_IMG_VERSION) -f test.dockerfile .

# Build the CI image we'll be using when releasing the CI
.PHONY: release
release:
	docker buildx build --platform linux/amd64 \
		--build-arg BASE_VERSION=$(DOCKER_IMG_VERSION) \
		--build-arg GH_CLI_VERSION=2.59.0 \
		--progress plain \
		-t ghcr.io/scitags/flowd-go:release-$(DOCKER_IMG_VERSION) -f release.dockerfile .

# Build the multiplatform CI image we'll be using for building SRPMs and RPMs
.PHONY: rpm
rpm:
	docker buildx build --platform linux/amd64,linux/arm64 \
		--progress plain \
		-t ghcr.io/scitags/flowd-go:rpm-$(DOCKER_IMG_VERSION) -f rpm.dockerfile .
