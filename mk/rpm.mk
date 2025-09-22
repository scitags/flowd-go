# This Makefile provides several targets hadling the creation of of RPM packages
# and documentation for publishing flowd-go. Bear in mind one needs to do quite
# a bit of reading before attempting to understand everything at play here. Be
# sure to check the following:
#   https://rpm-software-management.github.io/rpm/manual/
#   https://rpm-software-management.github.io/rpm/manual/macros.html
#   https://rpm-software-management.github.io/rpm/manual/lua.html
#   https://rpm-software-management.github.io/rpm/manual/relocatable.html
#   https://rpm-software-management.github.io/rpm/manual/arch_dependencies.html
#   https://rpm-software-management.github.io/rpm/manual/buildprocess.html
#   https://rpm-software-management.github.io/rpm/manual/spec.html
#   https://docs.fedoraproject.org/en-US/packaging-guidelines/
#   https://docs.fedoraproject.org/en-US/packaging-guidelines/Golang/
#   https://rpm-software-management.github.io/mock/
#   https://rpm-packaging-guide.github.io
#   https://gitlab.cern.ch/linuxsupport/myrpm
#   https://gitlab.cern.ch/linuxsupport/rpmci

SPECFILE             = $(shell find . -type f -name *.spec)
SPECFILE_NAME        = $(shell awk '$$1 == "Name:"     { print $$2 }' $(SPECFILE))
SPECFILE_VERSION     = $(shell awk '$$1 == "Version:"  { print $$2 }' $(SPECFILE))
SPECFILE_RELEASE     = $(shell awk '$$1 == "Release:"  { print $$2 }' $(SPECFILE))
DIST                ?= $(shell rpm --eval %{dist})
ARCH                := $(shell uname -m)
RPM_TARGET_ARCH      = $(ARCH)
SRPM_PATH           ?= $(PWD)/build/SRPMS/flowd-go-$(SPECFILE_VERSION)-$(SPECFILE_RELEASE).src.rpm

# How are we going to bundle the sources into a *.tar.gz? By default we'll leverage Go
# to vendor and generate the Makefile, but we can also download a ready-made copy from
# a preexisting GitHub release and call it a day... In order to use this second mode
# one just needs to specify anything other than 'go' when invoking the sources
# target, for instance: make SRC_GEN_MODE=curl
SRC_GEN_MODE ?= go

# Let's get the Go version we're currently using so that we can download it should we
# need to. We'll mangle the Go version for now given we cannot install 1.24.4 when
# building on Koji...
GO_VERSION = $(shell awk '/^go[[:space:]]/ {print $$2}' go.mod)

# The name of the *.tar.gz with the bundled sources. Note this name MUST be the one specified
# in the SPEC file on field Sources0.
SOURCES_FILENAME := ${SPECFILE_NAME}-${SPECFILE_VERSION}.tar.gz

# Path of the buildroot created with rpmdev-setuptree. In order to create
# it, install the necessary tools as explained on the main README.md and
# then simply run rpmdev-setuptree. The build tree will be created by
# default on ${HOME}/rpmbuild, hence the definition of this variable.
RPM_BUILDROOT = $(shell echo ${HOME})/rpmbuild

# If we have to download either Go or jq we need to know the architecture we're running on.
# The value returned by uname(1) is not the one used when distributing software, so we'll
# just do a naive translation. We could even safely assume to always be running on amd64
# though....
ifeq ($(ARCH),x86_64)
DL_ARCH := amd64
else
DL_ARCH := arm64
endif

# Everything jq-related. This URL we'll be leveraged if running in the download-a-ready-made-file mode.
JQ_VERSION      := 1.7.1
JQ_DOWNLOAD_URL := https://github.com/jqlang/jq/releases/download/jq-$(JQ_VERSION)/jq-linux-$(DL_ARCH)

# The URLs from GitHub's API allowing us to get the latest release and download the read-made sources.
GH_LATEST_RELEASE_URL   := https://github.com/scitags/flowd-go/releases/latest
GH_SOURCES_DOWNLOAD_URL := https://github.com/scitags/flowd-go/releases/download/$(RELEASE_VER)/sources.tar.gz

# Simply show the variables we'll use in the build
.PHONY: rpm-dbg
rpm-dbg:
	@echo "        SPECFILE: $(SPECFILE)"
	@echo "   SPECFILE_NAME: $(SPECFILE_NAME)"
	@echo "SPECFILE_VERSION: $(SPECFILE_VERSION)"
	@echo "SPECFILE_RELEASE: $(SPECFILE_RELEASE)"
	@echo "            DIST: $(DIST)"
	@echo "         VERSION: $(VERSION)"
	@echo "         DL_ARCH: $(DL_ARCH)"
	@echo "      GO_VERSION: $(GO_VERSION)"
	@echo " RPM_TARGET_ARCH: $(RPM_TARGET_ARCH)"
	@echo "       SRPM_PATH: $(SRPM_PATH)"

# Files to include in the SRPM
RPM_FILES := backends cmd enrichment plugins settings rpm stun types go.mod go.sum Makefile vendor commit

# This target will bundle all the source files so that we can easily create a SRPM with our SPEC file.
# We'll also bundle vmlinux.h so as to avoid having to generate that on the machine we might generate
# the SRPM on: these might be CI/CD workers where access to the /sys directory might be forbidden...
# We'll also get rid of any other unnecessary stuff and include a file containing the current commit
# so that we can fetch it when building the RPM, something completely independent of the git repo (we
# are actually deleting the .git directory!). Please note the target name MUST be sources as this is
# what CERN's koji instance expects! Be sure to check https://gitlab.cern.ch/linuxsupport/myrpm for
# a great working example. The repo at https://gitlab.cern.ch/linuxsupport/rpmci is also a fundamental
# source of information.
.PHONY: sources
sources:
	mkdir -p $(PWD)/build

	ls -la

ifeq ($(SRC_GEN_MODE),go)
	@# Only download Go if it's not present on the PATH.
	which go || curl -L -s -o go.tar.gz https://dl.google.com/go/go$(GO_VERSION).linux-$(DL_ARCH).tar.gz
	which go || tar -C /tmp -xzf go.tar.gz
	which go || /tmp/go/bin/go version

	@# Try to use a 'normally' installed Go release and, if not, use the one we should've already installed.
	go mod vendor || /tmp/go/bin/go mod vendor
	go generate cmd/doc.go || /tmp/go/bin/go generate cmd/doc.go
	gzip --force rpm/$(SPECFILE_NAME).1

	@# Record the current commit so that it can be embedded in the resulting binary.
	cat .git/$(shell cut -d ' ' -f 2 .git/HEAD) > commit || git rev-parse --short HEAD > commit

	@# Simply append the needed prefix to every entry in the *.tar.gz instead of creating a tree.
	tar -czvf $(SOURCES_FILENAME) --transform 's,^,${SPECFILE_NAME}-${SPECFILE_VERSION}/,' $(RPM_FILES)

	@# Make a copy of the sources with a known name to include it in GitHub releases. This could be done
	@# on the GitHub CI workflows, but it's much easier to do it here instead.
	cp $(SOURCES_FILENAME) sources.tar.gz
else
	curl -sLo jq $(JQ_DOWNLOAD_URL); chmod +x jq
	$(eval RELEASE_VER := $(shell curl -L -s -H 'Accept: application/json' $(GH_LATEST_RELEASE_URL) | ./jq -r .tag_name))
	curl -sLo $(SOURCES_FILENAME) $(GH_SOURCES_DOWNLOAD_URL)
endif

# Simply build a SRPM after bundling the sources. Please note the target name MUST be srpm as this is what CERN's koji
# instance expects.
.PHONY: srpm
srpm: sources
	rpmbuild -bs --define "dist $(DIST)" --define "_topdir $(PWD)/build" --define '_sourcedir $(PWD)' $(SPECFILE)

# Build the binary (i.e. carrying teh compiled binary) RPM. Please note the target name MUST be rpm as this is what
# CERN's koji instance expects.
.PHONY: rpm
rpm:
	rpmbuild -rb                        \
		--define "dist $(DIST)"         \
		--define "_topdir $(PWD)/build" \
		--define '_sourcedir $(PWD)'    \
		--noclean \
		$(SRPM_PATH)

# Note how we need network access so that Go can pull its dependencies!
.PHONY: rpm-mock
rpm-mock: srpm
	mock -r almalinux-9-$(RPM_TARGET_ARCH) -v --resultdir $(PWD)/build build/SRPMS/flowd-go-$(SPECFILE_VERSION)-$(SPECFILE_RELEASE).src.rpm

# .PHONY: rpm-cat
# rpm-cat:
# 	rpm2cpio build/SRPMS/flowd-go-$(SPECFILE_VERSION)-$(SPECFILE_RELEASE).src.rpm | cpio -idmv

.PHONY: rpm-clean
rpm-clean:
	rm -rf build dist vendor *.tar.gz commit
