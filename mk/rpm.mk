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

SPECFILE             = $(shell find . -type f -name *.spec)
SPECFILE_NAME        = $(shell awk '$$1 == "Name:"     { print $$2 }' $(SPECFILE))
SPECFILE_VERSION     = $(shell awk '$$1 == "Version:"  { print $$2 }' $(SPECFILE))
SPECFILE_RELEASE     = $(shell awk '$$1 == "Release:"  { print $$2 }' $(SPECFILE))
DIST                ?= $(shell rpm --eval %{dist})

# Path of the buildroot created with rpmdev-setuptree. In order to create
# it, install the necessary tools as explained on the main README.md and
# then simply run rpmdev-setuptree. The build tree will be created by
# default on ${HOME}/rpmbuild, hence the definition of this variable.
RPM_BUILDROOT = $(shell echo ${HOME})/rpmbuild

# Simply show the variables we'll use in the build
.PHONY: rpm-dbg
rpm-dbg:
	@echo "        SPECFILE: $(SPECFILE)"
	@echo "   SPECFILE_NAME: $(SPECFILE_NAME)"
	@echo "SPECFILE_VERSION: $(SPECFILE_VERSION)"
	@echo "SPECFILE_RELEASE: $(SPECFILE_RELEASE)"
	@echo "            DIST: $(DIST)"
	@echo "         VERSION: $(VERSION)"

# Files to include in the SRPM
RPM_FILES := backends cmd enrichment plugins settings rpm stun types const.go go.mod go.sum vendor Makefile

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
sources: rpm-clean
	ls -la
	env

	mkdir -p $(PWD)/dist/${SPECFILE_NAME}-${SPECFILE_VERSION} $(PWD)/build

	yum-builddep -y $(SPECFILE)

	go mod vendor

	go generate

	gzip --force rpm/$(SPECFILE_NAME).1

	cp -pr ${RPM_FILES} dist/${SPECFILE_NAME}-${SPECFILE_VERSION}/.
	cat .git/$(shell cut -d ' ' -f 2 .git/HEAD)
	cat .git/$(shell cut -d ' ' -f 2 .git/HEAD) > dist/${SPECFILE_NAME}-${SPECFILE_VERSION}/commit

	find dist -type d -name .git       | xargs -i rm -rf {}
	find dist -type d -name '*sample*' | xargs -i rm -rf {}
	find dist -type f -name '*.gdb'    | xargs -i rm -rf {}
	find dist -type f -name '*.pcapng' | xargs -i rm -rf {}
	find dist -type f -name '*.o'      | xargs -i rm -rf {}
	find dist -type f -name 'test'     | xargs -i rm -rf {}

	cd dist; tar -czvf ${SPECFILE_NAME}-${SPECFILE_VERSION}.tar.gz ${SPECFILE_NAME}-${SPECFILE_VERSION}

	cp dist/${SPECFILE_NAME}-${SPECFILE_VERSION}.tar.gz .

	ls -la
	ls -la ..

# Simply build a SRPM after bundling the sources. Please note the target name MUST be srpm as this is what CERN's koji
# instance expects.
.PHONY: srpm
srpm: sources
	ls -la
	rpmbuild -bs --define "dist $(DIST)" --define "_topdir $(PWD)/build" --define '_sourcedir $(PWD)/dist' $(SPECFILE)

# Build the binary (i.e. carrying teh compiled binary) RPM. Please note the target name MUST be rpm as this is what
# CERN's koji instance expects.
.PHONY: rpm
rpm: sources
	rpmbuild -bb --define "dist $(DIST)" --define "_topdir $(PWD)/build" --define '_sourcedir $(PWD)/dist' $(SPECFILE)

# Note how we need network access so that Go can pull its dependencies!
.PHONY: rpm-mock
rpm-mock: srpm
	mock -r almalinux-9-x86_64 build/SRPMS/flowd-go-$(SPECFILE_VERSION)-$(SPECFILE_RELEASE).src.rpm

# .PHONY: rpm-cat
# rpm-cat:
# 	rpm2cpio build/SRPMS/flowd-go-$(SPECFILE_VERSION)-$(SPECFILE_RELEASE).src.rpm | cpio -idmv

.PHONY: rpm-clean
rpm-clean:
	rm -rf build dist vendor
