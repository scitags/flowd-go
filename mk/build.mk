# This Makefile provides several targets hadling the creation of of RPM packages
# and documentation for publishing flowd-go

# The directory on which to place the build files and resulting RPMs for easier access
RPM_DIR = rpms

# Markdown-formatted manpage to parse with pandoc.
DOC_FILE = $(BIN_NAME).1.md

SPECFILE             = $(shell find $(RPM_DIR) -type f -name *.spec)
SPECFILE_NAME        = $(shell awk '$$1 == "Name:"     { print $$2 }' $(SPECFILE))
SPECFILE_VERSION     = $(shell awk '$$1 == "Version:"  { print $$2 }' $(SPECFILE))
SPECFILE_RELEASE     = $(shell awk '$$1 == "Release:"  { print $$2 }' $(SPECFILE))
DIST                ?= $(shell rpm --eval %{dist})

# Path of the buildroot created with rpmdev-setuptree. In order to create
# it, install the necessary tools as explained on the main README.md and
# then simply run rpmdev-setuptree. The build tree will be created by
# default on ${HOME}/rpmbuild, hence the definition of this variable.
RPM_BUILDROOT = $(shell echo ${HOME})/rpmbuild

rpm-dbg:
	@echo "        SPECFILE: $(SPECFILE)"
	@echo "   SPECFILE_NAME: $(SPECFILE_NAME)"
	@echo "SPECFILE_VERSION: $(SPECFILE_VERSION)"
	@echo "SPECFILE_RELEASE: $(SPECFILE_RELEASE)"
	@echo "            DIST: $(DIST)"
	@echo "         VERSION: $(VERSION)"

# Be sure to check https://rpm-packaging-guide.github.io for more info!
rpm-old: doc build $(RPM_BUILDROOT)
	@echo "Building RPM with buildroot $(RPM_BUILDROOT)"
	@echo "Copying artifacts to the RPM buildroot..."
	@cp $(BIN_DIR)/$(BIN_NAME)                $(RPM_BUILDROOT)/SOURCES/$(BIN_NAME)
	@cp $(RPM_DIR)/conf.json                  $(RPM_BUILDROOT)/SOURCES/$(BIN_NAME).json
	@cp $(RPM_DIR)/$(BIN_NAME).service        $(RPM_BUILDROOT)/SOURCES/$(BIN_NAME).service
	@cp $(RPM_DIR)/$(basename $(DOC_FILE)).gz $(RPM_BUILDROOT)/SOURCES/$(basename $(DOC_FILE)).gz
	@echo "Building the RPM..."
	@rpmbuild -bb $(RPM_DIR)/$(BIN_NAME).spec
	@echo "Copying the RPM to $(RPM_DIR)"
	@cp $(RPM_BUILDROOT)/RPMS/x86_64/flowd-go-$(VERSION)-1.x86_64.rpm $(RPM_DIR)

# If the devtree doesn't exist (i.e. we're running in the CI container) simply create it
$(RPM_BUILDROOT):
	@echo "Creating RPM build tree..."
	rpmdev-setuptree

# Files to include in the SRPM
FILES := backends cmd enrichment plugins settings stun types const.go go.mod go.sum Makefile $(addprefix rpms/, conf.json flowd-go.1.md flowd-go.service)

rpm-dist: rpm-clean
	echo "$(FILES)"
	mkdir $(PWD)/dist $(PWD)/build
	cp ${SPECFILE} dist/
	mkdir -p dist/${SPECFILE_NAME}-${SPECFILE_VERSION}
	cp -pr ${FILES} dist/${SPECFILE_NAME}-${SPECFILE_VERSION}/.
	git rev-parse --short HEAD > dist/${SPECFILE_NAME}-${SPECFILE_VERSION}/commit
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > dist/${SPECFILE_NAME}-${SPECFILE_VERSION}/backends/ebpf/progs/vmlinux.h
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > dist/${SPECFILE_NAME}-${SPECFILE_VERSION}/enrichment/skops/progs/vmlinux.h
	find dist -type d -name .git       | xargs -i rm -rf {}
	find dist -type d -name '*sample*' | xargs -i rm -rf {}
	find dist -type f -name '*.gdb'    | xargs -i rm -rf {}
	find dist -type f -name '*.pcapng' | xargs -i rm -rf {}
	find dist -type f -name '*.o'      | xargs -i rm -rf {}
	find dist -type f -name 'test'     | xargs -i rm -rf {}
	cd dist ; tar cfz ${SPECFILE_NAME}-${SPECFILE_VERSION}.tar.gz ${SPECFILE_NAME}-${SPECFILE_VERSION}

rpm-src: rpm-dist
	rpmbuild -bs --define "dist $(DIST)" --define "_topdir $(PWD)/build" --define '_sourcedir $(PWD)/dist' $(SPECFILE)

rpm-bin: rpm-dist
	rpmbuild -bb --define "dist $(DIST)" --define "_topdir $(PWD)/build" --define '_sourcedir $(PWD)/dist' $(SPECFILE)

rpm-mock: rpm-src
	mock -r alma+epel-9-x86_64 --enable-network build/SRPMS/flowd-go-$(SPECFILE_VERSION)-$(SPECFILE_RELEASE).src.rpm

doc: $(RPM_DIR)/$(DOC_FILE)
	@echo "Building documentation"
	@pandoc --standalone --to man $(RPM_DIR)/$(DOC_FILE) | gzip > $(RPM_DIR)/$(basename $(DOC_FILE)).gz

rpm-clean:
	rm -rf build dist
