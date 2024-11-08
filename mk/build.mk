# This Makefile provides several targets hadling the creation of of RPM packages
# and documentation for publishing glowd

# Markdown-formatted manpage to parse with pandoc.
DOC_FILE = $(BIN_NAME).1.md

# Path of the buildroot created with rpmdev-setuptree. In order to create
# it, install the necessary tools as explained on the main README.md and
# then simply run rpmdev-setuptree. The build tree will be created by
# default on ${HOME}/rpmbuild, hence the definition of this variable.
RPM_BUILDROOT = $(shell echo ${HOME})/rpmbuild

# The directory on which to place the resulting RPM for easier access
RPM_OUTPUT_DIR = rpms

# Be sure to check https://rpm-packaging-guide.github.io for more info!
rpm: doc build
	@echo "Building RPM with buildroot $(RPM_BUILDROOT)"
	@echo "Copying artifacts to the RPM buildroot..."
	@cp $(BIN_DIR)/$(BIN_NAME)     $(RPM_BUILDROOT)/SOURCES/$(BIN_NAME)
	@cp cmd/conf.json              $(RPM_BUILDROOT)/SOURCES/$(BIN_NAME).json
	@cp $(BIN_NAME).service        $(RPM_BUILDROOT)/SOURCES/$(BIN_NAME).service
	@cp $(basename $(DOC_FILE)).gz $(RPM_BUILDROOT)/SOURCES/$(basename $(DOC_FILE)).gz
	@echo "Building the RPM..."
	@rpmbuild -bb $(BIN_NAME).spec
	@echo "Copying the RPM to $(RPM_OUTPUT_DIR)"
	@mkdir -p $(RPM_OUTPUT_DIR)
	@cp $(RPM_BUILDROOT)/RPMS/x86_64/glowd-1.0-1.x86_64.rpm $(RPM_OUTPUT_DIR)

doc: $(DOC_FILE)
	@echo "Building documentation"
	@pandoc --standalone --to man $(DOC_FILE) | gzip > $(basename $(DOC_FILE)).gz
