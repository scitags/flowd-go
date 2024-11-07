# This Makefile provides several targets hadling the creation of of RPM packages
# and documentation for publishing glowd
rpm: linux doc
	@echo "Building RPM with buildroot $(RPM_BUILDROOT)"
	@echo "Copying artifacts to the RPM buildroot..."
	@cp $(BIN_DIR)/$(BIN_NAME)     $(RPM_BUILDROOT)/SOURCES/$(BIN_NAME)
	@cp conf.json                  $(RPM_BUILDROOT)/SOURCES/$(BIN_NAME).json
	@cp $(BIN_NAME).service        $(RPM_BUILDROOT)/SOURCES/$(BIN_NAME).service
	@cp $(basename $(DOC_FILE)).gz $(RPM_BUILDROOT)/SOURCES/$(basename $(DOC_FILE)).gz
	@echo "Building the RPM..."
	@rpmbuild -bb $(RPM_BUILDROOT)/SPECS/wlcg-site-snmp.spec

doc: $(DOC_FILE)
	@echo "Building documentation"
	@pandoc --standalone --to man $(DOC_FILE) | gzip > $(basename $(DOC_FILE)).gz
