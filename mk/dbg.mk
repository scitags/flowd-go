.PHONY: dbg
dbg:
	@echo "  VERSION: $(VERSION)"
	@echo "   COMMIT: $(COMMIT)"
	@echo "     EBPF: '$(EBPF)'"
	@echo "   CFLAGS: $(CFLAGS)"
	@echo "ENV_FLAGS: $(ENV_FLAGS)"
