ELFUTILS_VERSION := 0.193
LIBZSTD_VERSION := 1.5.5
NPROC := 4

.PHONY: deps
deps: deps-libelf deps-libzstd deps-rpm

.PHONY: deps-rpm
deps-rpm:
	@echo "dnf install -y --enablerepo=crb glibc-static libbpf-static zlib-static"

.PHONY: deps-dir
deps-dir:
	mkdir -p deps

.PHONY: deps-libelf
deps-libelf: deps-dir
	cd deps; curl -s -LO https://sourceware.org/elfutils/ftp/$(ELFUTILS_VERSION)/elfutils-$(ELFUTILS_VERSION).tar.bz2
	cd deps; tar -xjf elfutils*.tar.bz2
	cd deps/elfutils-$(ELFUTILS_VERSION); ./configure
	cd deps/elfutils-$(ELFUTILS_VERSION); make -j$(NPROC)

.PHONY: deps-libzstd
deps-libzstd: deps-dir
	cd deps; curl -s -LO https://github.com/facebook/zstd/releases/download/v$(LIBZSTD_VERSION)/zstd-$(LIBZSTD_VERSION).tar.gz
	cd deps; tar -xzf zstd*.tar.gz
	cd deps/zstd-$(LIBZSTD_VERSION); make -j$(NPROC)

.PHONY: deps-clean
deps-clean:
	@rm -rf deps
