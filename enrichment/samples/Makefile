CC := clang

bin/tcp_ca: tcp_ca.c
	@mkdir -p bin
	$(CC) -o $@ $^

.PHONY: clean
clean:
	@rm -rf bin
