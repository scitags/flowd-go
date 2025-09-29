CC := clang

bin/tcp_ca: tcp_ca.c
	@mkdir -p bin
	$(CC) -o $@ $^

.PHONY: listener
listener:
	nc -l -k 8888

.PHONY: clean
clean:
	@rm -rf bin
