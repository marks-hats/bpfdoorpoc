CFLAGS=-Os -Wall # -fsanitize=address,undefined -fno-omit-frame-pointer -fno-optimize-sibling-calls

.phony: all

all: bin bin/client bin/bpfdoorpoc

bin:
	-mkdir bin

bin/client: client.c
	$(CC) $(CFLAGS) -o $@ $<

bin/bpfdoorpoc: bpfdoorpoc.c
	$(CC) $(CFLAGS) -o $@ $<
	sudo setcap cap_net_raw+eip $@

