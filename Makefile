CC=gcc
CFLAGS=-Wall -Wextra -march=native -mtune=native -std=gnu99 -pedantic -finline-functions -O3 -flto -g
SRC=alyal.c
BIN=alyal
TST=tests
DIF=diff

.PHONY: all
all: Makefile $(SRC) $(BIN)
	$(CC) $(CFLAGS) $(SRC) -o $(BIN)

.PHONY: clean
clean:
	rm -rf $(BIN) $(TST)

.PHONY: test
test: $(BIN)
	###############################
	# preparing tests
	###############################
	mkdir -p $(TST)
	dd bs=1MB count=100 if=/dev/random of=$(TST)/file.txt
	###############################
	# testing with raw 128-bit keys
	###############################
	echo 2233f17a53d912bb67efe39e564f4dd2 | ./alyal enc \
							$(TST)/file.txt \
							$(TST)/file.enc
	echo 2233f17a53d912bb67efe39e564f4dd2 | ./alyal dec \
							$(TST)/file.enc \
							$(TST)/file.enc.txt
	$(DIF) $(TST)/file.txt $(TST)/file.enc.txt
	###############################
	# testing with key derivation
	###############################
	echo "some password!" | ./alyal dkenc \
					$(TST)/file.txt \
					$(TST)/file.dkenc
	echo "some password!" | ./alyal dkdec \
					$(TST)/file.dkenc \
					$(TST)/file.dkenc.txt
	$(DIF) $(TST)/file.txt $(TST)/file.dkenc.txt
