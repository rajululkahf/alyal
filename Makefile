CC=gcc
CFLAGS=-Wall -Wextra -march=native -mtune=native -std=gnu99 -pedantic -finline-functions -O3 -flto
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
	dd bs=1MB count=100 if=/dev/zero of=$(TST)/file.txt
	###############################
	# testing with raw 128-bit keys
	###############################
	echo 2233f17a53d912bb67efe39e564f4dd2 | ./alyal enc \
							$(TST)/file.txt \
							$(TST)/file.enc
	echo b507432fddf13a95e2b0ab7a738ff3cb | ./alyal enc \
							$(TST)/file.txt \
							$(TST)/file.enc2
	echo 78e3fd29eef1ff0e1afc46d75b44ed1a | ./alyal enc \
							$(TST)/file.txt \
							$(TST)/file.enc3
	echo 2233f17a53d912bb67efe39e564f4dd2 | ./alyal dec \
							$(TST)/file.enc \
							$(TST)/file.enc.txt
	echo b507432fddf13a95e2b0ab7a738ff3cb | ./alyal dec \
							$(TST)/file.enc2 \
							$(TST)/file.enc.txt2
	echo 78e3fd29eef1ff0e1afc46d75b44ed1a | ./alyal dec \
							$(TST)/file.enc3 \
							$(TST)/file.enc.txt3
	$(DIF) $(TST)/file.txt $(TST)/file.enc.txt
	$(DIF) $(TST)/file.txt $(TST)/file.enc.txt2
	$(DIF) $(TST)/file.txt $(TST)/file.enc.txt3
	###############################
	# tests completed successfully
	###############################
