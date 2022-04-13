CC=gcc
CFLAGS=-Wall -Wextra -march=native -mtune=native -std=gnu99 -pedantic -finline-functions -O3 -flto
SRC=alyal.c
BIN=alyal

.PHONY: all
all: Makefile $(SRC) $(BIN)
	$(CC) $(CFLAGS) $(SRC)  -o $(BIN)

.PHONY: clean
clean:
	rm -rf $(BIN)
