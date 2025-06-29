# Makefile for CSE156 Final Project - Client-to-Server HTTP Proxy 
CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread -lssl -lcrypto
SRC = src/myproxy.c
BIN = bin/myproxy

all: $(BIN)

$(BIN): $(SRC)
	mkdir -p bin
	$(CC) $(CFLAGS) -o $(BIN) $(SRC)

clean:
	rm -rf bin/*.o $(BIN)

.PHONY: all clean
