CC = gcc
CFLAGS = -Wall -Wextra -O2
SRC_DIR = src
BIN_DIR = bin

CLIENT_SRC = $(SRC_DIR)/myclient.c
SERVER_SRC = $(SRC_DIR)/myserver.c
CLIENT_BIN = $(BIN_DIR)/myclient
SERVER_BIN = $(BIN_DIR)/myserver

.PHONY: all clean

all: $(CLIENT_BIN) $(SERVER_BIN)

$(BIN_DIR)/myclient: $(CLIENT_SRC)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BIN_DIR)/myserver: $(SERVER_SRC)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(BIN_DIR)/myclient $(BIN_DIR)/myserver

