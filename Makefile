MAKEFLAGS += --silent --no-print-directory

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
DEBUG_CFLAGS = -Wall -Wextra -g -std=c99
LDFLAGS =
TARGET = artifacts/slacksecchk
SRCS = src/slacksecchk.c src/rules.c
OBJS = artifacts/slacksecchk.o artifacts/rules.o

# Debug toggle
debug: CFLAGS = $(DEBUG_CFLAGS)
debug:
	@echo "Building in debug mode..."
	$(MAKE) all

all:
	@echo "Starting build..."
	$(MAKE) $(TARGET)

$(TARGET): $(OBJS)
	@echo "Linking executable..."
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

artifacts/slacksecchk.o: src/slacksecchk.c
	@echo "Compiling slacksecchk..."
	@mkdir -p artifacts
	$(CC) $(CFLAGS) -c $< -o $@

artifacts/rules.o: src/rules.c
	@echo "Compiling rules..."
	@mkdir -p artifacts
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "Cleaning..."
	rm -f ./test_output.txt
	rm -rf artifacts/*
	rm -rf artifacts

test: $(TARGET)
	@echo "Running tests..."
	chmod +x ./test.sh
	./test.sh

install: $(TARGET)
	@echo "Installing binary..."
	mkdir -p /usr/local/bin
	cp $(TARGET) /usr/local/bin/slacksecchk
	chmod +x /usr/local/bin/slacksecchk

uninstall:
	@echo "Uninstalling binary..."
	rm -f /usr/local/bin/slacksecchk

usage:
	@echo "Usage: make [all | clean | test | install | uninstall | debug]"

.PHONY: all clean test install uninstall debug usage
