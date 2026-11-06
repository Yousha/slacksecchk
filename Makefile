MAKEFLAGS += --no-print-directory

CC = gcc
CFLAGS ?= -Wall -Wextra -O2 -std=c99
DEBUG_CFLAGS ?= -Wall -Wextra -g -std=c99
CPPFLAGS ?=
LDFLAGS ?=

TARGET = artifacts/slacksecchk
OBJS = artifacts/slacksecchk.o artifacts/rules.o

all: $(TARGET)

$(TARGET): $(OBJS)
	@echo "Linking executable..."
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS)

artifacts/%.o: src/%.c src/rules.h
	@mkdir -p artifacts
	@echo "Compiling $<..."
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

debug:
	$(MAKE) clean
	$(MAKE) CFLAGS="$(DEBUG_CFLAGS)" all

clean:
	@echo "Cleaning..."
	rm -rf artifacts
	rm -f ./test_output.txt

test: $(TARGET)
	@echo "Running tests..."
	bash ./test.sh

install: $(TARGET)
	@echo "Installing binary..."
	install -D -m 0755 $(TARGET) /usr/local/bin/slacksecchk

uninstall:
	@echo "Uninstalling binary..."
	rm -f /usr/local/bin/slacksecchk

checksums:
	find . -type f -not -path './.git/*' -not -path './artifacts/*' -not -name 'Checksums.sha256' -print0 | sort -z | xargs -0 sha256sum > Checksums.sha256

usage:
	@echo "Usage: make [all | clean | test | checksums | install | uninstall | debug]"

.PHONY: all clean test checksums install uninstall debug usage
