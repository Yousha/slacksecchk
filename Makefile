# Compiler and flags.
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
LDFLAGS =
SRCS = src/slacksecchk.c src/rules.c
OBJS = $(SRCS:.c=.o)
TARGET = slacksecchk

# Default target.
all: $(TARGET)

# Link object files into the final executable.
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

# Compile source files into object files.
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Cleanup compiled files.
clean:
	rm -f $(OBJS) $(TARGET)

# Run the test script.
test: $(TARGET)
	./test.sh

# Install the binary (optional).
install: $(TARGET)
	mkdir -p /usr/local/bin
	cp $(TARGET) /usr/local/bin/
	chmod +x /usr/local/bin/$(TARGET)

# Uninstall the binary (optional).
uninstall:
	rm -f /usr/local/bin/$(TARGET)

.PHONY: all clean test install uninstall
