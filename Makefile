CFLAGS = -Wall -Wextra -Wno-missing-field-initializers -Wno-missing-braces -O0 -g -DM5_USER_PROP_SIZE=2

CC = gcc

all: test

test: src/m5.c src/m5_test.c src/m5.h
	mkdir -p bin
	$(CC) $(CFLAGS) -Isrc src/m5_test.c -o bin/m5_test

clean:
	rm -f bin/*
