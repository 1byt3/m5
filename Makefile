CFLAGS = -Wall -Wextra -Werror -Wno-missing-field-initializers -Wno-missing-braces -O0 -g

TARGET = bin/test_m5

all: $(TARGET)

checkpatch:
	perl ./checkpatch.pl --no-tree -f src/* --ignore BRACES,CONST_STRUCT

$(TARGET): src/m5.c src/test_m5.c src/m5.h
	mkdir -p bin
	$(CC) $(CFLAGS) -Isrc src/test_m5.c -o $(TARGET)

test: $(TARGET)
	valgrind -q --leak-check=full --error-exitcode=1 $(TARGET) || exit 1;

clean:
	rm -f bin/*
