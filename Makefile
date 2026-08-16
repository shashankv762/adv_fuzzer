CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -O2 -D_POSIX_C_SOURCE=200809L -I./include

TARGET = acfp_fuzzer
DEMO_TARGET = demo_vulnerable

SRCS = src/core.c src/corpus.c src/triage.c src/main.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean test

all: $(TARGET) $(DEMO_TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) -lm

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(DEMO_TARGET): targets/demo_vulnerable.c
	$(CC) -g -O0 -o $@ $<

test: $(TARGET) $(DEMO_TARGET)
	@echo "Build successful"
	./$(DEMO_TARGET) || true

clean:
	rm -f $(TARGET) $(DEMO_TARGET) src/*.o
