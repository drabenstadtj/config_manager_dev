CC = gcc
CFLAGS = -Wall -Wextra -O2 -g
LDFLAGS = -lssl -lcrypto -lcyaml  # Link OpenSSL and CYAML

SRC = key_generation.c parser.c  config_manager.c
OBJ = $(SRC:.c=.o)
DEPS = key_generation.h parser.h 

TARGET = config_manager

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
