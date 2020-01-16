
#add source paths to vpath
VPATH = $(dir)

APP_SOURCES := ./

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
    OPENSSL := /usr/lib/ssl/
    LDFLAGS += -L/usr/lib/ssl/
endif
ifeq ($(UNAME_S),Darwin)
    OPENSSL := /usr/local/opt/openssl/include/
    LDFLAGS += -L/usr/local/opt/openssl/lib/
endif


SRC += main.c
SRC += printer.c
SRC += commander.c
SRC += ../Crypto.c

CFLAGS += -Wall -std=c99

CFLAGS += 	-I$(APP_SOURCES)\
			-I$(OPENSSL)\

CC = gcc
TARGET = crypto-tool

all: $(TARGET)


#  Compiling sll src files
$(SRC):
	$(CC) $(CFLAGS) -g $@


# Linking all object files
$(TARGET): $(SRC:.c=.o)
	$(CC) $(LDFLAGS) -g $^ -o $(TARGET) -lssl -lcrypto -lm

clean:
	rm -f $(TARGET) *.o *~

docker_build: clean
	docker run -it --rm -v"$(PWD):/opt/crypto-c" -w /opt/crypto-c  swift:4.0 make
