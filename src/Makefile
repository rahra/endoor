CC=gcc
CFLAGS=-g -Wall -pthread
LDLIBS=-lpthread

all: rwpack

rwpack: log.o rwpack.o pcap.o bridge.o protoaddr.o tun.o state.o

clean:
	rm -f *.o rwpack

.PHONY: clean
