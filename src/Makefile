CC=gcc
CFLAGS=-g -Wall -pthread
LDLIBS=-lpthread

all: endoor

endoor: log.o endoor.o pcap.o bridge.o protoaddr.o tun.o state.o

install:
	install endoor /usr/local/bin

clean:
	rm -f *.o endoor

.PHONY: clean
