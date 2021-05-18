PRJ=ipk-sniffer
CC=gcc
PROGS=$(PRJ)
CFLAGS= -Wall -Werror

all:
	$(CC) $(PRJ).c $(CFLAGS) -o $(PRJ) -lpcap
