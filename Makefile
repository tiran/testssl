CC=gcc
OPENSSL=$(abspath ../multissl/openssl/1.1.1-pre6)
CFLAGS=-I$(OPENSSL)/include
LDFLAGS=-L$(OPENSSL)/lib -Wl,-rpath=$(OPENSSL)/lib -lcrypto -lssl

all: testssl
	./testssl

%.o: %.c 
	$(CC) $(CFLAGS) -c -o $@ $< 

testssl: testssl.o
	$(CC) $(LDFLAGS) -o $@ $< 

