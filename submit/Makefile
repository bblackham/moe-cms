TLSCF:=$(shell libgnutls-config --cflags)
TLSLF:=$(shell libgnutls-config --libs)
GCRCF:=$(shell libgcrypt-config --cflags)

CFLAGS=-O2 -Iinclude -g -Wall -W -Wno-parentheses -Wstrict-prototypes -Wmissing-prototypes -Wundef -Wredundant-decls -std=gnu99 $(TLSCF) $(GCRCF)
LDFLAGS=$(TLSLF)

#CC=gcc-4.1.1
CFLAGS+=-Wno-pointer-sign -Wdisabled-optimization -Wno-missing-field-initializers
LDFLAGS+=-lpthread	# FIXME: Use libucw without threads

all: submitd privkey

submitd: submitd.o commands.o tasks.o lib/libsh.a lib/libucw.a
submitd.o: submitd.c submitd.h
commands.o: commands.c submitd.h
tasks.o: tasks.c submitd.h
connect: connect.o lib/libucw.a
connect.o: connect.c
privkey: privkey.o lib/libucw.a
privkey.o: privkey.c

certs:
	certtool --generate-privkey --outfile ca-key.pem
	certtool --generate-privkey --outfile ca-key.pem --template ca-cert.tpl
	certtool --generate-privkey --outfile server-key.pem
	certtool --generate-request --load-privkey server-key.pem --outfile server-req.pem --template server-cert.tpl
	certtool --generate-certificate --load-request server-req.pem --outfile server-cert.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem --template server-cert.tpl
	certtool --generate-privkey --outfile client-key.pem
	certtool --generate-request --load-privkey client-key.pem --outfile client-req.pem --template client-cert.tpl
	certtool --generate-certificate --load-request client-req.pem --outfile client-cert.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem --template client-cert.tpl
	# Beware of serial numbers

clean:
	rm -f `find . -name "*~" -or -name "*.[oa]" -or -name "\#*\#" -or -name TAGS -or -name core -or -name .depend -or -name .#*`
	rm -f submitd connect privkey
