TLSCF:=$(shell libgnutls-config --cflags)
TLSLF:=$(shell libgnutls-config --libs)

CFLAGS=-O2 -Iinclude -g -Wall -W -Wno-parentheses -Wstrict-prototypes -Wmissing-prototypes -Wundef -Wredundant-decls -std=gnu99 $(TLSCF)
LDFLAGS=$(TLSLF)

all: submitd

submitd: submitd.o lib/libucw.a lib/libsh.a
submitd.o: submitd.c

certs:
	certtool --generate-privkey --outfile ca-key.pem
	certtool --generate-privkey --outfile ca-key.pem --template ca-cert.tpl
	certtool --generate-privkey --outfile server-key.pem
	certtool --generate-request --load-privkey server-key.pem --outfile server-req.pem --template server-cert.tpl
	certtool --generate-certificate --load-request server-req.pem --outfile server-cert.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem --template server-cert.tpl
	# Beware of serial numbers

clean:
	rm -f `find . -name "*~" -or -name "*.[oa]" -or -name "\#*\#" -or -name TAGS -or -name core -or -name .depend -or -name .#*`
	rm -f submitd
