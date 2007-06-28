TLSCF:=$(shell libgnutls-config --cflags)
TLSLF:=$(shell libgnutls-config --libs)
GCRCF:=$(shell libgcrypt-config --cflags)

CFLAGS+=-I$(LIBUCW)/include $(TLSCF) $(GCRCF)
LDFLAGS+=$(TLSLF)
LDFLAGS+=-lpthread	# FIXME: Use libucw without threads

all: submitd privkey lib

submitd: submitd.o commands.o tasks.o $(LIBUCW)/lib/libsh.a $(LIBUCW)/lib/libucw.a
submitd.o: submitd.c submitd.h
commands.o: commands.c submitd.h
tasks.o: tasks.c submitd.h
connect: connect.o $(LIBUCW)/lib/libucw.a
connect.o: connect.c
privkey: privkey.o $(LIBUCW)/lib/libucw.a
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

lib: .lib-stamp lib/perl5/MO/Submit.pm lib/perl5/Sherlock/Object.pm

.lib-stamp:
	mkdir -p lib/perl5/{MO,Sherlock}
	touch .lib-stamp

lib/perl5/MO/Submit.pm: MO/Submit.pm
	cp $^ $@

lib/perl5/Sherlock/Object.pm: $(LIBUCW)/lib/perl5/Sherlock/Object.pm
	cp $^ $@

clean:
	rm -f `find . -name "*~" -or -name "*.[oa]" -or -name "\#*\#" -or -name TAGS -or -name core -or -name .depend -or -name .#*`
	rm -f submitd connect privkey
	rm -rf lib .lib-stamp

.PHONY: lib
