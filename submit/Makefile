# Makefile for MO-Eval submitter
# (c) 2008 Martin Mares <mj@ucw.cz>

TLSCF:=$(shell libgnutls-config --cflags)
TLSLF:=$(shell libgnutls-config --libs)
GCRCF:=$(shell libgcrypt-config --cflags)

DIRS+=submit
SDIR=$(o)/submit

### The submit server ###

PROGS+=$(addprefix $(SDIR)/,submitd privkey connect)

$(SHERLOCK_PERL_MODS): PERL_MODULE_DIR=MO

$(SDIR)/submitd: $(addprefix $(SDIR)/,submitd.o commands.o tasks.o) $(LIBUCW) $(LIBSH)
$(SDIR)/submitd: CFLAGS+=$(TLSCF) $(GCRCF)
$(SDIR)/submitd: LIBS+=$(TLSLF)

$(SDIR)/connect: $(SDIR)/connect.o $(LIBUCW)
$(SDIR)/connect: CFLAGS+=$(TLSCF) $(GCRCF)
$(SDIR)/connect: LIBS+=$(TLSLF)

$(SDIR)/privkey: $(SDIR)/privkey.o $(LIBUCW)
$(SDIR)/privkey: CFLAGS+=$(TLSCF) $(GCRCF)
$(SDIR)/privkey: LIBS+=$(TLSLF)

### Submitter perl module ###

EXTRA_RUNDIRS+=lib/perl5/MO
SUBMIT_PERL_MODS=$(o)/submit/Submit.pm
PROGS+=$(SUBMIT_PERL_MODS)

### The submit client and utilities ###

PROGS+=$(addprefix $(SDIR)/,contest create-certs remote-status remote-submit show-submits)

$(SDIR)/contest: $(s)/submit/contest.pl
$(SDIR)/create-certs: $(s)/submit/create-certs.sh
$(SDIR)/remote-status: $(s)/submit/remote-status.pl
$(SDIR)/remote-submit: $(s)/submit/remote-submit.pl
$(SDIR)/show-submits: $(s)/submit/show-submits.pl

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
