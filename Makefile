# Makefile for mo-eval and related utilities
# (c) 2007 Martin Mares <mj@ucw.cz>

VERSION=1.0.1
#DEBUG=-ggdb
CFLAGS=-O2 -Wall -W -Wno-parentheses -Wstrict-prototypes -Wmissing-prototypes -Wundef -Wredundant-decls -Winline $(DEBUG) -std=gnu99

CC=gcc-4.1.1

# Comment out if you are using a recent gcc
CFLAGS+=-Wno-pointer-sign -Wdisabled-optimization -Wno-missing-field-initializers

# Comment out if you do not wish to build remote submit utilities
#SUBMIT=submit
#LIBUCW:=$(shell cd ../holmes-libs-3.12/run && pwd)

export LIBUCW CFLAGS LDFLAGS DEBUG

all: bin/box bin/iwrapper bin/md5crypt bin/pedant $(SUBMIT)

bin/%: src/%.o
	$(CC) $(LDFLAGS) -o $@ $^

bin/box: src/box.o
bin/iwrapper: src/iwrapper.o
bin/md5crypt: src/md5crypt.o src/md5.o
bin/pedant: src/pedant.o

submit:

clean::
	rm -f `find . -name "*~" -or -name "*.[oa]" -or -name "\#*\#" -or -name TAGS -or -name core`
	rm -f bin/box bin/iwrapper bin/md5crypt bin/pedant

distclean: clean

ifdef SUBMIT

submit:
	$(MAKE) -C submit

clean::
	$(MAKE) -C submit clean

endif

.PHONY: all clean distclean submit
