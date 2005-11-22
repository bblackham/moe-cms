VERSION=1.0.1
#DEBUG=-ggdb
CFLAGS=-O2 -Wall -W -Wno-parentheses -Wstrict-prototypes -Wmissing-prototypes -Winline $(DEBUG)

all: bin/box bin/iwrapper bin/md5crypt bin/pedant

bin/%: src/%.o
	$(CC) $(LDFLAGS) -o $@ $^

bin/box: src/box.o
bin/iwrapper: src/iwrapper.o
bin/md5crypt: src/md5crypt.o src/md5.o
bin/pedant: src/pedant.o

clean:
	rm -f `find . -name "*~" -or -name "*.[oa]" -or -name "\#*\#" -or -name TAGS -or -name core`
	rm -f bin/box bin/iwrapper bin/md5crypt

distclean: clean

.PHONY: all clean distclean
