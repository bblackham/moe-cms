#DEBUG=-ggdb
CFLAGS=-O2 -Wall -W -Wno-parentheses -Wstrict-prototypes -Wmissing-prototypes -Winline $(DEBUG)

all: bin/box bin/iwrapper bin/md5crypt

bin/%: src/%.o
	$(CC) $(LDFLAGS) -o $@ $^

bin/box: src/box.o
bin/iwrapper: src/iwrapper.o
bin/md5crypt: src/md5crypt.o src/md5.o

clean:
	rm -f `find . -name "*~" -or -name "*.[oa]" -or -name "\#*\#" -or -name TAGS -or -name core`
	rm -f bin/box bin/iwrapper bin/md5crypt
