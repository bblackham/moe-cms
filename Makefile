#DEBUG=-ggdb
CFLAGS=-O2 -Wall -W -Wno-parentheses -Wstrict-prototypes -Wmissing-prototypes -Winline $(DEBUG)

all: bin/box bin/iwrapper

bin/box: src/box.o
	$(CC) $(LDFLAGS) -o $@ $<

bin/iwrapper: src/iwrapper.o
	$(CC) $(LDFLAGS) -o $@ $<

clean:
	rm -f `find . -name "*~" -or -name "*.[oa]" -or -name "\#*\#" -or -name TAGS -or -name core`
	rm -f bin/box bin/iwrapper
