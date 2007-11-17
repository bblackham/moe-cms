CC=gcc-4.1.1
CFLAGS=-O2 -Wall -W -Wno-parentheses -Wstrict-prototypes -Wmissing-prototypes -Wundef -Wredundant-decls -Winline $(DEBUG) -std=gnu99
CFLAGS+=-Wno-pointer-sign -Wdisabled-optimization -Wno-missing-field-initializers

all: test-io test-tok

JLIB=utils.o io.o token.o

test-io: test-io.o $(JLIB)
test-tok: test-tok.o $(JLIB)

clean::
	rm -f `find . -name "*~" -or -name "*.[oa]" -or -name "\#*\#" -or -name TAGS -or -name core`
	rm -f test-io test-tok

.PHONY: all clean distclean
