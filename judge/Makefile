#CC=gcc-4.1.1
CFLAGS=-O2 -Wall -W -Wno-parentheses -Wstrict-prototypes -Wmissing-prototypes -Wundef -Wredundant-decls -Winline $(DEBUG) -std=gnu99
CFLAGS+=-Wno-pointer-sign -Wdisabled-optimization -Wno-missing-field-initializers

all: test-io test-tok judge-tok judge-shuff filter-cmt

JLIB=utils.o io.o token.o

test-io: test-io.o $(JLIB)
test-tok: test-tok.o $(JLIB)
judge-tok: judge-tok.o $(JLIB)
judge-tok: LDLIBS+=-lm
judge-shuff: judge-shuff.o $(JLIB)
filter-cmt: filter-cmt.o $(JLIB)

tests: $(addsuffix .test,io token filter-cmt judge-tok)
io.test: test-io
token.test: test-tok
filter-cmt.test: filter-cmt
judge-tok.test: judge-tok

%.test: %.t tester
	./tester $<

clean::
	rm -f `find . -name "*~" -or -name "*.[oa]" -or -name "\#*\#" -or -name TAGS -or -name core`
	rm -f test-io test-tok judge-tok judge-shuff filter-cmt
	rm -rf tmp

.PHONY: all clean distclean
