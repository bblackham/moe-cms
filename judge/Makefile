# Makefile for MO-Eval judges
# (c) 2008 Martin Mares <mj@ucw.cz>

DIRS+=judge
JDIR=$(o)/judge
PROGS+=$(addprefix $(JDIR)/,test-io test-tok judge-tok judge-shuff filter-cmt)
JLIB=$(addprefix $(o)/judge/,utils.o io.o token.o)

$(JDIR)/test-io: $(JDIR)/test-io.o $(JLIB)
$(JDIR)/test-tok: $(JDIR)/test-tok.o $(JLIB)
$(JDIR)/judge-tok: $(JDIR)/judge-tok.o $(JLIB)
$(JDIR)/judge-tok: LDLIBS+=-lm
$(JDIR)/judge-shuff: $(JDIR)/judge-shuff.o $(JLIB)
$(JDIR)/filter-cmt: $(JDIR)/filter-cmt.o $(JLIB)

TESTS+=$(addprefix $(JDIR)/,io.test token.test judge-tok.test filter-cmt.test)
