# Makefile for MO-P contest environment
# (c) 2008 Martin Mares <mj@ucw.cz>

DIRS+=mop
PROGS+=$(addprefix $(o)/mop/,md5crypt)

$(o)/mop/md5crypt: $(o)/mop/md5crypt.o $(LIBUCW)

CONFIGS+=mop
run/cf/mop: $(o)/mop/mop.cf
