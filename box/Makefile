# Makefile for MO-Eval sandbox
# (c) 2008 Martin Mares <mj@ucw.cz>

DIRS+=box
PROGS+=$(o)/box/box

$(o)/box/box: $(o)/box/box.o
$(o)/box/box.o: $(o)/box/syscall-table.h

$(o)/box/syscall-table.h: $(s)/box/mk-syscall-table
	sh $^ >$@
