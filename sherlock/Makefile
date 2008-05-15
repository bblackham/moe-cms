# Makefile for the Sherlock Library (c) 2004--2007 Martin Mares <mj@ucw.cz>

DIRS+=sherlock

LIBSH_MODS= \
	object bucket buck2obj obj2buck obj-linear obj-format \
	attrset conf-parse

LIBSH_MOD_PATHS=$(addprefix $(o)/sherlock/,$(LIBSH_MODS))

$(o)/sherlock/libsh.a: $(addsuffix .o,$(LIBSH_MOD_PATHS))
$(o)/sherlock/libsh.so: $(addsuffix .oo,$(LIBSH_MOD_PATHS))
$(o)/sherlock/libsh.pc: $(LIBUCW)

include $(s)/sherlock/perl/Makefile
