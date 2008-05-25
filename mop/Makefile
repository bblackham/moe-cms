# Makefile for MO-P contest environment
# (c) 2008 Martin Mares <mj@ucw.cz>

DIRS+=mop

include mop/admin/Makefile
include mop/eval/Makefile
include mop/public/Makefile
include mop/score/Makefile

CONFIGS+=mop userlist
run/cf/mop: $(o)/mop/mop.cf
run/cf/userlist: $(o)/mop/userlist.cf
