# Makefile for MO-P contest environment
# (c) 2008 Martin Mares <mj@ucw.cz>

DIRS+=mop/eval
PROGS+=$(addprefix $(o)/mop/eval/,\
	mo-ev-all mo-ev-inc mo-get-users \
	mo-score mo-report)

$(o)/mop/eval/mo-ev-all: mop/eval/mo-ev-all.sh
$(o)/mop/eval/mo-ev-inc: mop/eval/mo-ev-inc.sh
$(o)/mop/eval/mo-get-users: mop/eval/mo-get-users.sh
$(o)/mop/eval/mo-report: mop/eval/mo-report.sh
$(o)/mop/eval/mo-score: mop/eval/mo-score.sh
