# Makefile for MO-P contest environment
# (c) 2008 Martin Mares <mj@ucw.cz>

DIRS+=mop/admin
PROGS+=$(addprefix $(o)/mop/admin/,\
	md5crypt \
	mo-backup mo-back-status \
	mo-install mo-create-contestants mo-create-eval mo-create-logins \
	mo-create-packages mo-create-public mo-create-submit mo-create-testusers \
	mo-grab mo-back-grab mo-grab-remote \
	mo-push-certs mo-push-feedback)

$(o)/mop/admin/md5crypt: $(o)/mop/admin/md5crypt.o $(LIBUCW)

$(o)/mop/admin/mo-back-grab: mop/admin/mo-back-grab.sh
$(o)/mop/admin/mo-back-status: mop/admin/mo-back-status.sh
$(o)/mop/admin/mo-backup: mop/admin/mo-backup.sh
$(o)/mop/admin/mo-create-contestants: mop/admin/mo-create-contestants.sh
$(o)/mop/admin/mo-create-eval: mop/admin/mo-create-eval.sh
$(o)/mop/admin/mo-create-logins: mop/admin/mo-create-logins.sh
$(o)/mop/admin/mo-create-packages: mop/admin/mo-create-packages.sh
$(o)/mop/admin/mo-create-public: mop/admin/mo-create-public.sh
$(o)/mop/admin/mo-create-submit: mop/admin/mo-create-submit.sh
$(o)/mop/admin/mo-create-testusers: mop/admin/mo-create-testusers.sh
$(o)/mop/admin/mo-grab-remote: mop/admin/mo-grab-remote.sh
$(o)/mop/admin/mo-grab: mop/admin/mo-grab.sh
$(o)/mop/admin/mo-install: mop/admin/mo-install.sh
$(o)/mop/admin/mo-push-certs: mop/admin/mo-push-certs.sh
$(o)/mop/admin/mo-push-feedback: mop/admin/mo-push-feedback.sh
