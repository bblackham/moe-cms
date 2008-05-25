#!/bin/bash
# Create home directories of all contestants.

[ -f cf/mop ] || { echo "Missing config file, check cwd." ; exit 1 ; }
set -e
. cf/mop

H=`pwd`
cd $MO_ROOT
rm -rf users
mkdir users
cd users

for a in `cd $H && bin/mo-get-users` ; do
	echo "Creating $a"
	mkdir $a $a/$a
	chown root.$a $a
	chmod 750 $a
	cp -a `find $H/template -mindepth 1 -maxdepth 1` $a/$a/

	if [ -n "$REMOTE_SUBMIT" ] ; then
		M=$a/$a/.mo
		mkdir $M
		cp $H/certs/$a-cert.pem $M/cert.pem
		cp $H/certs/$a-key.pem $M/key.pem
		chmod 600 $M/key.pem
		cp $H/certs/ca-cert.pem $M/
	fi

	chown $a.$a $a/$a -R
	chmod 700 $a/$a
done
