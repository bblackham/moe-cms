#!/bin/bash

[ -f config ] || { echo "Missing config file, check cwd." ; exit 1 ; }
set -e
. config

echo "Populating $MO_ROOT/public"
H=`pwd`
cd $MO_ROOT/public
rm -rf bin lib

sed '/^\(TEST_USER\|MO_ROOT\)=/s/^/#/' <$H/config >config

mkdir bin
cp -a $H/public/[a-z]* bin/
for a in `cat $H/public/COPY` ; do
	cp -a $H/$a bin/
done

if [ -n "$REMOTE_SUBMIT" ] ; then
	cp $H/submit/{contest,remote-submit,remote-status} bin/
	mkdir lib
	cp -a $H/submit/lib .
fi

mkdir -p problems

if [ `id -u` == 0 ] ; then
	chown -R $EVAL_USER.$EVAL_GROUP .
	chmod 755 .
fi
