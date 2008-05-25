#!/bin/sh
# A trivial script to back up contestants' home directories.

if [ -z "$1" ] ; then
	D=back/`date '+%H%M'`
else
	D=$1
fi
mkdir -p $D
for m in `seq 27 74` ; do
	m="ceoi$m"
	echo -n "$m: "
	mkdir $p $D/$m
	pushd $D/$m >/dev/null
	ssh root@$m 'cd /mo/users ; tar czf - . --exclude=.kde' | tar xzf -
	popd >/dev/null
	du -s $D/$m | cut -f 1
done
