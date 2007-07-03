#!/bin/bash
set -e
while IFS="	" read LOGIN FULL MACH ; do
	if [ -z "$1" -o "$1" == "$LOGIN" ] ; then
		echo "$LOGIN -> $MACH"
		D=/mo/users/$LOGIN/$LOGIN/
		rsync -av ~mo-eval/testing/$LOGIN root@$MACH:$D/results
		ssh root@$MACH "cd $D && chown -R $LOGIN.$LOGIN results"
	fi </dev/null
done <userlist
