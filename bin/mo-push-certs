#!/bin/bash
[ -f config ] || { echo "Missing config file, check cwd." ; exit 1 ; }
set -e
. config

while IFS="	" read LOGIN FULL MACH ; do
	if [ -z "$1" -o "$1" == "$LOGIN" ] ; then
		echo "$LOGIN -> $MACH"
		D=/mo/users/$LOGIN/$LOGIN/
		rsync -av $D/.mo root@$MACH:$D/
	fi </dev/null
done <userlist
