#!/bin/bash

if [ "$1" = --help ] ; then
	echo "Usage: mo-get-users [--full]"
fi
[ -f config ] || { echo "Missing config file, check cwd." ; exit 1 ; }
set -e
. config

if [ -z "$CT_USER_LIST" ] ; then
	if [ "$1" = --full ] ; then
		FORM='$1,$5'
	else
		FORM='$1'
	fi
	awk -F: </etc/passwd "{ gsub(\",.*\",\"\",\$5); OFS=\"\t\"; if (\$3 >= $CT_UID_MIN && \$3 <= $CT_UID_MAX) print $FORM; }"
else
	if [ "$1" = --full ] ; then
		cut -d '	' -f 1,2 <$CT_USER_LIST
	else
		cut -d '	' -f 1 <$CT_USER_LIST
	fi
fi
