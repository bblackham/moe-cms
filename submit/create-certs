#!/bin/sh
# A script for creation of all the certificates used by submitd
# (c) 2007 Martin Mares <mj@ucw.cz>

set -e
if [ ! -f submit/ca-cert.tpl ] ; then
	echo >&2 "Please run from the MO root directory."
	exit 1
fi

umask 033
rm -rf certs
mkdir certs

echo "### Creating CA certificate ###"
submit/privkey >certs/ca-key.pem
certtool --generate-self-signed --load-privkey certs/ca-key.pem --outfile certs/ca-cert.pem --template submit/ca-cert.tpl

echo "### Creating server certificate ###"
submit/privkey >certs/server-key.pem
certtool --generate-request --load-privkey certs/server-key.pem --outfile certs/server-req.pem --template submit/server-cert.tpl
certtool --generate-certificate --load-request certs/server-req.pem --outfile certs/server-cert.pem --load-ca-certificate certs/ca-cert.pem --load-ca-privkey certs/ca-key.pem --template submit/server-cert.tpl

seq=1
for user in `bin/mo-get-users` ; do
	seq=$(($seq+1))
	echo "### Creating certificate for user #$seq ($user) ###"
	sed <submit/client-cert.tpl >certs/$user-cert.tpl "s/cn = \".*\"/cn = \"$user\"/; s/serial = .*/serial = $seq/;"
	submit/privkey >certs/$user-key.pem
        certtool --generate-request --load-privkey certs/$user-key.pem --outfile certs/$user-req.pem --template certs/$user-cert.tpl
        certtool --generate-certificate --load-request certs/$user-req.pem --outfile certs/$user-cert.pem --load-ca-certificate certs/ca-cert.pem --load-ca-privkey certs/ca-key.pem --template certs/$user-cert.tpl
done
