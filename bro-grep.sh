#!/bin/sh -ex

test -f $1 || exit 1

patt_file=$1

zgrep -f $patt_file /var/log/bro/`date +%Y-%m`*/known_hosts.* | tee /dev/stderr | while read found ; do
	path=`echo $found | sed -e 's/known_hosts/\*/' -e 's/\.gz:.*$/.gz/'`
	zgrep -f $patt_file $path
done

