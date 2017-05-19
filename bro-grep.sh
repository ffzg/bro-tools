#!/bin/sh -ex

date_filter=`date +%Y-%m-%d`
test ! -z "$DATE" && date_filter=$DATE

if [ ! -f $1 ] ; then
	:> /dev/shm/ips
	while [ ! -z "$1" ] ; do
		echo $1 | sed 's/\./\\./g' >> /dev/shm/ips
		shift
	done
	patt_file=/dev/shm/ips
else
	patt_file=$1
fi

(
zgrep -f $patt_file /var/log/bro/$date_filter*/known_hosts.* | tee /dev/stderr | while read found ; do
	path=`echo $found | sed -e 's/known_hosts/\*/' -e 's/\.gz:.*$/.gz/'`
	zgrep -f $patt_file $path
done
) | less -S -F

