#!/bin/sh -e

old_date=''

ls /var/log/bro/*/conn.*.log.gz | while read file ; do
	name=$( basename $file )
	date=$( echo $file | cut -d/ -f5 )
	#echo "# $old_date $name - $file"
	if [ "$old_date" != "$date" ] ; then
		test -d ips/$date || mkdir ips/$date
		if [ ! -z "$old_date" -a ! -e "ips/$old_date.ips" ] ; then
			echo "# create date $old_date summary"
			cat ips/$old_date/* | sort -u > ips/$old_date.ips
			git -C ips add $old_date.ips
			git -C ips commit -m "$old_date" $old_date.ips
			wc -l ips/$old_date.ips
		fi
		old_date=$date
	fi
	if [ ! -e "ips/$date/$name" ] ; then
		zcat $file | bro-cut id.orig_h id.resp_h | sed 's/\t/\n/' | grep '193\.198\.21[2345]\.' | sort -u > ips/$date/$name
		git -C ips add $date/$name
		git -C ips commit -m "$date $name" $date/$name
		wc -l ips/$date/$name
	fi
done

# calculate free and used IP addresses

cat ips/*.ips | sort -u | ./sort-ip.pl  > /dev/shm/ips.used

# 1 .. 255
yes | head -255 | cat -n | awk '{ print $1 }' | \
sed 's/^\(.*\)$/193.198.212.\1\n193.198.213.\1\n193.198.214.\1\n193.198.215.\1/' | ./sort-ip.pl > /dev/shm/ips.all
diff -urw /dev/shm/ips.all /dev/shm/ips.used | grep '193.198' | grep '^-' | sed 's/^-//' > /dev/shm/ips.free
rm /dev/shm/ips.all

wc -l /dev/shm/ips.used /dev/shm/ips.free

exit 0

bro-cut id.orig_h id.resp_h < /var/log/bro/current/conn.log  | sed 's/\t/\n/' | grep '193\.198\.21[2345]\.' | sort -u | ~/sort-ip.pl
