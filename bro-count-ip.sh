#!/bin/sh -e

dir=/dev/shm/bro-count-ip
test -d $dir || mkdir $dir

ls /var/log/bro/*/conn.* | while read log_path ; do
	log=`echo $log_path | sed -e 's/\/conn./_/' -e 's/^.*\///'`
	if [ ! -e $dir/$log ] ; then
		echo -n "## $log "
		zcat $log_path | bro-cut -d id.orig_h -F' ' | grep '193.198.21[2345].' | sort -u | tee $dir/$log | wc -l
	fi
done

cat /dev/shm/bro-count-ip/* | sort | uniq -c | tee $dir.uniq-c | awk '{ split($2,a,"."); printf("%03d%03d%03d%03d %d\n",a[1],a[2],a[3],a[4],$1) }' | sort -n | sed -e 's/^\(...\)\(...\)\(...\)\(...\)/\1.\2.\3.\4/' -e 's/\.00*/./g' | tee $dir.sorted

