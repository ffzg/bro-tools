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

total() {
	cat $dir/* | sort -u | grep $1 | wc -l
}

echo -n "# total IPs   : " ; total '.'
echo -n "# 193.198.212.: " ; total 193.198.212.
echo -n "# 193.198.213.: " ; total 193.198.213.
echo -n "# 193.198.214.: " ; total 193.198.214.
echo -n "# 193.198.215.: " ; total 193.198.215.
