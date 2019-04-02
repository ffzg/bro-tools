#!/bin/sh -e

dir=/var/log/bro/.mac2ip

if [ ! -z "$1" -a "$1" != "update" ] ; then
	if [ -z "$2" ] ; then
		# just one mac, faster even for multiple invocations!
		zgrep $1 $dir/*.gz
	else
		re=`echo $* | sed 's/ /|/g'`
		zegrep "($re)" $dir/*.gz
	fi
	exit 0
fi


# ignore tilera and pix mac for nat returns
# this hides public IPs which are not interesting
filter="(d4:ca:6d:01:4c:f2|00:0e:0c:5f:77:1e)"

test -d $dir || mkdir $dir

ls -t /var/log/bro/*/conn.*gz | while read log_path ; do

	log=`echo $log_path | sed -e 's/\/conn./_/' -e 's/^.*\///'`
	if [ ! -e $dir/$log ] ; then
		echo -n "## $log "
		zcat $log_path \
			| bro-cut -F' ' -d resp_l2_addr id.resp_h vlan \
			| egrep -v "^$filter" \
			| sort -u | tee $dir/$log | wc -l
	fi

done

