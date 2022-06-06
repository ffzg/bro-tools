#!/bin/sh -e

ip=193.198.213.175
#ip=$1

grep $ip ./ips/*.ips | while read file ; do
	path=$( echo $file | sed 's/\.ips.*$//' )
	echo "# $file -> $path"
	grep $ip $path/* | while read file2 ; do
		path2=$( echo $file2 | sed -e 's,\./ips,/var/log/bro,' -e "s/:$ip//" )
		echo "## $file2 -> $path2"

		zgrep $ip $path2
	done
done

