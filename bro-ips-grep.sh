#!/bin/sh -e

ip=$1

test -z "$ip" && echo "Usage: $0 ip" && exit 1

grep --line-regex $ip ./ips/*.ips | while read file ; do
	path=$( echo $file | sed 's/\.ips.*$//' )
	echo "# $file -> $path"
	grep --line-regex $ip $path/* | while read file2 ; do
		path2=$( echo $file2 | sed -e 's,\./ips,/var/log/bro,' -e "s/:$ip//" )
		path3=$( echo $file2 | sed -e 's,\./ips,/opt/zeek/logs,' -e "s/:$ip//" )
		echo "## $file2 -> $path2 $path3"

		zgrep "$ip[^0-9]" $path2 $path3
	done
done

