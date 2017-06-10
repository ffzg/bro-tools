#!/bin/sh

while true ; do
	redis-cli -n 4 --scan | while read ts ; do
		json=`echo GET $ts | redis-cli -n 4 | tee /dev/shm/4.json`
	       	ip=`echo $json | jq .orig_h`
		expire=`echo $json | jq .expire`
		echo " $ip/$expire "
		ssh -i /home/dpavlin/.ssh/mtik/enesej enesej@193.198.212.1 "/ip firewall address-list add list=public_blacklist address=$ip timeout=${expire}s comment=Blocked-by-BRO"
		echo DEL $ts | redis-cli -n 4
	done
	echo -n .
	sleep 3
done
