#!/bin/sh

while true ; do
	redis-cli -n 4 --scan | while read ts ; do
		json=`echo GET $ts | redis-cli -n 4 | tee /dev/shm/4.json`
	       	ip=`echo $json | jq .orig_h`
		expire=`echo $json | jq .expire`
		msg=`echo $json | jq .location`
		echo " $ip/$expire $msg "
		ssh -i /home/dpavlin/.ssh/mtik/enesej enesej@193.198.212.1 "/ip firewall address-list add list=public_blacklist address=$ip timeout=${expire}s comment=$msg"
		echo DEL $ts | redis-cli -n 4
		logger -f /dev/shm/4.json --tag=json --id=4
	done
	echo -n .
	sleep 3
done
