#!/bin/sh

while true ; do
	redis-cli -n 4 --scan | while read ts ; do
		ip=`echo GET $ts | redis-cli -n 4 | tee /dev/shm/4.json | jq .orig_h`
		echo " $ip "
		ssh -i /home/dpavlin/.ssh/mtik/enesej enesej@193.198.212.1 "/ip firewall address-list add list=public_blacklist address=$ip timeout=1h comment=Blocked-by-BRO"
		echo DEL $ts | redis-cli -n 4
	done
	echo -n .
	sleep 3
done
