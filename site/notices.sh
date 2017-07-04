#!/bin/sh

sleep=3
while true ; do
	redis-cli -n 5 --scan | while read ts ; do
		json=`echo GET $ts | redis-cli -n 5 | tee /dev/shm/5.json`
	       	ip=`echo $json | jq .src`
		expire=`echo $json | jq .suppress_for`
		msg=`echo $json | jq .msg`
		echo " $ip/$expire $msg"
		ssh -i /home/dpavlin/.ssh/mtik/enesej enesej@193.198.212.1 "/ip firewall address-list add list=public_blacklist address=$ip timeout=${expire}s comment=$msg"
		echo DEL $ts | redis-cli -n 5
	done
	echo -n .
	sleep $sleep
done
