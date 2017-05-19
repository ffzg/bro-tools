show="id.orig_h id.resp_h id.resp_p proto"
cat /var/log/bro/current/conn.log | bro-cut -d $show | grep -v '^193.198.21[2345]' | grep -v '^10\.' | sort | uniq -c | sort -rn | tee /dev/shm/conn-remote.log | less

