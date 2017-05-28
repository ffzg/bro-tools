cat /var/log/bro/current/http.log | bro-cut -d id.orig_h host method | sort | uniq -c | tee /dev/shm/http-count
