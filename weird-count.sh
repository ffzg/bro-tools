( zcat weird.* || cat weird.log ) | bro-cut -d name | sort | uniq -c | sort -n | tee /dev/shm/weird.count 
