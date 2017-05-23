zcat software.* | bro-cut -d software_type name version.major   version.minor   version.minor2  version.minor3 | sort | uniq -c | sort -n | tee /dev/shm/software.count 
