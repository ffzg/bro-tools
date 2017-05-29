zcat software.* || cat software.log | bro-cut -d software_type name version.major   version.minor | sort | uniq -c | sort -n | tee /dev/shm/software.count 
