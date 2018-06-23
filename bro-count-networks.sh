#!/bin/sh -xe

ls /dev/shm/bro-count-ip/* | xargs -i sh -ce 'echo {} `cat {} | sort -u | cut -d. -f-3 | uniq -c`' | \
sed -e 's/^.*\///' -e 's/_/ /' -e 's/\.log.gz//' -e 's/ 193.198.21[2345]//g' | \
tee /dev/shm/bro-count-networks
