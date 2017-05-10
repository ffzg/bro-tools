cat conn.log | bro-cut -d id.orig_h  | grep -v 193.198.21[2345] | sort | uniq -c | sort -rn | less

