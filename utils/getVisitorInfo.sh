#!/bin/sh
LOG=/common/weblogs/polara/access.log.1

for IP_ADRESS in `grep "mulval.tar.gz" $LOG | awk '{print $3}' | sort | uniq  | sort -n`; do
 # echo "IP_ADRESS = ${IP_ADRESS}"
    whois ${IP_ADRESS} >> log_tmp.txt
 # echo "please find visitor information at log_tmp.txt"
done