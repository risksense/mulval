#!/bin/sh
zcat -f /common/weblogs/polara/access.log* | grep "mulval.tar.gz" | awk '{print $3}' | sort | uniq -c | sort -n