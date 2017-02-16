#!/bin/sh

interface='eth0'

ip_addr=`ifconfig $interface | sed -n 's/.*r:\(.*\) B.*/\1/p'`
dir=`mktemp -d`

./proxy.py -o live.db -c config.json -d $dir -t 600000 -a $ip_addr "$@"



