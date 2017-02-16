#!/bin/sh

if [ "$#" -lt 1 ]; then
    echo "Usage: run_file.sh <file>"
    exit 1
fi

interface='eth0'

dir=`mktemp -d`
db=$1.db
lp="index.html"
ip_addr=`ifconfig $interface | sed -n 's/.*r:\(.*\) B.*/\1/p'`
file=$1
shift 1


echo "dump dir: $dir, database: $db, landing page: $lp"
echo "Now browse to http://www.example.com/index.html"
./proxy.py -i $file -l $lp -o $db -c config.json -d $dir -a $ip_addr -t 120 -y misc.yara "$@"


