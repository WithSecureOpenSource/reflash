#!/bin/bash

PROXY_IP="192.168.56.1"
NODE_IP="192.168.56.2"
NODE_PORT="5555"
SELENIUM="selenium-server-standalone-3.0.0.jar"

if [ "$#" -lt 1 ]; then
    echo "Usage: run_vm.sh [list|file|live]"
    exit 1
fi
command=$1
if [ "$command" == "list" ]; then
    for i in `vboxmanage list vms | sed 's/\(.*\){\(.*\)}$/\2/g'`; do
        echo "VM UUID: $i"
        vboxmanage showvminfo $i | grep Name:
        echo
    done
fi

if [[ ( "$command" == "live" ) || ( "$command" == "file" ) ]]; then
    if [ "$#" -lt 4 ]; then
        echo "Usage: run_vm.sh $1 <VM UUID> <snapshot UUID> <resource>"
        exit 1
    fi
    machine=$2
    snapshot=$3
    resource=$4
    shift 4
    
    # Start Selenium hub
    nohup java -jar $SELENIUM -role hub > selenium.log 2>&1 &
    SELENIUM_PID=$!
    
    echo "Waiting for Selenium hub..."
    while ! nc -q 1 localhost 4444 </dev/null; do sleep 1; done
    
    # Start the VM
    vboxmanage snapshot $machine restore $snapshot >/dev/null 2>&1
    vboxmanage startvm $machine --type headless
    echo "Waiting for Selenium node..."
    while ! nc -q 1 $NODE_IP $NODE_PORT </dev/null; do sleep 1; done
    sleep 1

    dir=`mktemp -d`
    if [ "$command" == "file" ]; then
        lp="index.html"
        db=$resource.db
        url=http://www.whatever.com/$lp
        ./proxy.py -l $lp -o $db -c config.json -d $dir -a $PROXY_IP -t 120 -y misc.yara -i $resource -b $url "$@"
        echo
        echo "dump dir: $dir, database: $db"
        echo
    else
        db="live.db"
        ./proxy.py -o $db -c config.json -d $dir -t 600000 -y misc.yara -a $PROXY_IP -b $resource "$@"
        echo
        echo "dump dir: $dir, database: $db"
        echo
    fi
    
    vboxmanage controlvm $machine poweroff >/dev/null 2>&1
    kill $SELENIUM_PID

fi
