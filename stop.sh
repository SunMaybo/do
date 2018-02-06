#!/bin/bash
echo -e "Stoping the $1 ............\c"
kill -15 `/usr/sbin/lsof -t -i:$2`
kill -2 `/usr/sbin/lsof -t -i:$2`
kill -1 `/usr/sbin/lsof -t -i:$2`
echo "OK!"
PIDS=`ps -f | grep java | grep "$1.jar" |awk '{print $2}'`
echo "PID: $PIDS"
echo "------------------------------------------finish-----------------------------------"