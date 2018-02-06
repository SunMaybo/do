#!/bin/bash
echo -e "Starting the $1 ............\c"
nohup java $4 -jar /home/java/dotconnect_service/$2/$3/$1.jar –spring.profiles.active=$2 >&1 &
echo "OK!"
PIDS=`ps -f | grep java | grep "$1.jar" |awk '{print $2}'`
echo "PID: $PIDS"
echo "------------------------------------------finish-----------------------------------"