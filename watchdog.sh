#!/bin/bash


while :
do
  if [[ $(ps -ef | grep Virus_class_publickey.py | grep -v grep) ]];then
    continue
  else
    sleep 30
    echo "start .py"
    echo "1">>watch.txt
    python Virus_class_publickey.py
  fi
  sleep 1
done

