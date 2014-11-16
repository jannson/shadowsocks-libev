#!/bin/bash

while true
do
  /usr/bin/ss-redir &
  PID=$!
  wait $PID
  echo $?
done
