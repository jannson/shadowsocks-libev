#!/bin/bash

while true
do
  ./src/ss-test &
  PID=$!
  wait $PID
  echo $?
done
