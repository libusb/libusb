#!/bin/bash
adb forward tcp:9999 tcp:9999
while true
do
  adb push ../cmake-build-debug/examples/listdevs /data
  adb shell "gdbserver64 0.0.0.0:9999 /data/listdevs"
done

