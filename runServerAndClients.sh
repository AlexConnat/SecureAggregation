#!/bin/bash

pythonCmd=/usr/local/bin/python3

for i in {1..3}; do

echo "Round $i"

$pythonCmd server.py &

sleep 1

# non-crashing clients
for i in {1..5}; do
    $pythonCmd client.py & 
done

# crashing clients
#for i in {0..0}; do
#    $pythonCmd client.py crash & 
#done

sleep 10

done
