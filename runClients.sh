#!/bin/bash 

for i in {1..5}; do
    /usr/local/bin/python3 client.py & 
done


for i in {0..0}; do
    /usr/local/bin/python3 client.py crash & 
done
