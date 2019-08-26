#!/bin/bash 

DATASET="mnist"
NB_CLIENTS=250

for ((CLIENT_ID=1;CLIENT_ID<=NB_CLIENTS;CLIENT_ID++)); do
    /usr/local/bin/python3 client.py $DATASET $CLIENT_ID & 
done

