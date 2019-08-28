#!/bin/bash

pythonCmd=/usr/bin/python3

ifname="lo"
limit="100Gbps"

#for LATENCY in 0.5 5 25 50 100 200; do
     
# Remove all network limitations
#sudo tc qdisc del dev $ifname root

# Apply network rate and latency limitations
#sudo tc qdisc add dev $ifname root handle 1: htb default 12
#sudo tc class add dev $ifname parent 1:1 classid 1:12 htb rate $limit ceil $limit
#sudo tc qdisc add dev $ifname parent 1:12 netem delay $LATENCY

for NB_CLIENTS in 60 70 80 90 100; do
#for NB_CLIENTS in 50; do

	echo "==== $NB_CLIENTS clients ===="
	echo "($LATENCY ms of latency)"
	echo ""

	for i in {1..5}; do
		
		echo "Iteration $i"

		$pythonCmd server.py $NB_CLIENTS BENCHMARK/benchmark_${NB_CLIENTS}c_nodrop_l${LATENCY} &

		sleep 0.5

		# non-crashing clients
		for ((i=0; i<$NB_CLIENTS; i++)); do
    			$pythonCmd client.py & 
		done

		# crashing clients
		#for i in 1; do
		#    $pythonCmd client.py crash & 
		#done

		sleep 150
		echo ""

	done

	echo ""

done

#done
