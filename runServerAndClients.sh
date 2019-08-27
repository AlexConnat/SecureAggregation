#!/bin/bash

pythonCmd=/usr/bin/python3

for NB_CLIENTS in 150; do

	echo "==== $NB_CLIENTS clients ===="

	for i in {1..5}; do

		echo "Iteration $i"

		$pythonCmd server.py $NB_CLIENTS benchmark_${NB_CLIENTS}c_nodrop &

		sleep 0.5

		# non-crashing clients
		for ((i=0; i<$NB_CLIENTS; i++)); do
    			$pythonCmd client.py & 
		done

		# crashing clients
		#for i in 1; do
		#    $pythonCmd client.py crash & 
		#done

		sleep 1700

	done

	echo ""

done
