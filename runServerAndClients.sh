#!/bin/bash

pythonCmd=/usr/bin/python3

for NB_CLIENTS in {3..20}; do

	echo "==== $NB_CLIENTS clients ===="

	for i in {1..20}; do

		echo "Round $i"

		$pythonCmd server.py benchmark_${NB_CLIENTS}c_1drop &

		sleep 0.5

		# non-crashing clients
		for ((i=0; i<$NB_CLIENTS-1; i++)); do
    			$pythonCmd client.py & 
		done

		# crashing clients
		for i in 1; do
		    $pythonCmd client.py crash & 
		done

		sleep 10

	done

	echo ""

done
