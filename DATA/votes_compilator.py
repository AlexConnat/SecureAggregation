#!/usr/bin/python3

import sys
import os
import numpy as np

if len(sys.argv) < 3:
    print(f'Usage: {sys.argv[0]} <votes folder> <nb_clients> [client 1] [client 2] ... [client n]')
    exit()

VOTES_FOLDER = sys.argv[1]
NB_CLIENTS = int(sys.argv[2])

votes_filename = [ f for f in os.listdir(VOTES_FOLDER) if 'votes_teacher_' in f ] 
NB_VOTES = len(votes_filename)

assert NB_CLIENTS <= NB_VOTES

votes_for_client = []

# EQUAL SPLIT
if len(sys.argv) == 3:
    NB_VOTES_PER_CLIENT = round(NB_VOTES/NB_CLIENTS)
    for client_id in range(NB_CLIENTS-1):
        votes_for_client.append(votes_filename[client_id*NB_VOTES_PER_CLIENT:(client_id+1)*NB_VOTES_PER_CLIENT])
    votes_for_client.append(votes_filename[(client_id+1)*NB_VOTES_PER_CLIENT:]) # Last client takes the rest

# SPLIT ACCORDING COMMAND LINE OPTIONS
else:
    if len(sys.argv) != NB_CLIENTS + 3:
        print(f'ERROR: Should specify the parts that each of the {NB_CLIENTS} receive!')
        print(f'Usage: {sys.argv[0]} <votes folder> <nb_clients> [client 1] [client 2] ... [client n]')
        exit()
    
    nb_votes_for_client = []
    for i in range(3, 3+NB_CLIENTS):
        nb_votes_for_client.append(int(sys.argv[i]))
    
    assert sum(nb_votes_for_client) == NB_VOTES
    assert len(nb_votes_for_client) == NB_CLIENTS

    # ex nb_votes_for_client = [150, 50, 15, 35]
    # 0 --> v[0:150]
    # 1 --> v[150:200]
    # 2 --> v[200:215]
    # 3 --> v[215:250]
    S = 0
    for client_id in range(NB_CLIENTS):
        votes_for_client.append(votes_filename[S:S+nb_votes_for_client[client_id]])
        S += nb_votes_for_client[client_id]

    for client_id in range(NB_CLIENTS):
        assert len(votes_for_client[client_id]) == nb_votes_for_client[client_id]



test_votes = np.load(os.path.join(VOTES_FOLDER, votes_for_client[0][0]))
NB_SAMPLES = len(test_votes)
NB_CLASSES = len(test_votes[0])

# ACTUAL VOTES COMPILATION
for client_id in range(NB_CLIENTS):
    
    len(votes_for_client)

    all_votes = np.zeros( (len(votes_for_client[client_id]), NB_SAMPLES, NB_CLASSES) )
    
    #print(client_id+1, '-->', votes_for_client[client_id])
    
    for i, vote_file in enumerate(votes_for_client[client_id]):
        votes = np.load(os.path.join(VOTES_FOLDER, vote_file))
        all_votes[i] = votes

    compiled_votes = np.zeros( (NB_SAMPLES, NB_CLASSES) )
    
    compiled_votes = np.sum(all_votes, axis=0)
   
    output_filename = 'votes_client_%d.npy' % (client_id+1)
    np.save(output_filename, compiled_votes)
    
    print(f'[*] Compiled votes saved as {output_filename}.')
