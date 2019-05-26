#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request
from flask_socketio import SocketIO
import time

from utils import bcolors, pretty_print, print_info, print_success, print_failure

import numpy as np


###############################
## BIG UNKNOWN CONSTANTS TBD ##
###############################
SIGMA = 40
NB_CLASSES = 5
###############################


DO_GLOBAL_LOGGING = False

TIMEOUT_ROUND_0 = 15
TIMEOUT_ROUND_1 = 10
TIMEOUT_ROUND_2 = 5

SERVER_STORAGE = {}
SERVER_VALUES = {}

app = Flask(__name__)
sio = SocketIO(app, logger=DO_GLOBAL_LOGGING) # async_mode='eventlet'



##### Just for the PoC - Remove in the final product ###########################
@app.route('/server_storage')
def index():
    return render_template('display_server_storage.html', **SERVER_STORAGE)
################################################################################


def client_ack(OK, msg, client_sid):
    if OK:
        print_success(msg, client_sid)
    else:
        print_failure(msg, client_sid)
        sio.disconnect()


@sio.on('connect')
def connect(): # also use request.environ???
    sio.emit('your sid', request.sid, room=request.sid) # We'll use the sid to identify client, we let them know who they are

@sio.on('disconnect')
def disconnect():
    pass
    # print('Bye', request.sid)


@sio.on('pubkeys')
def handle_pubkeys(data):

    print_success('Received public keys.', request.sid)

    elapsed_time = time.time() - START_TIME
    if elapsed_time > TIMEOUT_ROUND_0:
        print_failure('Too late to send public keys.', request.sid)
        return False, 'Too late to send public keys.'  # If FALSE, make this node drop (disconnect()) in the client callback

    try:
        SERVER_STORAGE.setdefault(request.sid, {})['cpk'] = data['cpk']
        SERVER_STORAGE.setdefault(request.sid, {})['spk'] = data['spk']
    except:
        print_failure('Missing key cpk or spk in client''s messsage.', request.sid)
        return False, 'Missing key cpk or spk in your message.'

    return True, 'Public keys succesfully received by server.' # acknowledgement message that everything went fine


@sio.on('list encrypted messages')
def handle_encrypted_messages(encrypted_messages):
    sending_client_sid = request.sid
    print_success('Received list of encrypted messages.', sending_client_sid)
    SERVER_STORAGE[sending_client_sid]['list_enc_msg'] = encrypted_messages
    return True, 'List of encrypted messages succesfully received by server.'


@sio.on('y')
def handle_y(y):

    sending_client_sid = request.sid
    print(bcolors.GREEN, 'Received masked input y from', sending_client_sid, bcolors.ENDC)
    print(y)
    print('{}{}{}{}{}{}{}{}{}{}{}{}')

    SERVER_STORAGE[sending_client_sid]['y'] = y

    return True, 'Merveilleux!'




############# ROUND 0 ##############
### RECEIVE PUBLIC KEYS FROM ALL ###
###  CLIENTS AND BROADCAST THEM  ###
####################################

def timer_round_0():
    print(bcolors.BOLD + 'Timer Round 0 Starts' + bcolors.ENDC)
    sio.sleep(TIMEOUT_ROUND_0)
    print(bcolors.BOLD + 'Timer Round 0 Ends' + bcolors.ENDC)
    round0()

def round0():

    n0 = len(SERVER_STORAGE.keys())
    if n0 < 3: # At least 3 clients (n=3, t=2)
        print_failure('Did not receive public keys from enough clients. Abort.', 'Server')
        sio.emit('abort', 'not enough clients') # Broadcast to everyone that the server aborts --> client should disconnect
        sio.stop()
        sio.sleep(1)

    SERVER_VALUES['n0'] = n0
    SERVER_VALUES['t'] = int(n0/2) + 1

    list_pubkeys = {} # Copy here the cpk and spk keys for each client, don't send the WHOLE server storage dict
    for client_sid, storage_fod_client_sid in SERVER_STORAGE.items():
        try:
            list_pubkeys[client_sid] = {}
            list_pubkeys[client_sid]['cpk'] = storage_fod_client_sid['cpk']
            list_pubkeys[client_sid]['spk'] = storage_fod_client_sid['spk']
        except KeyError:
            print('No keys cpk or spk for client', client_sid)

    print()
    print_info('Broadcasting list of pubkeys to clients.', 'Server')
    print()

    sio.emit('round1', list_pubkeys) # No callback because it's a broadcast message (room=/)

    sio.start_background_task(timer_round_1)




################ ROUND 1 #################
### RECEIVE LIST OF ENCRYPTED MESSAGES ###
### FROM ALL CLIENTS AND FORWARD THEM  ###
##########################################

def timer_round_1():
    print(bcolors.BOLD + 'Timer Round 1 Starts' + bcolors.ENDC)
    sio.sleep(TIMEOUT_ROUND_1)
    print(bcolors.BOLD + 'Timer Round 1 Ends' + bcolors.ENDC)
    round1()

def round1():

    list_enc_msg_FROM = {}  # Received encrypted messages from these SIDs
    for client_sid in SERVER_STORAGE.keys():
        if (SERVER_STORAGE[client_sid].get('list_enc_msg', None) != None):
            list_enc_msg_FROM[client_sid] = SERVER_STORAGE[client_sid]['list_enc_msg']

    n1 = len(list_enc_msg_FROM.keys())
    if n1 < SERVER_VALUES['t']:
        print_failure('Did not receive encrypted messages from enough clients. Abort.', 'Server')
        sio.emit('abort', 'not enough clients') # Broadcast to everyone that the server aborts --> client should disconnect
        sio.stop()
        sio.sleep(1)

    # Instead of having a dictionary of messages FROM a given client SID, we want to construct
    # a dictionary of messages TO a given client SID.
    list_enc_msg_TO = {}
    for from_client_sid, enc_msg_from_client_sid in list_enc_msg_FROM.items():
        for to_client_sid, enc_msg_to_client_sid in enc_msg_from_client_sid.items():
            # print(from_client_sid + ' --> ' + to_client_sid + ' : ' + str(enc_msg_to_client_sid))
            list_enc_msg_TO.setdefault(to_client_sid, {})[from_client_sid] = enc_msg_to_client_sid

    print()
    print_info('Forwarding lists of encrypted messages to all clients.', 'Server')
    print()

    for client_sid in list_enc_msg_TO.keys():
        sio.emit('round2', list_enc_msg_TO[client_sid], room=client_sid) # callback=client_ack # TODO: Acknowledgement is confusing in the logs

    sio.start_background_task(timer_round_2)





######################## ROUND 2 ###########################
### RECEIVE MASKED INPUTS FROM ALL CLIENTS AND ADVERTISE ###
###   ABOUT THE DROPPED OUT CLIENTS FROM LAST ROUND      ###
############################################################

def timer_round_2():
    print(bcolors.BOLD + 'Timer Round 2 Starts' + bcolors.ENDC)
    sio.sleep(TIMEOUT_ROUND_2)
    print(bcolors.BOLD + 'Timer Round 2 Ends' + bcolors.ENDC)
    round2()

def round2():
    print('Processing round2!')

    print()
    print_info('Advertise list of "alive" clients from the previous round to all other alive clients.', 'Server')
    print()

    sio.start_background_task(timer_round_3)





#################### ROUND 3 #########################
### RECEIVE ALL NECESSARY INFORMATION FROM CLIENTS ###
###     TO RECONSTRUCT AGGREGATED OUTPUT Z         ###
######################################################

def timer_round_3():
    print(bcolors.BOLD + 'Timer Round 3 Starts' + bcolors.ENDC)
    sio.sleep(TIMEOUT_ROUND_2)
    print(bcolors.BOLD + 'Timer Round 3 Ends' + bcolors.ENDC)
    round3()

def round3():
    print('Processing round3!')
    print('Reconstructing output z!')
    sio.stop()











def construct_y():

    sio.sleep(5)

    print('\n\n==============')
    print('RECONSTRUCTION')
    print('==============\n\n')
    BigX = np.zeros(NB_CLASSES)
    for client_sid in SERVER_STORAGE.keys():
        print('sid =', client_sid)
        print(SERVER_STORAGE[client_sid]['y'])
        BigX += SERVER_STORAGE[client_sid]['y']
        print()

    print('BigX =', BigX)
    # Should be equal to addition of BONJOUR MADAMEs









sio.start_background_task(timer_round_0)



if __name__ == '__main__':

    START_TIME = time.time()
    sio.run(app, host='127.0.0.1', port=9876, debug=DO_GLOBAL_LOGGING)
