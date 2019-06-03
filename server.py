#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request
from flask_socketio import SocketIO
import time

from utils import bcolors, pretty_print, print_info, print_success, print_failure

import numpy as np

import os

###############################
## BIG UNKNOWN CONSTANTS TBD ##
###############################
SIGMA = 40
NB_CLASSES = 5

TIMEOUT_ROUND_0 = 15
TIMEOUT_ROUND_1 = 10
TIMEOUT_ROUND_2 = 10




START_TIME = time.time() # TODO: Care about out-of-time messages

DO_GLOBAL_LOGGING = False
###############################




##### Just for the PoC - Remove in the final product ###########################
# @app.route('/server_storage')
# def index():
#     return render_template('display_server_storage.html', **SERVER_STORAGE)
################################################################################


# TODO: never used...
def client_ack(OK, msg, client_sid):
    if OK:
        print_success(msg, client_sid)
    else:
        print_failure(msg, client_sid)
        sio.disconnect()



#############################################################################################
# Handlers should be short (https://github.com/miguelgrinberg/Flask-SocketIO/issues/597)
# If big CPU work, use async_handlers = True, or just start_background_task
#############################################################################################


# @sio.on('connect')
def connect(): # also use request.environ???
    sio.emit('your sid', request.sid, room=request.sid) # We'll use the sid to identify client, we let them know who they are

# @sio.on('disconnect')
def disconnect():
    pass
    # print('Bye', request.sid)


# @sio.on('PUB_KEYS')
def handle_pubkeys(data):
    sending_client_sid = request.sid
    if SERVER_VALUES['ROUND'] != 0:
        print_failure('Too late to send public keys.', sending_client_sid)
        return False, 'Too late to send your public keys.'  # If False, make this node drop (sio.disconnect()) in the client callback

    print_success('Received public keys.', sending_client_sid)
    try:
        SERVER_STORAGE.setdefault(sending_client_sid, {})['cpk'] = data['cpk']
        SERVER_STORAGE.setdefault(sending_client_sid, {})['spk'] = data['spk']
    except:
        print_failure('Missing key cpk or spk in client''s messsage.', sending_client_sid)
        return False, 'Missing key cpk or spk in your message.'

    return True, 'Public keys succesfully received by server.' # acknowledgement message that everything went fine


# @sio.on('ENC_MSGS')
def handle_encrypted_messages(encrypted_messages):
    sending_client_sid = request.sid
    if SERVER_VALUES['ROUND'] != 1:
        print_failure(str(ROUND) + 'Too late to send list of encrypted messages.', sending_client_sid)
        return False, str(ROUND) + 'Too late to send your list encrypted messages.'  # If False, make this node drop (sio.disconnect()) in the client callback

    print_success('Received list of encrypted messages.', sending_client_sid)
    SERVER_STORAGE[sending_client_sid]['list_enc_msg'] = encrypted_messages

    return True, 'List of encrypted messages succesfully received by server.'


# @sio.on('INPUT_Y')
def handle_y(y):
    sending_client_sid = request.sid
    if SERVER_VALUES['ROUND'] != 2:
        print_failure('Too late to send masked input "y".', sending_client_sid)
        return False, 'Too late to send your masked input "y".'  # If False, make this node drop (sio.disconnect()) in the client callback

    print_success('Received masked input "y".', request.sid)
    SERVER_STORAGE[sending_client_sid]['y'] = y

    return True, 'Masked input "y" succesfully received by server.'



# @sio.on('MASKS')
def handle_masks(masks):
    sending_client_sid = request.sid
    if SERVER_VALUES['ROUND'] != 3:
        print_failure('Too late to send masks and shares.', sending_client_sid)
        return False, 'Too late to send your mask and shares.'  # If False, make this node drop (sio.disconnect()) in the client callback

    print_success('Received mask "b" and shares from dropped out clients.', request.sid)

    if 'b' in masks.keys():
        SERVER_STORAGE[sending_client_sid]['b'] = masks['b']
    else:
        print_failure('Missing mask "b" in client''s messsage.', sending_client_sid) # TODO: Should we assume that it always have it?
        return False, 'Missing mask "b" in your message.'

    if 'shares_dropped_out_clients' in masks.keys():
        SERVER_STORAGE[sending_client_sid]['shares_dropped_out_clients'] = masks['shares_dropped_out_clients']

    return True, 'Masks succesfully received by server.'




############# ROUND 0 ##############
### RECEIVE PUBLIC KEYS FROM ALL ###
###  CLIENTS AND BROADCAST THEM  ###
####################################

def timer_round_0():
    print(bcolors.BOLD + 'Timer Round 0 Starts' + bcolors.ENDC)
    sio.sleep(TIMEOUT_ROUND_0)
    print(bcolors.BOLD + 'Timer Round 0 Ends' + bcolors.ENDC)
    SERVER_VALUES['ROUND'] = 1  # Enter Round1 in the FSM (does not accept pubkeys from clients anymore)
    round0()                    # Process Round0 server logic

def round0():

    U0 = list(SERVER_STORAGE.keys())
    n0 = len(U0)
    if n0 < 3: # At least 3 clients (n=3, t=2)
        print_failure('Did not receive public keys from enough clients. Abort.', 'Server')
        sio.emit('abort', 'not enough clients') # Broadcast to everyone that the server aborts --> client should disconnect
        sio.sleep(1)
        os._exit(-1) # sio.stop() # FIXME

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

    sio.emit('ROUND_1', list_pubkeys) # No callback because it's a broadcast message (room=/)

    sio.start_background_task(timer_round_1)




################ ROUND 1 #################
### RECEIVE LIST OF ENCRYPTED MESSAGES ###
### FROM ALL CLIENTS AND FORWARD THEM  ###
##########################################

def timer_round_1():
    print(bcolors.BOLD + 'Timer Round 1 Starts' + bcolors.ENDC)
    sio.sleep(TIMEOUT_ROUND_1) # TODO: or if receive ALL the clients messages in U0!
    print(bcolors.BOLD + 'Timer Round 1 Ends' + bcolors.ENDC)
    SERVER_VALUES['ROUND'] = 2  # Enter Round2 in the FSM (does not accept list of encrypted messages from clients anymore)
    round1()                    # Process Round1 server logic

def round1():

    U1 = []
    list_enc_msg_FROM = {}  # Received encrypted messages from these SIDs
    for client_sid in SERVER_STORAGE.keys():
        if 'list_enc_msg' in SERVER_STORAGE[client_sid].keys(): # Should have been set in the handler @sio.on('ENC_MSGS')
            list_enc_msg_FROM[client_sid] = SERVER_STORAGE[client_sid]['list_enc_msg']
            U1.append(client_sid)

    n1 = len(list_enc_msg_FROM.keys())
    n111 = len(U1)
    assert n1 == n111

    if n1 < SERVER_VALUES['t']:
        print_failure('Did not receive encrypted messages from enough clients. Abort.', 'Server')
        sio.emit('abort', 'not enough clients') # Broadcast to everyone that the server aborts --> client should disconnect
        sio.sleep(1)
        os._exit(-1) # sio.stop() # FIXME

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
        sio.emit('ROUND_2', list_enc_msg_TO[client_sid], room=client_sid) # callback=client_ack # TODO: Acknowledgement is confusing in the logs

    sio.start_background_task(timer_round_2)





######################## ROUND 2 ###########################
### RECEIVE MASKED INPUTS FROM ALL CLIENTS AND ADVERTISE ###
###   ABOUT THE DROPPED OUT CLIENTS FROM LAST ROUND      ###
############################################################

def timer_round_2():
    print(bcolors.BOLD + 'Timer Round 2 Starts' + bcolors.ENDC)
    sio.sleep(TIMEOUT_ROUND_2)
    print(bcolors.BOLD + 'Timer Round 2 Ends' + bcolors.ENDC)
    SERVER_VALUES['ROUND'] = 3  # Enter Round3 in the FSM (does not accept masked inputs "y" from clients anymore)
    round2()                    # Process Round2 server logic

def round2():

    U2 = []
    dropped_out_clients = []
    for client_sid in SERVER_STORAGE.keys():
        if 'y' in SERVER_STORAGE[client_sid].keys():
            U2.append(client_sid)
        if not 'y' in SERVER_STORAGE[client_sid].keys():
            if 'list_enc_msg' in SERVER_STORAGE[client_sid].keys(): # Only clients from last round! Meaning that we already received their encrypted shares
                dropped_out_clients.append(client_sid)

    n2 = len(U2) # TODO: Less hacky way to count number of clients that sent "y"?

    if n2 < SERVER_VALUES['t']:
        print_failure('Did not receive masked input "y" from enough clients. Abort.', 'Server')
        sio.emit('abort', 'not enough clients') # Broadcast to everyone that the server aborts --> client should disconnect
        sio.sleep(1)
        os._exit(-1) # sio.stop() # FIXME

    print()
    print_info('Advertise list of dropped out clients from the previous round to all still alive clients.', 'Server')
    print()

    sio.emit('ROUND_3', dropped_out_clients)

    sio.start_background_task(timer_round_3)





#################### ROUND 3 #########################
### RECEIVE ALL NECESSARY INFORMATION FROM CLIENTS ###
###     TO RECONSTRUCT AGGREGATED OUTPUT Z         ###
######################################################

def timer_round_3():
    print(bcolors.BOLD + 'Timer Round 3 Starts' + bcolors.ENDC)
    sio.sleep(TIMEOUT_ROUND_2)
    print(bcolors.BOLD + 'Timer Round 3 Ends' + bcolors.ENDC)
    SERVER_VALUES['ROUND'] = 4  # Enter Round4 in the FSM (does not accept masks from clients anymore)
    round3()                    # Process Round3 server logic

def round3():

    U3 = [] # TODO: Coherent notation... round3, U4???
    for client_sid in SERVER_STORAGE.keys():
        if 'b' in SERVER_STORAGE[client_sid].keys():           # TODO: Maybe create sets of client_sids for each users, like described in paper?
            U3.append(client_sid)

    n3 = len(U3) # TODO: Less hacky way to count number of messages? # Number of clients still alive at this round

    if n3 < SERVER_VALUES['t']:
        print_failure('Did not receive masks and shares from enough clients. Abort.', 'Server')
        sio.emit('abort', 'not enough clients') # Broadcast to everyone that the server aborts --> client should disconnect
        sio.sleep(1)
        os._exit(-1) # sio.stop() # FIXME



    print()
    print(bcolors.BOLD + bcolors.PURPLE + 'Reconstructed output z!!!' + bcolors.ENDC)

    # TODO: recontruct shared masks of missing clients

    # TODO: Reconstruct output z
    bigX = np.zeros(NB_CLASSES)
    for client_sid in U3:
        b_mask_for_sid = np.random.seed(SERVER_STORAGE[client_sid]['b'])
        b_mask = np.random.uniform(-10, 10, NB_CLASSES)
        bigX += (SERVER_STORAGE[client_sid]['y'] - b_mask)


    # print()
    # pretty_print(SERVER_VALUES)
    # pretty_print(SERVER_STORAGE)
    # print()


    print()
    print('BONJOUR A TOUS:')
    print(bigX)

    sio.emit('complete', 'Reconstructed output z!')
    sio.sleep(1)
    os._exit(0) # sio.stop() # FIXME  # No problem (SUCCESS_CODE 0?)




















if __name__ == '__main__':

    # This dictionary will contain all the values used by the server
    # to keep track of time, rounds, and number of clients
    global SERVER_VALUES
    SERVER_VALUES = {}

    # This dictionary will contain the information that the server
    # received about all clients. It is keyed by client_sid.
    global SERVER_STORAGE
    SERVER_STORAGE = {}

    # Global variable "ROUND" tracking the Round Number --> Finite State Machine Logic of the server
    SERVER_VALUES['ROUND'] = 0

    app = Flask(__name__)
    sio = SocketIO(app, logger=DO_GLOBAL_LOGGING) # async_mode='eventlet' # recommended


    sio.on_event('connect', connect)
    sio.on_event('disconnect', disconnect)

    ############# ROUND 0 ##############
    ### RECEIVE PUBLIC KEYS FROM ALL ###
    ###  CLIENTS AND BROADCAST THEM  ###
    ####################################
    sio.on_event('PUB_KEYS', handle_pubkeys)

    ################ ROUND 1 #################
    ### RECEIVE LIST OF ENCRYPTED MESSAGES ###
    ### FROM ALL CLIENTS AND FORWARD THEM  ###
    ##########################################
    sio.on_event('ENC_MSGS', handle_encrypted_messages)

    ######################## ROUND 2 ###########################
    ### RECEIVE MASKED INPUTS FROM ALL CLIENTS AND ADVERTISE ###
    ###   ABOUT THE DROPPED OUT CLIENTS FROM LAST ROUND      ###
    ############################################################
    sio.on_event('INPUT_Y', handle_y)

    #################### ROUND 3 #########################
    ### RECEIVE ALL NECESSARY INFORMATION FROM CLIENTS ###
    ###     TO RECONSTRUCT AGGREGATED OUTPUT Z         ###
    ######################################################
    sio.on_event('MASKS', handle_masks)


    sio.start_background_task(timer_round_0)


    sio.run(app, host='127.0.0.1', port=9876, debug=DO_GLOBAL_LOGGING)
