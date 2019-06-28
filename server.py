#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request
from flask_socketio import SocketIO
import time

from utils import bcolors, pretty_print, print_info, print_success, print_failure

from shamir_secret_sharing import SecretSharer
from diffie_hellman import DHKE

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
# TODO: When all clients in previous round are received: skip the timeout



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
    pass

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
    SERVER_VALUES['U0'].append(sending_client_sid)
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
    SERVER_VALUES['U1'].append(sending_client_sid)
    SERVER_STORAGE[sending_client_sid]['list_enc_msg'] = encrypted_messages

    return True, 'List of encrypted messages succesfully received by server.'


# @sio.on('INPUT_Y')
def handle_y(y):
    sending_client_sid = request.sid
    if SERVER_VALUES['ROUND'] != 2:
        print_failure('Too late to send masked input "y".', sending_client_sid)
        return False, 'Too late to send your masked input "y".'  # If False, make this node drop (sio.disconnect()) in the client callback

    print_success('Received masked input "y".', request.sid)
    SERVER_VALUES['U2'].append(sending_client_sid)

    SERVER_STORAGE[sending_client_sid]['y'] = y # TODO: Check if 'y' is present (correct format, etc...?)

    return True, 'Masked input "y" succesfully received by server.'



# @sio.on('MASKS')
def handle_masks(masks):
    sending_client_sid = request.sid
    if SERVER_VALUES['ROUND'] != 3:
        print_failure('Too late to send masks and shares.', sending_client_sid)
        return False, 'Too late to send your mask and shares.'  # If False, make this node drop (sio.disconnect()) in the client callback

    if 'b' in masks.keys():
        SERVER_STORAGE[sending_client_sid]['b'] = masks['b']
    else:
        print_failure('Missing mask "b" in client''s messsage.', sending_client_sid) # TODO: Should we assume that it always have it?
        return False, 'Missing mask "b" in your message.'

    if 'shares_dropped_out_clients' in masks.keys():
        SERVER_STORAGE[sending_client_sid]['shares_dropped_out_clients'] = masks['shares_dropped_out_clients']

    print_success('Received mask "b" and shares from dropped out clients.', request.sid)
    SERVER_VALUES['U3'].append(sending_client_sid)

    return True, 'Masks succesfully received by server.'




############# ROUND 0 ##############
### RECEIVE PUBLIC KEYS FROM ALL ###
###  CLIENTS AND BROADCAST THEM  ###
####################################

def timer_round_0():
    SERVER_VALUES['U0'] = []
    print(bcolors.BOLD + 'Timer Round 0 Starts' + bcolors.ENDC)
    sio.sleep(TIMEOUT_ROUND_0)
    print(bcolors.BOLD + 'Timer Round 0 Ends' + bcolors.ENDC)
    SERVER_VALUES['ROUND'] = 1  # Enter Round1 in the FSM (does not accept pubkeys from clients anymore)
    round0()                    # Process Round0 server logic

def round0():

    U0 = SERVER_VALUES['U0']
    n0 = len(U0)
    if n0 < 3: # At least 3 clients (n=3, t=2)
        print_failure('Did not receive public keys from enough clients. Abort.', 'Server')
        sio.emit('abort', 'not enough clients') # Broadcast to everyone that the server aborts --> client should disconnect
        sio.sleep(1)
        os._exit(-1) # sio.stop() # FIXME

    SERVER_VALUES['n0'] = n0
    SERVER_VALUES['t'] = int(n0/2) + 1

    list_pubkeys = {} # Copy here the cpk and spk keys for each client, don't send the WHOLE server storage dict
    for client_sid in U0:
        list_pubkeys[client_sid] = {}
        list_pubkeys[client_sid]['cpk'] = SERVER_STORAGE[client_sid]['cpk']
        list_pubkeys[client_sid]['spk'] = SERVER_STORAGE[client_sid]['spk']

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
    SERVER_VALUES['U1'] = []
    print(bcolors.BOLD + 'Timer Round 1 Starts' + bcolors.ENDC)
    sio.sleep(TIMEOUT_ROUND_1) # TODO: or if receive ALL the clients messages in U0!
    print(bcolors.BOLD + 'Timer Round 1 Ends' + bcolors.ENDC)
    SERVER_VALUES['ROUND'] = 2  # Enter Round2 in the FSM (does not accept list of encrypted messages from clients anymore)
    round1()                    # Process Round1 server logic

def round1():

    U1 = SERVER_VALUES['U1']
    n1 = len(U1)
    if n1 < SERVER_VALUES['t']:
        print_failure('Did not receive encrypted messages from enough clients. Abort.', 'Server')
        sio.emit('abort', 'not enough clients') # Broadcast to everyone that the server aborts --> client should disconnect
        sio.sleep(1)
        os._exit(-1) # sio.stop() # FIXME

    # Instead of having a dictionary of messages FROM a given client SID, we want to construct
    # a dictionary of messages TO a given client SID.
    list_enc_msg_FROM = {}
    for client_sid in U1:
        list_enc_msg_FROM[client_sid] = SERVER_STORAGE[client_sid]['list_enc_msg']

    list_enc_msg_TO = {}
    for from_client_sid, enc_msg_from_client_sid in list_enc_msg_FROM.items():
        for to_client_sid, enc_msg_to_client_sid in enc_msg_from_client_sid.items():
            # print(from_client_sid + ' --> ' + to_client_sid + ' : ' + str(enc_msg_to_client_sid))
            list_enc_msg_TO.setdefault(to_client_sid, {})[from_client_sid] = enc_msg_to_client_sid

    print()
    print_info('Forwarding lists of encrypted messages to all clients.', 'Server')
    print()

    for client_sid in U1:
        sio.emit('ROUND_2', list_enc_msg_TO[client_sid], room=client_sid) # callback=client_ack # TODO: Acknowledgement is confusing in the logs

    sio.start_background_task(timer_round_2)





######################## ROUND 2 ###########################
### RECEIVE MASKED INPUTS FROM ALL CLIENTS AND ADVERTISE ###
###   ABOUT THE DROPPED OUT CLIENTS FROM LAST ROUND      ###
############################################################

def timer_round_2():
    SERVER_VALUES['U2'] = []
    print(bcolors.BOLD + 'Timer Round 2 Starts' + bcolors.ENDC)
    sio.sleep(TIMEOUT_ROUND_2)
    print(bcolors.BOLD + 'Timer Round 2 Ends' + bcolors.ENDC)
    SERVER_VALUES['ROUND'] = 3  # Enter Round3 in the FSM (does not accept masked inputs "y" from clients anymore)
    round2()                    # Process Round2 server logic

def round2():

    U2 = SERVER_VALUES['U2']
    n2 = len(U2)
    if n2 < SERVER_VALUES['t']:
        print_failure('Did not receive masked input "y" from enough clients. Abort.', 'Server')
        sio.emit('abort', 'not enough clients') # Broadcast to everyone that the server aborts --> client should disconnect
        sio.sleep(1)
        os._exit(-1) # sio.stop() # FIXME

    # The "dropped out clients" are all the clients sid that were present in the set U1 but not in U2
    dropped_out_clients = list( set(SERVER_VALUES['U1']) - set(U2) )
    SERVER_VALUES['dropped_out_clients'] = dropped_out_clients

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
    SERVER_VALUES['U3'] = []
    print(bcolors.BOLD + 'Timer Round 3 Starts' + bcolors.ENDC)
    sio.sleep(TIMEOUT_ROUND_2)
    print(bcolors.BOLD + 'Timer Round 3 Ends' + bcolors.ENDC)
    SERVER_VALUES['ROUND'] = 4  # Enter Round4 in the FSM (does not accept masks from clients anymore)
    round3()                    # Process Round3 server logic

def round3():

    U3 = SERVER_VALUES['U3']
    n3 = len(U3)
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
    print()
    print('Reconstructed Z:')
    print(bigX)

    # This bigXX corresponds to the aggregation of all noisy_x of ALIVE clients + the s_masks of DROPPED OUT clients (that did not cancel out)


    # Recollect shares from dropped out clients
    shares_dead = {}
    for alive_client_sid in U3:
        for dead_client_sid, share_dead in SERVER_STORAGE[alive_client_sid]['shares_dropped_out_clients'].items():
            shares_dead.setdefault(dead_client_sid, []).append(share_dead)  # TODO: Better logic???

    # Reconstruct the ssk of dropped out clients from the collected shares
    ssk_dead = {}
    for dead_client_sid in SERVER_VALUES['dropped_out_clients']:
        ssk_for_sid = SecretSharer.recover_secret(shares_dead[dead_client_sid])
        ssk_dead[dead_client_sid] = ssk_for_sid

    # Reconstruct the needed masks from these dropped out clients secret keys
    s_mask_dead = {}
    for alive_client_sid in U3:
        for dead_client_sid in SERVER_VALUES['dropped_out_clients']:
            s_dead_alive = DHKE.agree(ssk_dead[dead_client_sid], SERVER_STORAGE[alive_client_sid]['spk'])
            np.random.seed(s_dead_alive)
            s_mask_dead_alive = np.random.uniform(-100, 100, NB_CLASSES)
            s_mask_dead.setdefault(dead_client_sid, {})[alive_client_sid] = s_mask_dead_alive  # TODO: Better logic???

    print()
    pretty_print(s_mask_dead)
    print()

    sio.emit('complete', 'Reconstructed output z!')
    sio.sleep(1)
    os._exit(0) # sio.stop() # FIXME  # No problem (SUCCESS_CODE 0?)




















if __name__ == '__main__':



    global DHKE
    DHKE = DHKE(groupID=14) # TODO: Use 2048-bit group (id=14) or above




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
    sio.on_event('PUB_KEYS', handle_pubkeys)   # Should be received at all time!

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



    ### TO PUT INTO A BACKGROUND TASK ###
    # input("Press Spacebar to continue...")
    # # Block until key pressed
    # sio.sleep(1)
    # sio.emit('START', 'Some classification task')
    ######

    sio.start_background_task(timer_round_0)


    sio.run(app, host='127.0.0.1', port=9876, debug=DO_GLOBAL_LOGGING)
