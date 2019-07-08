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
SIGMA = 3
NB_CLASSES = 5

TIMEOUT_ROUND_0 = 10
TIMEOUT_ROUND_1 = 5
TIMEOUT_ROUND_2 = 5


UNIFORM_B_BOUNDS = 10
UNIFORM_S_BOUNDS = 100


START_TIME = time.time() # TODO: Care about out-of-time messages

DO_GLOBAL_LOGGING = False
###############################




##### Just for the PoC - Remove in the final product ###########################
# @app.route('/server_storage')
# def index():
#     return render_template('display_server_storage.html', **SERVER_STORAGE)
################################################################################





#############################################################################################
# Handlers should be short (https://github.com/miguelgrinberg/Flask-SocketIO/issues/597)
# If big CPU work, use async_handlers = True, or just sio.start_background_task( function )
#############################################################################################


# @sio.on('connect')
def connect(): # also use request.environ???
    pass

# @sio.on('disconnect')
def disconnect():
    pass


# @sio.on('PUB_KEYS')
def handle_pubkeys(data):
    sending_client_sid = request.sid

    # Check in which round the FSM is
    if SERVER_VALUES['ROUND'] != 0:
        print_failure('Too late to send public keys.', sending_client_sid)
        return False, 'Too late to send your public keys.' # If False, make this node drop (sio.disconnect()) in the client callback

    # Add public key cpk to Server Storage for this client SID
    try:
        SERVER_STORAGE.setdefault(sending_client_sid, {})['cpk'] = data['cpk']
    except:
        print_failure('Missing key cpk in client''s messsage.', sending_client_sid)
        return False, 'Missing key cpk in your message.'

    # Add public key spk to Server Storage for this client SID
    try:
        SERVER_STORAGE.setdefault(sending_client_sid, {})['spk'] = data['spk']
    except:
        print_failure('Missing key spk in client''s messsage.', sending_client_sid)
        return False, 'Missing key spk in your message.'

    # Logging message
    print_success('Received public keys.', sending_client_sid)

    # Add this client SID in the list of active clients at round 0
    SERVER_VALUES['U0'].append(sending_client_sid)

    # Acknowledgement message (to the client) that everything went fine
    return True, 'Public keys succesfully received by server.'


# @sio.on('ENC_MSGS')
def handle_encrypted_messages(encrypted_messages):
    sending_client_sid = request.sid

    # Check in which round the FSM is
    if SERVER_VALUES['ROUND'] != 1:
        print_failure(str(ROUND) + 'Too late to send list of encrypted messages.', sending_client_sid)
        return False, str(ROUND) + 'Too late to send your list encrypted messages.' # If False, make this node drop (sio.disconnect()) in the client callback

    # TODO: Verify assumptions about this list
    # Add the list of encrypted messages from this client SID to the Server Storage
    ##########################################
    SERVER_STORAGE[sending_client_sid]['list_enc_msg'] = encrypted_messages
    #############################################

    # Logging message
    print_success('Received list of encrypted messages.', sending_client_sid)

    # Add this client SID in the list of active clients at round 1
    SERVER_VALUES['U1'].append(sending_client_sid)

    # # No clients from last round have dropped out, and this is the last client we're receiving the list of encrypted messages from
    # if set(SERVER_VALUES['U1']) == set(SERVER_VALUES['U0']):
    #     goto_next_round()
    #     SERVER_VALUES['ROUND'] = 2           # Enter Round2 in the FSM (hence, does not accept list of encrypted messages from clients anymore)
    #     sio.sleep(3)
    #     sio.start_background_task(round1())  # Proceed directly to Round1 server-side logic

    # Acknowledgement message (to the client) that everything went fine
    return True, 'List of encrypted messages succesfully received by server.'


# @sio.on('INPUT_Y')
def handle_y(y):
    sending_client_sid = request.sid

    # Check in which round the FSM is
    if SERVER_VALUES['ROUND'] != 2:
        print_failure('Too late to send masked input "y".', sending_client_sid)
        return False, 'Too late to send your masked input "y".'  # If False, make this node drop (sio.disconnect()) in the client callback

    # TODO: Verify assumptions about this y (format etc...)
    # Add the masked input y from this client SID to the Server Storage
    ############################################################
    SERVER_STORAGE[sending_client_sid]['y'] = y
    ############################################################

    # Logging message
    print_success('Received masked input "y".', request.sid)

    # Add this client SID in the list of active clients at round 2
    SERVER_VALUES['U2'].append(sending_client_sid)

    # # No clients from last round have dropped out, and this is the last client we're receiving the masked input y from
    # if set(SERVER_VALUES['U2']) == set(SERVER_VALUES['U1']):
    #     SERVER_VALUES['ROUND'] = 3           # Enter Round3 in the FSM (hence, does not accept masked inputs y from clients anymore)
    #     # sio.sleep(3)
    #     sio.start_background_task(round2())  # Proceed directly to Round2 server-side logic

    # Acknowledgement message (to the client) that everything went fine
    return True, 'Masked input "y" succesfully received by server.'



# @sio.on('SHARES')
def handle_shares(shares):
    sending_client_sid = request.sid

    # Check in which round the FSM is
    if SERVER_VALUES['ROUND'] != 3:
        print_failure('Too late to send final shares.', sending_client_sid)
        return False, 'Too late to send your mask and shares.'  # If False, make this node drop (sio.disconnect()) in the client callback

    # TODO: Verify assumptions about this y (format etc...)
    # Add the shares from this client SID to the Server Storage
    ####################################################################################
    SERVER_STORAGE[sending_client_sid]['b_shares_alive'] = shares['b_shares_alive']
    SERVER_STORAGE[sending_client_sid]['ssk_shares_dropped'] = shares['ssk_shares_dropped']

    if shares['extra_noises'] != []:
        SERVER_VALUES.setdefault('extra_noises', []).append(shares['extra_noises'])
    ####################################################################################

    # Logging message
    print_success('Received share of mask "b" for alive clients and share of key "ssk" for dropped out clients.', request.sid)

    # Add this client SID in the list of active clients at round 3
    SERVER_VALUES['U3'].append(sending_client_sid)

    # # No clients from last round have dropped out, and this is the last client we're receiving the masked input y from
    # if set(SERVER_VALUES['U3']) == set(SERVER_VALUES['U2']):
    #     SERVER_VALUES['ROUND'] = 4           # Enter Round4 in the FSM (hence, does not accept list of blinding values from clients anymore)
    #     # sio.sleep(3)
    #     sio.start_background_task(round3())  # Proceed directly to Round3 server-side logic

    return True, 'Shares succesfully received by server.'




############# ROUND 0 ##############
### RECEIVE PUBLIC KEYS FROM ALL ###
###  CLIENTS AND BROADCAST THEM  ###
####################################

def timer_round_0():
    SERVER_VALUES['U0'] = []
    print(bcolors.BOLD + 'Timer Round 0 Starts' + bcolors.ENDC)
    sio.sleep(TIMEOUT_ROUND_0) # The execution of THIS function will be hang here for TIMEOUT_ROUND_0 seconds
    print(bcolors.BOLD + 'Timer Round 0 Ends' + bcolors.ENDC)
    SERVER_VALUES['ROUND'] = 1
    round0()

    # # We're still at round 0, meaning that the timeout occurs before having received
    # # the public keys from all clients
    # if SERVER_VALUES['ROUND'] < 1:
    #     print(bcolors.BOLD + 'Timer Round 0 Ends' + bcolors.ENDC)
    #     SERVER_VALUES['ROUND'] = 1
    #     round0()


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
    sio.sleep(TIMEOUT_ROUND_1)
    print(bcolors.BOLD + 'Timer Round 1 Ends' + bcolors.ENDC)
    SERVER_VALUES['ROUND'] = 2  # Enter round 2 in the FSM
    round1()                    # Process round 1 server logic

    # # We're still at round 1, and the timeout occurs before having received the list
    # # of encrypted messages from all clients of last round
    # if SERVER_VALUES['ROUND'] < 2:
    #     print(bcolors.BOLD + 'Timer Round 1 Ends' + bcolors.ENDC)
    #     SERVER_VALUES['ROUND'] = 2  # Enter round 2 in the FSM
    #     round1()                    # Process round 1 server logic


def round1():
    U1 = SERVER_VALUES['U1']
    n1 = len(U1)
    if n1 < SERVER_VALUES['t']:
        print_failure('Did not receive encrypted messages from enough clients. Abort.', 'Server')
        sio.emit('abort', 'not enough clients') # Broadcast to everyone that the server aborts --> client should disconnect
        sio.sleep(1)
        os._exit(-1) # sio.stop() # FIXME

    # The "dropped out clients" are all the clients sid that were present in the set U0 but not in U1
    dropped_out_clients = list( set(SERVER_VALUES['U0']) - set(U1) )
    SERVER_VALUES['dropped_out_clients_round_1'] = dropped_out_clients

    # Instead of having a dictionary of messages FROM a given client SID, we want to construct
    # a dictionary of messages TO a given client SID.
    list_enc_msg_FROM = {}
    for client_sid in U1:
        list_enc_msg_FROM[client_sid] = SERVER_STORAGE[client_sid]['list_enc_msg']

    # This is here that we reverse the "FROM key TO value" dict to a "FROM value TO key" dict
    # e.g: {1: {2:a, 3:b, 4:c}, 3: {1:d,2:e,4:f}, 4: {1:g,2:h,3:i}}  -->  {1: {3:d, 4:g}, 3:{1:b, 4:i}, 4: {1:c,3:f} }
    list_enc_msg_TO = {}
    for from_client_sid, enc_msg_from_client_sid in list_enc_msg_FROM.items():
        for to_client_sid, enc_msg_to_client_sid in enc_msg_from_client_sid.items():
            # print(from_client_sid + ' --> ' + to_client_sid + ' : ' + str(enc_msg_to_client_sid))
            list_enc_msg_TO.setdefault(to_client_sid, {})[from_client_sid] = enc_msg_to_client_sid

    print()
    print_info('Forwarding lists of encrypted messages to all clients.', 'Server')
    print()

    for client_sid in U1:
        sio.emit('ROUND_2', list_enc_msg_TO[client_sid], room=client_sid)

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

    # # If the timeout occurs before we gathered ??? from all clients of previous round:
    # if SERVER_VALUES['ROUND'] < 3:
    #     print(bcolors.BOLD + 'Timer Round 2 Ends' + bcolors.ENDC)
    #     SERVER_VALUES['ROUND'] = 3
    #     round2()


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
    SERVER_VALUES['dropped_out_clients_round_2'] = dropped_out_clients

    print()
    print_info('Advertise list of alive and dropped out clients from the previous round to all still alive clients.', 'Server')
    print()

    sio.emit('ROUND_3', {'dropped_out': dropped_out_clients, 'alive': U2})


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

    # # If the timeout occurs before we gathered ??? from all clients of previous round:
    # if SERVER_VALUES['ROUND'] < 4:
    #     print(bcolors.BOLD + 'Timer Round 3 Ends' + bcolors.ENDC)
    #     SERVER_VALUES['ROUND'] = 4
    #     round3()


def round3():

    U3 = SERVER_VALUES['U3']
    n3 = len(U3)
    if n3 < SERVER_VALUES['t']:
        print_failure('Did not receive masks and shares from enough clients. Abort.', 'Server')
        sio.emit('abort', 'not enough clients') # Broadcast to everyone that the server aborts --> client should disconnect
        sio.sleep(1)
        os._exit(-1) # sio.stop() # FIXME

    # The "dropped out clients" are all the clients sid that were present in the set U0 but not in U1
    dropped_out_clients = list( set(SERVER_VALUES['U2']) - set(U3) )
    SERVER_VALUES['dropped_out_clients_round_3'] = dropped_out_clients

    Z = 0

    if SERVER_VALUES['dropped_out_clients_round_2'] != []:

        # Retrieve the shares of "ssk" of dropped out clients from all alive clients
        all_ssk_shares = []
        for client_sid in U3:
            all_ssk_shares.append(SERVER_STORAGE[client_sid]['ssk_shares_dropped'])

        ssk_shares_for_sid = {
            k: [d.get(k) for d in all_ssk_shares]
            for k in set().union(*all_ssk_shares)
        }

        # Reconstruct ssk from its shares
        ssk_for_sid = {}
        for client_sid in SERVER_VALUES['dropped_out_clients_round_2']:
            ssk = SecretSharer.recover_secret( ssk_shares_for_sid[client_sid] )
            ssk_for_sid[client_sid] = ssk

        # Reconstruct all blinding values (s_masks) for all pairs of alive users with the dropped out users
        all_masks = np.zeros(NB_CLASSES)
        for dropped_client_sid in SERVER_VALUES['dropped_out_clients_round_2']:
            for alive_client_sid in U3:
                s_for_sid = DHKE.agree(ssk_for_sid[dropped_client_sid], SERVER_STORAGE[alive_client_sid]['spk'])
                np.random.seed(s_for_sid % 2**32)
                s_mask_for_sid = np.random.uniform(-UNIFORM_S_BOUNDS, UNIFORM_S_BOUNDS, NB_CLASSES)
                sgn = np.sign(int(alive_client_sid, 16) - int(dropped_client_sid, 16))
                all_masks += sgn * s_mask_for_sid

        Z -= all_masks


    # Retrieve the shares of "b" from all alive clients
    all_b_shares = []
    for client_sid in U3:
        all_b_shares.append(SERVER_STORAGE[client_sid]['b_shares_alive'])

    b_shares_for_sid = {
        k: [d.get(k) for d in all_b_shares]
        for k in set().union(*all_b_shares)
    }

    # Reconstruct "b" from its shares
    b_for_sid = {}
    for client_sid in U3:
        b = SecretSharer.recover_secret(  b_shares_for_sid[client_sid] )
        b_for_sid[client_sid] = b

    # Remove b from the y that we received from clients, and aggregate the whole
    for client_sid in U3:
        b = b_for_sid[client_sid]
        np.random.seed(b)
        b_mask = np.random.uniform(-UNIFORM_B_BOUNDS, UNIFORM_B_BOUNDS, NB_CLASSES)
        Z += (SERVER_STORAGE[client_sid]['y'] - b_mask)

    print('\nZ_maxed = ', Z)

    if 'extra_noises' in SERVER_VALUES:
        extra_noises = np.array(SERVER_VALUES['extra_noises'])
        extra_noises_sum = np.sum(extra_noises, axis=0)

        Z -= extra_noises_sum


    print('\nZ = ', Z)



    sio.emit('complete', 'Reconstructed output z!')
    sio.sleep(1)
    os._exit(0) # sio.stop() # FIXME  # No problem (SUCCESS_CODE 0?)







if __name__ == '__main__':



    global DHKE
    DHKE = DHKE(groupID=14)




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
    sio.on_event('PUB_KEYS', handle_pubkeys)   # TODO: Should be received and stored at all time!?

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
    sio.on_event('SHARES', handle_shares)



    ### TO PUT INTO A BACKGROUND TASK ###
    # input("Press Spacebar to continue...")
    # # Block until key pressed
    # sio.sleep(1)
    # sio.emit('START', 'Some classification task')
    ######

    sio.start_background_task(timer_round_0)


    sio.run(app, host='127.0.0.1', port=9876, debug=DO_GLOBAL_LOGGING)
