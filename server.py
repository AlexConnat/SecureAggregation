#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request
from flask_socketio import SocketIO
import time

from utils import bcolors, pretty_print, print_info, print_success, print_failure

import numpy as np



##### Just for the PoC - Remove in the final product ###########################
# @app.route('/server_storage')
# def index():
#     return render_template('display_server_storage.html', **SERVER_STORAGE)
################################################################################


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


# @sio.on('pubkeys')
def handle_pubkeys(data):
    sending_client_sid = request.sid
    print_success('Received public keys.', sending_client_sid)

    # elapsed_time = time.time() - START_TIME
    # if elapsed_time > TIMEOUT_ROUND_0:
    #     print_failure('Too late to send public keys.', sending_client_sid)
    #     return False, 'Too late to send public keys.'  # If FALSE, make this node drop (disconnect()) in the client callback

    try:
        SERVER_STORAGE.setdefault(sending_client_sid, {})['cpk'] = data['cpk']
        SERVER_STORAGE.setdefault(sending_client_sid, {})['spk'] = data['spk']
    except:
        print_failure('Missing key cpk or spk in client''s messsage.', sending_client_sid)
        return False, 'Missing key cpk or spk in your message.'

    return True, 'Public keys succesfully received by server.' # acknowledgement message that everything went fine


# @sio.on('list encrypted messages')
def handle_encrypted_messages(encrypted_messages):
    # TODO: OUT-OF-TIME MESSAGE?
    sending_client_sid = request.sid
    print_success('Received list of encrypted messages.', sending_client_sid)
    SERVER_STORAGE[sending_client_sid]['list_enc_msg'] = encrypted_messages
    return True, 'List of encrypted messages succesfully received by server.'


# @sio.on('y')
def handle_y(y):
    # TODO: OUT-OF-TIME MESSAGE?
    sending_client_sid = request.sid
    print_success('Received masked input "y".', request.sid)
    SERVER_STORAGE[sending_client_sid]['y'] = y
    return True, 'Masked input "y" succesfully received by server.'







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
        if 'list_enc_msg' in SERVER_STORAGE[client_sid].keys(): # Should have been set in the handler @sio.on('list encrypted messages')
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

    n2 = 0 # TODO: Less hacky way to count number of messages?
    for client_sid in SERVER_STORAGE.keys():
        if 'y' in SERVER_STORAGE[client_sid].keys():
            n2 += 1

    if n2 < SERVER_VALUES['t']:
        print_failure('Did not receive masked input "y" from enough clients. Abort.', 'Server')
        sio.emit('abort', 'not enough clients') # Broadcast to everyone that the server aborts --> client should disconnect
        sio.stop()
        sio.sleep(1)



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

    n3 = 0 # TODO: Less hacky way to count number of messages?
    for client_sid in SERVER_STORAGE.keys():
        if 'b' in SERVER_STORAGE[client_sid].keys():
            n3 += 1

    if n3 < SERVER_VALUES['t']:
        print_failure('Did not receive masks and shares from enough clients. Abort.', 'Server')
        sio.emit('abort', 'not enough clients') # Broadcast to everyone that the server aborts --> client should disconnect
        sio.stop()
        sio.sleep(1)

    print('Processing round3!')


    print_success('Reconstructing output z!', 'Server')

    sio.emit('abort', 'SUPER COOL!')
    sio.stop()
















###############################
## BIG UNKNOWN CONSTANTS TBD ##
###############################
SIGMA = 40
NB_CLASSES = 5

TIMEOUT_ROUND_0 = 15
TIMEOUT_ROUND_1 = 5
TIMEOUT_ROUND_2 = 5

 START_TIME = time.time() # TODO: Care about out-of-time messages
###############################



if __name__ == '__main__':

    DO_GLOBAL_LOGGING = False

    # This dictionary will contain all the values used by the server
    # to keep track of time, rounds, and number of clients
    global SERVER_VALUES
    SERVER_VALUES = {}

    # This dictionary will contain the information that the server
    # received about all clients. It is keyed by client_sid.
    global SERVER_STORAGE
    SERVER_STORAGE = {}

    app = Flask(__name__)
    sio = SocketIO(app, logger=DO_GLOBAL_LOGGING) # async_mode='eventlet'

    sio.on('connect', connect)
    sio.on('disconnect', disconnect)

    # ROUND 0
    sio.on('pubkeys', handle_pubkeys)

    # ROUND 1
    sio.on('list encrypted messages', handle_encrypted_messages)

    # ROUND 2
    sio.on('y', handle_y)


    sio.start_background_task(timer_round_0)


    sio.run(app, host='127.0.0.1', port=9876, debug=DO_GLOBAL_LOGGING)
