#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request
from flask_socketio import SocketIO
import time

from utils import bcolors, pretty_print


DO_GLOBAL_LOGGING = False
DEBUG = True


TIMEOUT_ROUND_0 = 15
SERVER_STORAGE = {}

app = Flask(__name__)
sio = SocketIO(app, logger=DO_GLOBAL_LOGGING) # async_mode='eventlet'



##### Just for the PoC - Remove in the final product ###########################
@app.route('/server_storage')
def index():
    return render_template('display_server_storage.html', **SERVER_STORAGE)
################################################################################


@sio.on('connect')
def connect(): # also use request.environ???
    sio.emit('your sid', request.sid, room=request.sid) # We'll use the sid to identify client, we let them know who they are

@sio.on('disconnect')
def disconnect():
    pass
    # print('Bye', request.sid)


@sio.on('pubkeys')
def handle_pubkeys(data):

    if DEBUG:
        print(bcolors.YELLOW, 'receiving public keys from', request.sid, bcolors.ENDC)

    elapsed_time = time.time() - START_TIME

    if elapsed_time < TIMEOUT_ROUND_0:

        try:
            SERVER_STORAGE.setdefault(request.sid, {})['cpk'] = data['cpk']
        except KeyError:
            error_msg = 'sid=' + str(request.sid) + ': no key cpk.'
            if DEBUG:
                print(bcolors.RED, error_msg, bcolors.ENDC)
            return False, error_msg
        try:
            SERVER_STORAGE.setdefault(request.sid, {})['spk'] = data['spk']
        except KeyError:
            error_msg = 'sid=' + str(request.sid) + ': no key spk.'
            if DEBUG:
                print(bcolors.RED, error_msg, bcolors.ENDC)
            return False, error_msg

    else:
        error_msg = 'sid=' + str(request.sid) + ': too late to send public keys.'
        if DEBUG:
            print(bcolors.RED, error_msg, bcolors.ENDC)
        return False, error_msg  # If FALSE, make this node drop (disconnect()) in the client callback


    success_msg = 'sid=' + str(request.sid) + ': public keys succesfully stored.'
    if DEBUG:
        print(bcolors.GREEN, success_msg, bcolors.ENDC)
    return True, success_msg # acknowledgement message that everything went fine



def timer_round_0():
    if DEBUG:
        print(bcolors.BOLD, bcolors.YELLOW, 'Timer Starts', bcolors.ENDC)
    sio.sleep(TIMEOUT_ROUND_0)
    if DEBUG:
        print(bcolors.BOLD, bcolors.YELLOW, 'Timer Ends', bcolors.ENDC)


    n = len(SERVER_STORAGE.keys())
    if n < 3:
        print(bcolors.BOLD, bcolors.RED, 'Not enough clients. Aborting.', bcolors.ENDC)
        sio.emit('abort', 'not enough clients') # Broadcast to everyone that the server aborts --> should disconnect
        sio.stop()
        sio.sleep(1)

    if DEBUG:
        print(bcolors.YELLOW, 'Broadcasting list of pubkeys to clients.', bcolors.ENDC)

    list_pubkeys = {} # Copy here the cpk and spk keys for each client, don't send the WHOLE server storage dict
    for client_sid, storage_fod_client_sid in SERVER_STORAGE.items():
        try:
            list_pubkeys[client_sid] = {}
            list_pubkeys[client_sid]['cpk'] = storage_fod_client_sid['cpk']
            list_pubkeys[client_sid]['spk'] = storage_fod_client_sid['spk']
        except KeyError:
            print('No keys cpk or spk for client', client_sid)

    sio.emit('list pubkeys', list_pubkeys) # No callback because it's a broadcast message (room=/)

    # After some timeout??
    sio.start_background_task(construct_y)





@sio.on('list encrypted messages')
def handle_encrypted_messages(encrypted_messages):

    sending_client_sid = request.sid
    print(bcolors.GREEN, 'Received encrypted messages from', sending_client_sid, bcolors.ENDC)
    # pretty_print(encrypted_messages)
    # print()

    # TODO: Again, a timer for Round1

    # Forward messages to everyone else
    sio.start_background_task(forward_encrypted_messages, encrypted_messages)



    return True, 'Thanks for the list!'



def forward_encrypted_messages(encrypted_messages):

    for client_sid, enc_msg in encrypted_messages.items():
        # Send to each client the message encrypted for it
        sio.emit('enc msg', enc_msg, room=client_sid)




def construct_y():

    sio.sleep(5)

    print('\n\n==============')
    print('RECONSTRUCTION')
    print('==============\n\n')
    for client_sid in SERVER_STORAGE.keys():
        print('sid =', client_sid)
        print(SERVER_STORAGE[client_sid]['y'])
        print()


@sio.on('y')
def handle_y(y):

    sending_client_sid = request.sid
    print(bcolors.GREEN, 'Received masked input y from', sending_client_sid, bcolors.ENDC)
    print(y)
    print('{}{}{}{}{}{}{}{}{}{}{}{}')

    SERVER_STORAGE[sending_client_sid]['y'] = y

    return True, 'Merveilleux!'



sio.start_background_task(timer_round_0)



if __name__ == '__main__':
    START_TIME = time.time()
    sio.run(app, host='127.0.0.1', port=9876, debug=DO_GLOBAL_LOGGING)
