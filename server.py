#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request
from flask_socketio import SocketIO
import time

from utils import bcolors


DO_GLOBAL_LOGGING = False
DEBUG = True


TIMEOUT_ROUND_0 = 10
SERVER_STORAGE = {}

app = Flask(__name__)
sio = SocketIO(app, logger=DO_GLOBAL_LOGGING)

##### Just for the PoC - Remove in the final product ###########################
@app.route('/server_storage')
def index():
    return render_template('display_server_storage.html', **SERVER_STORAGE)
################################################################################


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


sio.start_background_task(timer_round_0)



if __name__ == '__main__':
    START_TIME = time.time()
    sio.run(app, host='127.0.0.1', port=9876, debug=DO_GLOBAL_LOGGING)
