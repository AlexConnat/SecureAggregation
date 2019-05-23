#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random


import socketio

from utils import bcolors, pretty_print


CLIENT_STORAGE = {}


def server_ack(OK, msg):
    if OK:
        print(bcolors.GREEN, msg, bcolors.ENDC)
    else:
        print(bcolors.RED, msg, bcolors.ENDC)
        sio.disconnect()


def store_keys(pubkeys):
    print('Storing the keys...')
    for client_sid, pubkeys_for_client_sid in pubkeys.items():
        try:
            CLIENT_STORAGE.setdefault(client_sid, {})['cpk'] = pubkeys_for_client_sid['cpk']
            CLIENT_STORAGE.setdefault(client_sid, {})['spk'] = pubkeys_for_client_sid['spk']
        except KeyError:
            print('Missing key cpk or spk for client', client_sid)

    sio.start_background_task(compute_round_1) # Background task or normal function?



def compute_round_1():

    # Compute n
    n = len(CLIENT_STORAGE.keys())

    # Compute t
    t = int(n/2) + 1

    # Draw random seed a, and make a gaussian noise mask out of it
    a = random.randint(0, 100000)
    a_noise_mask = np.random.normal(t, k)

    # Draw random seed b, and make a mask out of it
    b = random.randint(0, 100000)
    b_mask = PRNG(k)

    # Create t-out-of-n shares for my private key my_ssk
    shares_my_ssk = CreateShares(my_ssk, t, n)

    # Create t-out-of-n shares for seed a
    shares_a = CreateShares(a, t, n)

    # Create t-out-of-n shares for seed b
    shares_b = CreateShares(b, t, n)

    # For each client "client_sid"
    for ID, client_sid in enumerate(CLIENT_STORAGE.keys()):

        # Derive encryption key enc_key_for_sid
        enc_key_for_sid = DHAgree(my_csk, CLIENT_STORAGE[client_sid]['cpk'])

        ####### DO IT HERE???? ############
        # Derive secret mask s_mask_for_sid
        s_mask_for_sid = DHAgree(my_ssk, CLIENT_STORAGE[client_sid]['spk'])    #s_masks[v] = s_mask_v  # in a big list?
        ###################################

        # Client "client_sid" will be sent this message:
        msg = protocol_version || my_sid || client_sid || shares_my_ssk[ID] || a || b
        enc_msg = Encrypt(enc_key_for_sid, msg)





sio = socketio.Client()

# Receive the list of every client's public keys from the server
@sio.on('list pubkeys')
def handle_list_pubkeys(pubkeys):
    print('Receiving public keys from server...')
    # Handlers should be short (https://github.com/miguelgrinberg/Flask-SocketIO/issues/597)
    # If big CPU work, use async_handlers = True, or just start_background_task
    sio.start_background_task(store_keys, pubkeys)
    sio.disconnect()


sio.connect('http://127.0.0.1:9876')


# Send the client's public key for c and s to the server
sio.emit('pubkeys', {'cpk':random.randint(0,1000), 'spk':random.randint(1000,2000)}, callback=server_ack) # Print the sid + real HTTP request it's sending



sio.wait()

sio.disconnect()
