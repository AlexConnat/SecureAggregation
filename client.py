#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import secrets

import numpy as np

import socketio

from secretsharing import SecretSharer
from diffie_hellman import DHKE


from utils import bcolors, pretty_print, int_to_hex


###############################
## BIG UNKNOWN CONSTANTS TBD ##
###############################
SIGMA = 40
NB_CLASSES = 5
###############################


sio = socketio.Client()
my_sid = None    # On connect, server will emmit('your sid') -> sid will be caught and set
                 # in the function "@sio.on('your sid') --> i_will_have_a_name(sid):"

@sio.on('your sid')
def i_will_have_a_name(sid):
    print('My sid =', sid)
    global my_sid # set it globally
    my_sid = sid

# Receive the list of every client's public keys from the server  # TODO: Order matters! (before everything)
@sio.on('list pubkeys')
def handle_list_pubkeys(pubkeys):
    print('Receiving public keys from server...')
    # Handlers should be short (https://github.com/miguelgrinberg/Flask-SocketIO/issues/597)
    # If big CPU work, use async_handlers = True, or just start_background_task
    sio.start_background_task(store_keys, pubkeys)
    sio.disconnect()

@sio.on('abort')
def abort(reason):
    sio.disconnect()



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

    pretty_print(CLIENT_STORAGE)
    print()
    sio.start_background_task(compute_round_1) # Background task or normal function?



def compute_round_1():

    # Compute n
    n = len(CLIENT_STORAGE.keys())                                               ; print('n =', n)

    # Compute t
    t = int(n/2) + 1                                                             ; print('t =', t)

    # Draw random seed a, and make a gaussian noise mask out of it
    a = secrets.randbits(32)                                                     ; print('a =', a) # TODO: Chose higher entropy
    np.random.seed(a)
    a_noise_mask = np.random.normal(0, float(SIGMA)/float(t), NB_CLASSES)        ; print('a_noise_mask =', a_noise_mask)

    # Draw random seed b, and make a mask out of it
    b = secrets.randbits(32)                                                     ; print('b =', b)
    np.random.seed(b)
    b_mask = np.random.uniform(-10, 10, NB_CLASSES)                              ; print('b_mask =', b_mask) # TODO: HOW TO CHOOSE THOSE VALUES???

    # Create t-out-of-n shares for my private key my_ssk (as an hex_string)
    print('my_ssk =', my_ssk)
    print('type(my_ssk) =', type(my_ssk))
    shares_my_ssk = SecretSharer.split_secret(int_to_hex(my_ssk), t, n)          ; print('shares_my_ssk =', shares_my_ssk)

    # Create t-out-of-n shares for seed a
    shares_a = SecretSharer.split_secret(int_to_hex(a), t, n)                    ; print('shares_a =', shares_a) # TODO: Shares size should'nt leak

    # Create t-out-of-n shares for seed b
    shares_b = SecretSharer.split_secret(int_to_hex(b), t, n)                    ; print('shares_b =', shares_b)

    print('-------------------------')
    # For each client "client_sid"
    for ID, client_sid in enumerate(CLIENT_STORAGE.keys()):

        if client_sid == my_sid:
            continue # Skip my own sid

        # print(ID, 'For Client', client_sid)
        # Derive encryption key enc_key_for_sid (Diffie-Hellman Agreement)
        # enc_key_for_sid = my_csk.update(CLIENT_STORAGE[client_sid]['cpk'])

        ####### DO IT HERE???? ############
        # Derive secret shared mask s_mask_for_sid (Diffie-Hellman Agreement)
        s_mask_shared = DHKE.agree(my_ssk, CLIENT_STORAGE[client_sid]['spk'])    #s_masks[v] = s_mask_v  # in a big list?
        print('client_sid =', client_sid)
        print('s_mask_shared =', s_mask_shared)
        ###################################

        # Client "client_sid" will be sent this message:
        # msg = protocol_version || my_sid || client_sid || shares_my_ssk[ID] || a || b
        # enc_msg = Encrypt(enc_key_for_sid, msg)
        print('-------------------------')



if __name__ == '__main__':

    sio.connect('http://127.0.0.1:9876')

    # TODO: Use a more "profesional" library
    DHKE = DHKE(groupID=666) # TODO: Use 2048-bit group (id=14) or above
    my_ssk, my_spk = DHKE.generate_keys()
    my_csk, my_cpk = DHKE.generate_keys()


    # Send the client's public key for c and s to the server
    sio.emit('pubkeys', {'cpk':my_cpk, 'spk':my_spk}, callback=server_ack) # Print the sid + real HTTP request it's sending

    sio.wait()

    sio.disconnect()
