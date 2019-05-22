#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random



import socketio

from utils import bcolors

def server_ack(OK, msg):
    if OK:
        print(bcolors.GREEN, msg, bcolors.ENDC)
    else:
        print(bcolors.RED, msg, bcolors.ENDC)
        sio.disconnect()


sio = socketio.Client()


# Receive the list of every client's public keys from the server
@sio.on('list pubkeys')
def handle_list_pubkeys(pubkeys):
    print('Receiving public keys from server...')
    print(pubkeys)
    sio.disconnect()





sio.connect('http://127.0.0.1:9876')


# Send the client's public key for c and s to the server
sio.emit('pubkeys', {'cu_pk':random.randint(0,1000), 'su_pk':random.randint(1000,2000)}, callback=server_ack) # Print the sid + real HTTP request it's sending



sio.wait()

sio.disconnect()
