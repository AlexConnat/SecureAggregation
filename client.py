#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import secrets
import time

import numpy as np

import socketio

from secretsharing import SecretSharer
from diffie_hellman import DHKE


from utils import bcolors, pretty_print, int_to_hex, print_info, print_success, print_failure


#############################################################################################
# Handlers should be short (https://github.com/miguelgrinberg/Flask-SocketIO/issues/597)
# If big CPU work, use async_handlers = True, or just start_background_task
#############################################################################################


def server_ack(OK, msg):
    if OK:
        print_success(msg, CLIENT_VALUES['my_sid'])
    else:
        print_failure(msg, CLIENT_VALUES['my_sid'])
        sio.disconnect()

# @sio.on('your sid')
def set_sid(sid):
    print('My sid =', sid)
    CLIENT_VALUES['my_sid'] = sid

# @sio.on('connect')
def connect():
    pass

# @sio.on('disconnect')
def disconnect():
    pass

# @sio.on('abort')
def abort(reason):
    sio.disconnect()



############# ROUND 0 ###############
### GENERATE AND SEND PUBLIC KEYS ###
#####################################

def round0():

    # Generate the 2 pair of Diffie-Hellman keys
    # "s" will be used to generate the seed for the shared mask, and "c" the shared encryption key
    my_ssk, my_spk = DHKE.generate_keys()
    my_csk, my_cpk = DHKE.generate_keys()

    # Store the previously generated keys
    CLIENT_VALUES['my_ssk'] = my_ssk; CLIENT_VALUES['my_spk'] = my_spk
    CLIENT_VALUES['my_csk'] = my_csk; CLIENT_VALUES['my_cpk'] = my_cpk

    # Load the secret input "x". We want to aggregate a noisy version of x
    # The added noise will be generated later on
    CLIENT_VALUES['x'] = np.zeros(NB_CLASSES) # TODO: Load a REAL votes array!
    CLIENT_VALUES['x'][int(time.time()) % NB_CLASSES] = 1 # one-hot-encoded vector
    print('My secret x =', CLIENT_VALUES['x'])

    # Send the client's public key for "c" and "s" to the server
    print_info('Sending pubkeys to server...', CLIENT_VALUES['my_sid'])
    sio.emit('pubkeys', {'cpk':my_cpk, 'spk':my_spk}, callback=server_ack)



############### ROUND 1 ##################
###   RECEIVE PUBKEYS FROM EVERYONE,   ###
### GENERATE AND SEND ENCRYPTED SHARES ###
##########################################

def round1_handler(pubkeys):
    print()
    print_success('Received public keys from server...', CLIENT_VALUES['my_sid'])
    sio.start_background_task(round1, pubkeys)

def round1(pubkeys):

    # Store the keys received from the server, in the dictionary CLIENT_STORAGE, for each client_sid
    for client_sid, pubkeys_for_client_sid in pubkeys.items():
        try:
            CLIENT_STORAGE.setdefault(client_sid, {})['cpk'] = pubkeys_for_client_sid['cpk']
            CLIENT_STORAGE.setdefault(client_sid, {})['spk'] = pubkeys_for_client_sid['spk']
        except KeyError:
            print_failure('Missing key cpk or spk in server''s messsage.', request.sid)
            sio.disconnect()

    # Compute n, the number of active clients
    n = len(CLIENT_STORAGE.keys())                                                               #; print('n =', n)

    # Compute t, the minimum number of clients we need for the aggregation
    t = int(n/2) + 1                                                                             #; print('t =', t)

    # Draw random seed a, and make a gaussian noise mask out of it
    a = secrets.randbits(32)                                                                     #; print('a =', a) # TODO: Chose higher entropy
    np.random.seed(a)
    a_noise_vector = np.random.normal(0, float(SIGMA)/float(t), NB_CLASSES)                        #; print('a_noise_vector =', a_noise_vector)

    # Draw random seed b, and make a mask out of it
    b = secrets.randbits(32)                                                                    #; print('b =', b)
    np.random.seed(b)
    b_mask = np.random.uniform(-10, 10, NB_CLASSES)                                             #; print('b_mask =', b_mask) # TODO: HOW TO CHOOSE THOSE VALUES???

    # Create t-out-of-n shares for my private key my_ssk (as an hex_string)
    shares_my_ssk = SecretSharer.split_secret(int_to_hex(CLIENT_VALUES['my_ssk']), t, n)        #; print('shares_my_ssk =', shares_my_ssk)  # TODO don't use hex strings??? Too short

    # Create t-out-of-n shares for seed a
    shares_a = SecretSharer.split_secret(int_to_hex(a), t, n)                                   #; print('shares_a =', shares_a) # TODO: Shares size should'nt leak

    # Create t-out-of-n shares for seed b
    shares_b = SecretSharer.split_secret(int_to_hex(b), t, n)                                   #; print('shares_b =', shares_b)


    # Store all the previously generated values, in client's dictionary
    CLIENT_VALUES['n'] = n; CLIENT_VALUES['t'] = t

    CLIENT_VALUES['a'] = a; CLIENT_VALUES['a_noise'] = a_noise_vector
    CLIENT_VALUES['b'] = b; CLIENT_VALUES['b_mask'] = b_mask

    CLIENT_VALUES['shares_my_ssk'] = shares_my_ssk
    CLIENT_VALUES['shares_a'] = shares_a
    CLIENT_VALUES['shares_b'] = shares_b


    list_encrypted_messages = {}
    # print('-------------------------')
    for ID, client_sid in enumerate(CLIENT_STORAGE.keys()):

        if client_sid == CLIENT_VALUES['my_sid']:
            continue # Skip my own sid

        # print(ID, 'For Client', client_sid)

        # Derive encryption key enc_key_for_sid (via Diffie-Hellman Agreement)
        enc_key_for_sid = DHKE.agree(CLIENT_VALUES['my_csk'], CLIENT_STORAGE[client_sid]['cpk'])             #; print('enc_key_for_sid =', enc_key_for_sid)

        # Client "client_sid" will be sent this message:
        msg = 'ProtoV1.0' + ' || ' + str(CLIENT_VALUES['my_sid']) + ' || ' + str(client_sid) + ' || ' + str(shares_my_ssk[ID]) + ' || ' + str(shares_a[ID]) + ' || ' + str(shares_b[ID])

        # Encrypt the message with the pre-derived shared encryption key
        # enc_msg = Encrypt(enc_key_for_sid, msg) # TODO: Encrypt

        # Store the encrypted messages in a dictionary (keyed by client_sid) that will be sent to the server
        list_encrypted_messages[client_sid] = msg # TODO: Only send encrypted messages


        CLIENT_STORAGE[client_sid]['enc_key'] = enc_key_for_sid
        CLIENT_STORAGE[client_sid]['msg'] = msg
        # CLIENT_STORAGE[client_sid]['enc_msg'] = enc_mask

        # print('-------------------------')

    print_info('Sending list of encrypted messages to server...', CLIENT_VALUES['my_sid'])
    sio.emit('list encrypted messages', list_encrypted_messages, callback=server_ack)



########### ROUND 2 ##############
### MASK AND SEND INPUT VECTOR ###
##################################

def round2_handler(enc_msgs):
    print()
    print_success('Received list of encrypted messages for me from server...', CLIENT_VALUES['my_sid'])
    sio.start_background_task(round2, enc_msgs)
    # return True, 'List of encrypted messages succesfully received by client.', CLIENT_VALUES['my_sid'] # TODO: Acknowledgement is confusing in the logs

def round2(enc_msgs):

    for client_sid, enc_msg in enc_msgs.items():

        msg = enc_msg # TODO: Add Decryption function

        msg_parts = msg.split(' || ')

        protocol_id = msg_parts[0] # TODO: What's the use?
        from_client_sid = msg_parts[1]
        my_sid = msg_parts[2]
        share_ssk_for_sid = msg_parts[3]
        share_a_for_sid = msg_parts[4]
        share_b_for_sid = msg_parts[5]

        # Store has been received for client_sid
        CLIENT_STORAGE[from_client_sid]['share_ssk'] = share_ssk_for_sid
        CLIENT_STORAGE[from_client_sid]['share_a'] = share_a_for_sid
        CLIENT_STORAGE[from_client_sid]['share_b'] = share_b_for_sid

        # Sanity check
        if client_sid != from_client_sid or my_sid != CLIENT_VALUES['my_sid']:
            print_failure('Received wrong message!', CLIENT_VALUES['my_sid'])
            sio.disconnect()

        # Derive secret shared mask seed s_for_sid (Diffie-Hellman Agreement)
        s_for_sid = DHKE.agree(CLIENT_VALUES['my_ssk'], CLIENT_STORAGE[client_sid]['spk'])         #; print('s_for_sid =', s_for_sid)

        # Derive s_mask from above seed
        np.random.seed(s_for_sid)
        s_mask_for_sid = np.random.uniform(-100, 100, NB_CLASSES)                                  #; print('s_for_sid =', s_for_sid )# TODO: Which values??

        # Store also that
        CLIENT_STORAGE[client_sid]['s'] = s_for_sid
        CLIENT_STORAGE[client_sid]['s_mask'] = s_mask_for_sid


    # Construct masked input:
    # First the noisy input (the one that the server will aggregate)
    noisy_x = CLIENT_VALUES['x'] + CLIENT_VALUES['a_noise']

    # Then, add the individual mask
    yy = noisy_x + CLIENT_VALUES['b_mask']

    # Finally, add shared mask for every client SIDs smaller than yours, or substract it for client SIDs greater than yours
    all_masks = np.zeros(NB_CLASSES)
    for client_sid in CLIENT_STORAGE.keys():
        if client_sid == CLIENT_VALUES['my_sid']:
            continue # Skip my own SID
        if not 's_mask' in CLIENT_STORAGE[client_sid].keys():
            continue # We did not receive shared mask from this client SID
        if CLIENT_VALUES['my_sid'] > client_sid:
            all_masks += CLIENT_STORAGE[client_sid]['s_mask'] # Add the mask of smaller client SIDs
        else:
            all_masks -= CLIENT_STORAGE[client_sid]['s_mask'] # Substract the mask of greater client SIDs

    # Here is the final output "y" to send to server
    y = yy + all_masks

    print_info('Sending masked input "y" to server...', CLIENT_VALUES['my_sid'])
    sio.emit('y', list(y), callback=server_ack) # Send "y" as a python list because numpy arrays are not JSON-serializable



def round3_handler(data):
    print()
    pass
    # sio.start_background_task(round3, data)

def round3(data):
    pass



###############################
## BIG UNKNOWN CONSTANTS TBD ##
###############################
SIGMA = 40
NB_CLASSES = 5
###############################


if __name__ == '__main__':

    # This dictionary will contain all the values generated by this client
    # and used in the aggregation
    global CLIENT_VALUES
    CLIENT_VALUES = {}

    # This dictionary will contain all the values about the OTHER clients
    # part of the aggregation. It is keyed by client_sid.
    global CLIENT_STORAGE
    CLIENT_STORAGE = {}

    # The params of the group
    global DHKE
    DHKE = DHKE(groupID=666) # TODO: Use 2048-bit group (id=14) or above

    # The socketIO object representing our client's socket.
    # We can register listeners ('handlers') of events with the function sio.on(<event name>, <handler function>)
    sio = socketio.Client()

    # Connect this client to the server. Upon connection, this client receives a unique socket id "my_sid"
    # that we store in the CLIENT_VALUES, initially None, set in the function decorated by @sio.on('your sid')
    CLIENT_VALUES['my_sid'] = None
    sio.on('your sid', set_sid)
    sio.connect('http://127.0.0.1:9876')
    sio.sleep(1)

    # "connect" and "disconnect" are 2 special events generated by socketIO upon socket creation
    # and destruction. "abort" is a custom event that we created upon server stopping.
    sio.on('connect', connect)
    sio.on('disconnect', disconnect)
    sio.on('abort', abort)


    ############# ROUND 0 ###############
    ### GENERATE AND SEND PUBLIC KEYS ###
    #####################################
    round0()

    ############### ROUND 1 ##################
    ###   RECEIVE PUBKEYS FROM EVERYONE,   ###
    ### GENERATE AND SEND ENCRYPTED SHARES ###
    ##########################################
    sio.on('round1', round1_handler)

    ########### ROUND 2 ##############
    ### MASK AND SEND INPUT VECTOR ###
    ##################################
    sio.on('round2', round2_handler)

    ################ ROUND 3 ##################
    ### SEND MASKS (AND POTENTIALLY SHARES) ###
    ###########################################
    sio.on('round3', round3_handler)
