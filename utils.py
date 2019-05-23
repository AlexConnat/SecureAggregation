#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class bcolors:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def pretty_print(d, indent=0):
    for key, value in d.items():
        print('\t' * indent + str(key) + ':')
        if isinstance(value, dict):
            pretty_print(value, indent+1)
        else:
            print('\t' * (indent+1) + str(value))

# From int to hex string
def int_to_hex(i):
    return '{:02x}'.format(i)

# From hex string to int
def hex_to_int(s):
    return int(s, 16)
