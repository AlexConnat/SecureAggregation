#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Ref: https://eprint.iacr.org/2015/267.pdf

from Crypto.Random.random import randint
from gmpy2 import invert


from rfc_3526_groups import RFC_3526_GROUPS
from AES_encryption import AESCipher

class OT_Sender:

    def __init__(self, value0, value1, groupID=14):
        self.g = RFC_3526_GROUPS[groupID][0]
        self.p = RFC_3526_GROUPS[groupID][1]
        self.value0 = value0
        self.value1 = value1
        self.a = randint(1, self.p - 1)

    def get_params(self):
        return self.g, self.p

    def generate_A(self):
        A = pow(self.g, self.a, self.p)
        self.A = A
        return A

    def generate_e0_e1(self, B):
        k0 = pow(B, self.a, self.p)
        k1 = pow(B*int(invert(self.A,self.p)), self.a, self.p)
        e0 = AESCipher(str(k0)).encrypt(self.value0)
        e1 = AESCipher(str(k1)).encrypt(self.value1)
        return (e0, e1)

class OT_Receiver:

    def __init__(self, selection_bit, groupID=14):
        self.g = RFC_3526_GROUPS[groupID][0]
        self.p = RFC_3526_GROUPS[groupID][1]
        assert selection_bit in [0,1]
        self.selection_bit = selection_bit # c
        self.b = randint(1, self.p - 1)

    def get_params(self):
        return self.g, self.p

    def generate_B(self, A):
        if self.selection_bit == 0:
            B = pow(self.g, self.b, self.p)
        else:
            B = (A * pow(self.g, self.b, self.p)) % self.p
        self.B = B
        self.kr = pow(A, self.b, self.p)
        return B

    def obtain_value(self, e0, e1):
        if self.selection_bit == 0:
            cipher = e0
        else:
            cipher = e1
        value = AESCipher(str(self.kr)).decrypt(cipher)
        return value


# https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
