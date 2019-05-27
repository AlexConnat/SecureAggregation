#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from diffie_hellman import DHKE
from sharing import SecretSharer

DHKE = DHKE(groupID=14)

sk, pk = DHKE.generate_keys()

print(sk)
print('LENGTH:', len(str(sk)))

print()

parts = SecretSharer.split_secret(sk, 5, 6)
for p in parts:
    print('-', p)
    print('LENGTH:', len(str(p)))

print()

secretTrue = SecretSharer.recover_secret(parts[0:5])
print(secretTrue == sk)

print()
secretFalse = SecretSharer.recover_secret(parts[0:4]) # not enough
print(secretFalse == sk)
