#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from diffie_hellman import DHKE
from sharing import SecretSharer

DHKE = DHKE(groupID=666)

sk, pk = DHKE.generate_keys()

print(sk)
print('LENGTH:', len(str(sk)))

print()

shares = SecretSharer.split_secret(sk, 5, 6)
# for s in shares:
#     print('-', s)
#     print('LENGTH:', len(str(s)))
# print()

secretTrue = SecretSharer.recover_secret(shares[0:5])
print(secretTrue == sk)

secretFalse = SecretSharer.recover_secret(shares[0:4]) # not enough
print(secretFalse == sk)
