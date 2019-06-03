#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from diffie_hellman import DHKE
from sharing import SecretSharer

DHKE = DHKE(groupID=666)

# sk, pk = DHKE.generate_keys()
#
# print(sk)
# print('LENGTH:', len(str(sk)))
#
# print()
#
# shares = SecretSharer.split_secret(sk, 5, 6)
# # for s in shares:
# #     print('-', s)
# #     print('LENGTH:', len(str(s)))
# # print()
#
# secretTrue = SecretSharer.recover_secret(shares[0:5])
# print(secretTrue == sk)
#
# secretFalse = SecretSharer.recover_secret(shares[0:4]) # not enough
# print(secretFalse == sk)

sk1, pk1 = DHKE.generate_keys()
sk2, pk2 = DHKE.generate_keys()

shared_key = DHKE.agree(sk1, pk2)
shared_key2 = DHKE.agree(sk2, pk1)

assert shared_key == shared_key2


# Use KDF to generate AES key
