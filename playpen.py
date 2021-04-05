#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Apr 04, 2021

@author: boscolau

https://neurotechnics.com/tools/pbkdf2-test

"""

import binascii

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

password = b'password'
salt = b'0ED4AFF74B4C4EE3AD1CF95DDBAF62EE'
keys = PBKDF2(password, salt, 32, count=1000, hmac_hash_module=SHA256)
key1 = keys[:32]


print(binascii.hexlify(key1))