#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Apr 05, 2021

@author: boscolau
"""

import binascii

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Hash import SHA512

### Global Constants ###
ENCODING = "utf-8"
DEFAULT_KEY_LENGTH = 32


def create_master_key(secret: str, a_salt: str, iterations: int, key_length: int = DEFAULT_KEY_LENGTH,
                      hash_module=SHA256) -> str:
    password = secret.encode(ENCODING)
    salt = a_salt.encode(ENCODING)
    keys = PBKDF2(password, salt, key_length, count=iterations, hmac_hash_module=hash_module)
    key = keys[:key_length]

    print(binascii.hexlify(key))

    master_key = binascii.hexlify(key).decode(ENCODING)
    print(master_key)
    return master_key


create_master_key("password", "0ED4AFF74B4C4EE3AD1CF95DDBAF62EE", 1000, 32, SHA256)
create_master_key("password", "0ED4AFF74B4C4EE3AD1CF95DDBAF62EE", 1000)
