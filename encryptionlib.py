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
DEFAULT_ITERATIONS = 1000

### Check hash_module support
SUPPORTED_HASH_MODULE = {SHA256: 32, SHA512: 64}

### Debugging switch ###
DEBUG = True


def create_master_key(secret: str, salt: str, iterations: int, hash_module=SHA256) -> str:
    """
        Return a master key derived from secret with parameters specified. Internally, it is using PBKDF2 from Cryptodome.
    :param secret: The secret from which the returning key is derived.
    :param a_salt: Salt used to derive the key
    :param iterations: Number of iterations. Default to 1000
    :param key_length: Key length to create. Default to 32
    :param hash_module: Hash algorithm to use. Default to SHA256 (in Crypto.Hash from Cryptodome)
    :return:
    """
    if hash_module not in SUPPORTED_HASH_MODULE:
        raise ValueError("Unsupported hashing algorithm.")

    key_length = SUPPORTED_HASH_MODULE[hash_module]
    keys = PBKDF2(secret, salt, key_length, count=iterations, hmac_hash_module=hash_module)
    key = keys[:key_length]

    master_key = binascii.hexlify(key).decode()

    if DEBUG:
        print(binascii.hexlify(key))
        print(master_key)

    return master_key


create_master_key("password", "0ED4AFF74B4C4EE3AD1CF95DDBAF62EE", 1000, SHA256)
create_master_key("password", "0ED4AFF74B4C4EE3AD1CF95DDBAF62EE", 1000)
