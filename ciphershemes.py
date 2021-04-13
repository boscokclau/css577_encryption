#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Apr 11, 2021

@author: boscolau
"""

from Crypto.Cipher import AES
from Crypto.Cipher import DES3

# Constants
BLOCK_SIZE_IN_BYTES = "block_size_in_bytes"
CIPHER = "cipher"
KEY_LENGTH_IN_BYTES = "key_length_in_bytes"
NAME = "name"

# Schemes and corresponding configurations
schemes = {
    "AES128WithSHA256": {NAME: "AES128WithSHA256", CIPHER: AES, KEY_LENGTH_IN_BYTES: 16, BLOCK_SIZE_IN_BYTES: 16},
    "AES128WithSHA512": {NAME: "AES128WithSHA512", CIPHER: AES, KEY_LENGTH_IN_BYTES: 16, BLOCK_SIZE_IN_BYTES: 16},

    "AES256WithSHA256": {NAME: "AES256WithSHA256", CIPHER: AES, KEY_LENGTH_IN_BYTES: 32, BLOCK_SIZE_IN_BYTES: 16},
    "AES256WithSHA512": {NAME: "AES256WithSHA512", CIPHER: AES, KEY_LENGTH_IN_BYTES: 32, BLOCK_SIZE_IN_BYTES: 16},

    "DES3WithSHA256": {NAME: "DES3WithSHA256", CIPHER: DES3, KEY_LENGTH_IN_BYTES: 24, BLOCK_SIZE_IN_BYTES: 8},
    "DES3WithSHA512": {NAME: "DES3WithSHA512", CIPHER: DES3, KEY_LENGTH_IN_BYTES: 24, BLOCK_SIZE_IN_BYTES: 8}
}

# Support Set
ciphers = ["AES128", "AES256", "3DES"]
hashes = ["SHA256", "SHA512"]


def get_cipher_scheme(cipher_name: str, hash_algorithm: str):
    cipher_name = cipher_name.upper()
    hash_algorithm = hash_algorithm.upper()

    # Check supports
    if cipher_name not in ciphers:
        raise ValueError("Cipher not supported: " + cipher_name)

    if hash_algorithm not in hashes:
        raise ValueError("Hash not supported: " + hash_algorithm)

    # Special treatment for 3DES
    if cipher_name == "3DES":
        cipher_name = "DES3"

    scheme_name = cipher_name + "With" + hash_algorithm

    return schemes[scheme_name]
