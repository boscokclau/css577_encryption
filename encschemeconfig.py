#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Apr 11, 2021

@author: boscolau

This module contains meta-data given a cipher and a hmac-sha scheme.
"""

# Constants
BLOCK_SIZE_IN_BYTES = "block_size_in_bytes"
CIPHER = "cipher"
KEY_LENGTH_IN_BYTES = "key_length_in_bytes"
NAME = "name"

# Schemes and corresponding configurations
schemes = {
    "AES128WithSHA256": {NAME: "AES128WithSHA256", KEY_LENGTH_IN_BYTES: 16, BLOCK_SIZE_IN_BYTES: 16},
    "AES128WithSHA512": {NAME: "AES128WithSHA512", KEY_LENGTH_IN_BYTES: 16, BLOCK_SIZE_IN_BYTES: 16},

    "AES256WithSHA256": {NAME: "AES256WithSHA256", KEY_LENGTH_IN_BYTES: 32, BLOCK_SIZE_IN_BYTES: 16},
    "AES256WithSHA512": {NAME: "AES256WithSHA512", KEY_LENGTH_IN_BYTES: 32, BLOCK_SIZE_IN_BYTES: 16},

    "3DESWithSHA256": {NAME: "3DESWithSHA256", KEY_LENGTH_IN_BYTES: 24, BLOCK_SIZE_IN_BYTES: 8},
    "3DESWithSHA512": {NAME: "3DESWithSHA512", KEY_LENGTH_IN_BYTES: 24, BLOCK_SIZE_IN_BYTES: 8}
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

    scheme_name = cipher_name + "With" + hash_algorithm

    return schemes[scheme_name]
