#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Apr 05, 2021

@author: boscolau
"""

import binascii

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Hash import SHA512
from time import time

### Global Constants ###
DEFAULT_ITERATIONS = 1000

### Check hash_module support
SUPPORTED_HASH_MODULE = {SHA256: 32, SHA512: 64}

### Debugging switch ###
DEBUG = True


def timing(f):
    def wrapper(*args, **kwargs):
        start = time()
        result = f(*args, **kwargs)
        end = time()
        print("Time spent =", end - start)
        print("Throughput = ", 1 / (end - start))
        return result

    return wrapper


@timing
def create_key(secret: str, salt: str, iterations: int, hash_module=SHA256) -> str:
    """
        Return a master key derived from secret with parameters specified. Internally, it is using PBKDF2 from Cryptodome.
    :param secret: The secret from which the returning key is derived.
    :param salt: Salt used to derive the key
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

    key = binascii.hexlify(key).decode()

    if DEBUG:
        print(key)

    return key


def pad_message(base: bytes, block_length: int, padding: bytes):
    while len(base) % block_length != 0:
        base += padding
    return base


print("SHA256")
print("Master Key")
key_master = create_key("password", "0ED4AFF74B4C4EE3AD1CF95DDBAF62EE", 1000, SHA256)

print("Encryption Key")
key_encryption = create_key(key_master, "Encryption Key", 1, SHA256)

print("HMAC Key")
key_hmac = create_key(key_master, "HMAC Key", 1, SHA256)

print("---------------------------------------------")
print("Encrypt/Decrypt... key size =", len(key_encryption))
cipher = AES.new(binascii.unhexlify(key_encryption), AES.MODE_CBC, b"This is an IV456")

with open("ProdComp.xlsx", "rb") as f:
    file_to_encrypt = f.read()

padded_file = pad_message(file_to_encrypt, 16, b"0")
encrypted_file = cipher.encrypt(padded_file)

with open("ProdComp.xlsx.enc", "wb") as ef:
    ef.write(encrypted_file)

with open("ProdComp.xlsx.enc", "rb") as f2d:
    file_to_decrypt = f2d.read()

cipher = AES.new(binascii.unhexlify(key_encryption), AES.MODE_CBC, b"This is an IV456")
decrypted_file = cipher.decrypt(file_to_decrypt)

with open("ProdComp_decrypted.xlsx", "wb") as df:
    df.write(decrypted_file.rstrip(b"0"))
