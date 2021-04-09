#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Apr 05, 2021

@author: boscolau
"""

import binascii

from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Hash import SHA512
from time import time

### Global Constants ###
DEFAULT_ITERATIONS = 1000
PASSWORD = "password"
SALT_MASTER_KEY = "0ED4AFF74B4C4EE3AD1CF95DDBAF62EE"
SALT_ENCRYPTION_KEY = "encryption key"
SALT_HMAC_KEY = "hmac key"
NON_AUTOGEN_IV = None

### Cipher Suites
CIPHER = "cipher"
KEY_LENGTH_IN_BYTES = "key_length_in_bytes"
HASH_ALGORITHM = "hash_algorithm"
NAME = "NAME"

AES128WithSHA256 = {NAME: "AES128WithSHA256", CIPHER: AES, KEY_LENGTH_IN_BYTES: 16, HASH_ALGORITHM: SHA256}
AES128WithSHA512 = {NAME: "AES128WithSHA512", CIPHER: AES, KEY_LENGTH_IN_BYTES: 16, HASH_ALGORITHM: SHA512}

AES256WithSHA256 = {NAME: "AES256WithSHA256", CIPHER: AES, KEY_LENGTH_IN_BYTES: 32, HASH_ALGORITHM: SHA256}
AES256WithSHA512 = {NAME: "AES256WithSHA512", CIPHER: AES, KEY_LENGTH_IN_BYTES: 32, HASH_ALGORITHM: SHA512}

DES3WithSHA256 = {NAME: "DES3WithSHA256", CIPHER: AES, KEY_LENGTH_IN_BYTES: 24, HASH_ALGORITHM: SHA256}
DES3WithSHA512 = {NAME: "DES3WithSHA512", CIPHER: AES, KEY_LENGTH_IN_BYTES: 24, HASH_ALGORITHM: SHA256}

### Operation configurations
CIPHER = AES
OP_MODE = CIPHER.MODE_CBC
SCHEME = AES128WithSHA512

### Check hash_module support
SUPPORTED_HASH_MODULE = [SHA256, SHA512, DES3]

### Debugging switch ###
DEBUG = True


def timing(fn):
    def wrapper(*args, **kwargs):
        start = time()
        result = fn(*args, **kwargs)
        end = time()
        print("Time spent =", end - start)
        print("Throughput = ", 1 / (end - start))
        return result

    return wrapper


@timing
def create_key(secret: str, salt: str, iterations: int, key_length: int = DEFAULT_ITERATIONS,
               hash_module=SHA256) -> str:
    """
        Return a master key derived from secret with parameters specified. Internally, it is using PBKDF2 from Cryptodome.

    :param secret: The secret from which the returning key is derived.
    :param salt: Salt used to derive the key
    :param iterations: Number of iterations
    :param key_length:
    :param hash_module:
    :return:
    """

    if hash_module not in SUPPORTED_HASH_MODULE:
        raise ValueError("Unsupported hashing algorithm.")

    keys = PBKDF2(secret, salt.encode(), key_length, count=iterations, hmac_hash_module=hash_module)
    key = keys[:key_length]

    key_decoded = binascii.hexlify(key).decode()

    if DEBUG:
        # print("keys", keys, "|", len(keys))
        print("key_length configured:", key_length)
        print("key: ", key, "|", len(key))
        print("key_decoded: ", key_decoded, "|", len(key_decoded) * 4, "bits")

    return key_decoded


def pad_message(base: bytes, block_length: int, padding: bytes):
    while len(base) % block_length != 0:
        base += padding
    return base


print("Master Key with ", SCHEME[NAME])
scheme_key_length = SCHEME[KEY_LENGTH_IN_BYTES]
hash_algorithm = SCHEME[HASH_ALGORITHM]

key_master = create_key(PASSWORD, SALT_MASTER_KEY, DEFAULT_ITERATIONS, scheme_key_length, hash_algorithm)
print("key_master:", key_master, "|", len(key_master) * 4, "bits")
print()

print("Encryption Key")
key_encryption = create_key(key_master, SALT_ENCRYPTION_KEY, 1, scheme_key_length, hash_algorithm)
print("key_encryption:", key_encryption, "|", len(key_encryption) * 4, "bits")
print()

print("HMAC Key")
key_hmac = create_key(key_master, SALT_HMAC_KEY, 1, scheme_key_length, hash_algorithm)
print("key_hmac:", key_hmac, "|", len(key_hmac) * 4, "bits")
print()

print("---------------------------------------------")
print("Encrypt/Decrypt... key size =", len(key_encryption))
cipher = CIPHER.new(key=binascii.unhexlify(key_encryption), mode=OP_MODE, iv=NON_AUTOGEN_IV)

# Generated IV
iv = cipher.iv
print("cipher.iv", "|", cipher.iv, "|", binascii.hexlify(cipher.iv), binascii.hexlify(cipher.iv).decode())
print("iv to record:", iv)

print("iv length:", len(iv))

with open("ProdComp.xlsx", "rb") as f:
    file_to_encrypt = f.read()

padded_file = pad_message(file_to_encrypt, 16, b"0")
encrypted_file = cipher.encrypt(padded_file)
print("Encrypted file BEFORE prepending IV:\n", encrypted_file)
encrypted_file_with_iv = iv + encrypted_file
print("Encrypted file AFTER prepending IV:\n", encrypted_file_with_iv)

print("---------------------------------------------")
print("Extract IV")
cipher_block_size = CIPHER.block_size
iv_extracted = encrypted_file[:cipher_block_size]
print("iv_extracted:", iv_extracted)

print("---------------------------------------------")
print("HMAC to cover IV and encrypted value")
hmac = HMAC.HMAC(binascii.unhexlify(key_hmac), encrypted_file_with_iv, hash_algorithm)
print(hmac.digest(), "| len =", len(hmac.digest()))

encrypted_file_with_iv_hmac = hmac.digest() + encrypted_file_with_iv
print("encrypted_file_with_iv_hmac:\n")
print(encrypted_file_with_iv_hmac)

print("---------------------------------------------")
print("Extract hmac")
hmac_extracted = encrypted_file_with_iv_hmac[:hash_algorithm.digest_size]
print("hmac_extracted:", hmac_extracted)

print("iv + file:")
iv_plus_file = encrypted_file_with_iv_hmac[hash_algorithm.digest_size:]
print(iv_plus_file)
print("iv_plus_file == encrypted_file_with_iv:", iv_plus_file == encrypted_file_with_iv)

print("Removing IV")
iv_removed = encrypted_file_with_iv_hmac[hash_algorithm.digest_size: (hash_algorithm.digest_size + cipher_block_size)]
print("iv_removed:", iv_removed)
print("iv_removed == iv:", iv_removed == iv)

print("File only")
file_only = encrypted_file_with_iv_hmac[(hash_algorithm.digest_size + cipher_block_size):]
print("file_only:")
print(file_only)
print("file_only == encrypted_file:", file_only == encrypted_file)

print("---------------------------------------------")
print("Encrypt/decrypt")
cipher_text = encrypted_file_with_iv_hmac

with open("ProdComp.xlsx.enc", "wb") as ef:
    ef.write(cipher_text)

with open("ProdComp.xlsx.enc", "rb") as f2d:
    cipher_to_decrypt = f2d.read()

print("Retrieved:", cipher_to_decrypt == encrypted_file_with_iv_hmac)
print("Read from file:", cipher_to_decrypt)
print("      Original:", encrypted_file_with_iv_hmac)

print()
d_hmac = cipher_to_decrypt[:hash_algorithm.digest_size]
print("d_hmac:", d_hmac)
print("  hmac:", hmac.digest())
print("d_hmac == hmac.digest():", d_hmac == hmac.digest())

print()
d_iv = cipher_to_decrypt[SCHEME[HASH_ALGORITHM].digest_size: (hash_algorithm.digest_size + cipher_block_size)]
print("d_iv:", d_iv)
print("  iv:", iv)
print("d_iv == iv:", d_iv == iv)

print()
file_to_decrypt = cipher_to_decrypt[(hash_algorithm.digest_size + cipher_block_size):]
print("file_to_decrypt:", file_to_decrypt)
print("       Original:", encrypted_file)
print("file_to_decrypt == encrypted_file", file_to_decrypt == encrypted_file)

print()
print("Cipher text in encrypted file--open file in text editor to compare:")
print(binascii.hexlify(cipher_text))

print()
print("---------------------------------------------")
print("POC Decryption Starts")
d_salt_master = SALT_MASTER_KEY
d_salt_decryption = SALT_ENCRYPTION_KEY
d_salt_hmac = SALT_HMAC_KEY
d_hash_module = hash_algorithm
d_iterations = DEFAULT_ITERATIONS
d_key_length = scheme_key_length
d_mode = OP_MODE

d_master_key = create_key(PASSWORD, d_salt_master, d_iterations, d_key_length, d_hash_module)
print("d_master_key:", d_master_key)
print("e master_key:", key_master)
print()

d_decryption_key = create_key(d_master_key, d_salt_decryption, 1, d_key_length, d_hash_module)
print("d_decryption_key:", d_decryption_key)
print("e encryption key:", key_encryption)
print()

d_hmac_key = create_key(key_master, d_salt_hmac, 1, d_key_length, d_hash_module)
print("d_hmac_key", d_hmac_key)
print("e hmac_key", key_hmac)
print()

d_hmac_calculated = HMAC.HMAC(binascii.unhexlify(d_hmac_key), encrypted_file_with_iv, d_hash_module)
print("d_hmac == d_hmac_calculated:", d_hmac == d_hmac_calculated)

cipher = CIPHER.new(key=binascii.unhexlify(d_decryption_key), mode=d_mode, iv=d_iv)
decrypted_file = cipher.decrypt(encrypted_file_with_iv_hmac)

with open("ProdComp_decrypted.xlsx", "wb") as df:
    df.write(decrypted_file.rstrip(b"0"))

print()
print("Encryption/Decryption ends using:")
print("CIPHER:", CIPHER)
print("Scheme:", SCHEME)
