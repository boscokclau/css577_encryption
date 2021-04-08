#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Apr 05, 2021

@author: boscolau
"""

import binascii

from Crypto.Cipher import AES
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

HASH_MODULE = SHA256

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
        print("key: ", key)

    return key


def pad_message(base: bytes, block_length: int, padding: bytes):
    while len(base) % block_length != 0:
        base += padding
    return base


print("Master Key with ", HASH_MODULE)
key_master = create_key(PASSWORD, SALT_MASTER_KEY, 1000, HASH_MODULE)

print("Encryption Key")
key_encryption = create_key(key_master, SALT_ENCRYPTION_KEY, 1, HASH_MODULE)

print("HMAC Key")
key_hmac = create_key(key_master, SALT_HMAC_KEY, 1, HASH_MODULE)

print("---------------------------------------------")
print("Encrypt/Decrypt... key size =", len(key_encryption))
cipher = AES.new(binascii.unhexlify(key_encryption), AES.MODE_CBC)

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
cipher_block_size = AES.block_size
iv_extracted = encrypted_file[:cipher_block_size]
print("iv_extracted:", iv_extracted)

print("---------------------------------------------")
print("HMAC to cover IV and encrypted value")
hmac = HMAC.HMAC(binascii.unhexlify(key_hmac), encrypted_file_with_iv, HASH_MODULE)
print(hmac.digest(), "| len =", len(hmac.digest()))

encrypted_file_with_iv_hmac = hmac.digest() + encrypted_file_with_iv
print("encrypted_file_with_iv_hmac:\n")
print(encrypted_file_with_iv_hmac)

print("---------------------------------------------")
print("Extract hmac")
hmac_extracted = encrypted_file_with_iv_hmac[:HASH_MODULE.digest_size]
print("hmac_extracted:", hmac_extracted)

print("iv + file:")
iv_plus_file = encrypted_file_with_iv_hmac[HASH_MODULE.digest_size:]
print(iv_plus_file)
print("iv_plus_file == encrypted_file_with_iv:", iv_plus_file == encrypted_file_with_iv)

print("Removing IV")
iv_removed = encrypted_file_with_iv_hmac[HASH_MODULE.digest_size: (HASH_MODULE.digest_size + cipher_block_size)]
print("iv_removed:", iv_removed)
print("iv_removed == iv:", iv_removed == iv)

print("File only")
file_only = encrypted_file_with_iv_hmac[(HASH_MODULE.digest_size + cipher_block_size):]
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
d_hmac = cipher_to_decrypt[:HASH_MODULE.digest_size]
print("d_hmac:", d_hmac)
print("  hmac:", hmac.digest())
print("d_hmac == hmac.digest():", d_hmac == hmac.digest())

print()
d_iv = cipher_to_decrypt[HASH_MODULE.digest_size: (HASH_MODULE.digest_size + cipher_block_size)]
print("d_iv:", d_iv)
print("  iv:", iv)
print("d_iv == iv:", d_iv == iv)

print()
file_to_decrypt = cipher_to_decrypt[(HASH_MODULE.digest_size + cipher_block_size):]
print("file_to_decrypt:", file_to_decrypt)
print("       Original:", encrypted_file)
print("file_to_decrypt == encrypted_file", file_to_decrypt == encrypted_file)

print()
print("Cipher text in encrypted file--open file in text editor to compare:")
print(binascii.hexlify(cipher_text))

cipher = AES.new(binascii.unhexlify(key_encryption), AES.MODE_CBC, d_iv)
decrypted_file = cipher.decrypt(encrypted_file_with_iv_hmac)

with open("ProdComp_decrypted.xlsx", "wb") as df:
    df.write(decrypted_file.rstrip(b"0"))
