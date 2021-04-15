#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Apr 13, 2021

@author: boscolau

This module contains methods doing encryption and decryption. Application code passes the bytes to encrypt/decrypt
with a secret known only to the end-user.

The encryption by default uses AES128 with HMAC-HASH-256. Applications can  use other supported
cipher/hmac-hash combinations to do experiments. Suppoer ciphers are AES128, AES256, and 3DES (for test only--do not
use for production). HMAC-HASH supported are SHA256 and SHA512.

Application can specify only the bytes to decrypt and the secret to use for decryption. The decryption method will
detect the cipher scheme to use.
"""

import binascii

from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

from config import *
from encschemeconfig import *
from keycreationlib import *

# Verbosity
DEBUG = False

# dict key names
NAME = "name"
CIPHER_IMPL = "cipher"
HASH_IMPL = "hash_impl"
OP_MODE = "op_mode"

# header artifacts
HEADER_DELIMITER = b"_"
HEADER_PAYLOAD_SEPARATOR = b":::"

HEADER_KDF = 0
HEADER_CIPHER = 1
HEADER_HMAC_HASH = 2
HEADER_ITERATIONS = 3
HEADER_SALT_MASTER_KEY = 4
HEADER_SALT_HMAC_KEY = 5
HEADER_SALT_ENCRYPTION_KEY = 6

# Implementation lookup
scheme_impls = {
    "AES128WithSHA256": {NAME: "AES128WithSHA256", CIPHER_IMPL: AES, HASH_IMPL: SHA256, OP_MODE: AES.MODE_CBC},
    "AES128WithSHA512": {NAME: "AES128WithSHA512", CIPHER_IMPL: AES, HASH_IMPL: SHA512, OP_MODE: AES.MODE_CBC},

    "AES256WithSHA256": {NAME: "AES256WithSHA256", CIPHER_IMPL: AES, HASH_IMPL: SHA256, OP_MODE: AES.MODE_CBC},
    "AES256WithSHA512": {NAME: "AES256WithSHA512", CIPHER_IMPL: AES, HASH_IMPL: SHA512, OP_MODE: AES.MODE_CBC},

    "3DESWithSHA256": {NAME: "3DESWithSHA256", CIPHER_IMPL: DES3, HASH_IMPL: SHA256, OP_MODE: AES.MODE_CBC},
    "3DESWithSHA512": {NAME: "3DESWithSHA512", CIPHER_IMPL: DES3, HASH_IMPL: SHA512, OP_MODE: AES.MODE_CBC}
}

SALT_SIZE = 16  # bytes


########################################################################################################################
## Application APIs
##  APIs for encryption and decryption.
########################################################################################################################
def encrypt(data: bytes, secret: str, cipher: str = "aes128", hmac_hash="sha256", iterations: int = 1000,
            kdf: str = "pbkdf2") -> bytes:
    #######################################
    # Get scheme operating parameters
    #######################################
    cipher_impl, op_mode, hmac_hash_impl, key_length, block_size = __get_operation_parameters(cipher, hmac_hash)

    #######################################
    # Generate salts
    #######################################
    salt_master_key = binascii.hexlify(get_random_bytes(SALT_SIZE)).decode()
    salt_hmac_key = binascii.hexlify(get_random_bytes(SALT_SIZE)).decode()
    salt_encryption_key = binascii.hexlify(get_random_bytes(SALT_SIZE)).decode()

    if DEBUG:
        print("smk:", salt_master_key, "|", type(salt_master_key))
        print("shk:", salt_hmac_key, "|", type(salt_hmac_key))
        print("sek:", salt_encryption_key, "|", type(salt_encryption_key))

    #######################################
    # Generate keys
    #######################################
    master_key = create_key(secret=secret, salt=salt_master_key, iterations=iterations, key_length=key_length,
                            hmac_hash=hmac_hash, kdf=kdf)

    encryption_key = create_key(secret=master_key, salt=salt_encryption_key, iterations=1, key_length=key_length,
                                hmac_hash=hmac_hash, kdf=kdf)

    hmac_key = create_key(secret=master_key, salt=salt_hmac_key, iterations=1, key_length=key_length,
                          hmac_hash=hmac_hash, kdf=kdf)

    if DEBUG:
        print("mkey:", master_key)
        print("ekey:", encryption_key)
        print("hkey:", hmac_key)

    #######################################
    # Get cipher object with auto-gen IV
    #######################################
    enc_cipher = cipher_impl.new(key=binascii.unhexlify(encryption_key), mode=op_mode)
    iv = enc_cipher.iv

    padded_data = __pad_message(data, block_size)
    data_encrypted = enc_cipher.encrypt(padded_data)

    #######################################
    # HMAC
    #######################################
    iv_data_encrypted = iv + data_encrypted
    hmac = HMAC.HMAC(binascii.unhexlify(hmac_key), iv_data_encrypted, hmac_hash_impl)
    hmac_iv_data_encrypted = hmac.digest() + iv_data_encrypted

    #######################################
    # Create header and prepend
    #######################################
    header = __build_header(kdf, cipher, hmac_hash, iterations, salt_master_key, salt_hmac_key, salt_encryption_key)
    header_hmac_iv_data_encrypted = header + HEADER_PAYLOAD_SEPARATOR + hmac_iv_data_encrypted

    if DEBUG:
        print("    hmac:", hmac.digest(), "|", len(hmac.digest()))
        print("      iv:", iv, "|", type(iv), "|", binascii.hexlify(iv))
        print("env_data:", data_encrypted)
        print("   final:", hmac.digest() + iv_data_encrypted)
        print("complete:", header_hmac_iv_data_encrypted)

    return header_hmac_iv_data_encrypted


def decrypt(data: bytes, secret: str) -> bytes:
    #######################################
    # Get scheme operating parameters
    #######################################
    kdf, cipher, hmac_hash, iterations, salt_master_key, salt_hmac_key, salt_encrption_key = __get_header_info(data)

    #######################################
    # Get scheme operating parameters
    #######################################
    cipher_impl, op_mode, hmac_hash_impl, key_length, block_size = __get_operation_parameters(cipher, hmac_hash)

    #######################################
    # Generate keys
    #######################################
    master_key = create_key(secret=secret, salt=salt_master_key, iterations=iterations, key_length=key_length,
                            hmac_hash=hmac_hash, kdf=kdf)

    decryption_key = create_key(secret=master_key, salt=salt_encrption_key, iterations=1, key_length=key_length,
                                hmac_hash=hmac_hash, kdf=kdf)

    hmac_key = create_key(secret=master_key, salt=salt_hmac_key, iterations=1, key_length=key_length,
                          hmac_hash=hmac_hash, kdf=kdf)

    if DEBUG:
        print("mkey:", master_key)
        print("ekey:", decryption_key)
        print("hkey:", hmac_key)

    #######################################
    # Start decryption process
    # 1. Remove header
    # 2. Extract HMAC, IV, and data_encrypted
    # 3. Calculate HMAC
    # 4. Validate HMAC, for integrity
    # 5. Create decryption cipher object
    # 6. Decrypt data
    # 7. Unpad, and return
    #######################################
    # 1. Remove header
    payload = __get_payload(data)

    # 2. Extract HMAC, IV, and data_encrypted
    hmac_extracted = payload[0:hmac_hash_impl.digest_size]
    iv_data_encrypted = payload[hmac_hash_impl.digest_size:]
    iv = iv_data_encrypted[:block_size]
    data_encrypted = iv_data_encrypted[len(iv):]

    # 3. Calculate HMAC
    hmac_derived = HMAC.HMAC(binascii.unhexlify(hmac_key), iv_data_encrypted, hmac_hash_impl)

    if DEBUG:
        print("hmacextr:", hmac_extracted)
        print("cal_hmac:", hmac_derived.digest())

    # 4. Validate HMAC
    if hmac_derived.digest() != hmac_extracted:
        raise ValueError("Invalid data to decrypt.")

    # 5. Create decryption cipher object
    dec_cipher = cipher_impl.new(key=binascii.unhexlify(decryption_key), mode=op_mode, iv=iv)

    # 6. Decrypt data
    data_decrypted = dec_cipher.decrypt(data_encrypted)

    # 7. Unpad, and return
    return __unpad_message(data_decrypted, block_size)


########################################################################################################################
## Utilities APIs
########################################################################################################################
def __get_operation_parameters(cipher: str, hmac_hash: str):
    scheme_impl = __get_scheme_impl(cipher, hmac_hash)
    scheme_config = get_cipher_scheme(cipher, hmac_hash)

    cipher_impl = scheme_impl[CIPHER_IMPL]
    op_mode = scheme_impl[OP_MODE]
    hmac_hash_impl = scheme_impl[HASH_IMPL]
    key_length = scheme_config[KEY_LENGTH_IN_BYTES]
    block_size = scheme_config[BLOCK_SIZE_IN_BYTES]

    return cipher_impl, op_mode, hmac_hash_impl, key_length, block_size


def __build_header(kdf: str, cipher: str, hmac_hash: str, iterations: int, salt_master_key: str, salt_hmac_key: str,
                   salt_encryption_key: str) -> bytes:
    header = "_".join([
        kdf, cipher, hmac_hash, str(iterations), salt_master_key, salt_hmac_key, salt_encryption_key])

    return binascii.hexlify(header.encode())


def __get_header_info(data: bytes) -> (str, str, str, int, str, str, str):
    header_payload = data.split(HEADER_PAYLOAD_SEPARATOR)

    if DEBUG:
        print("header_payload:", header_payload)

    header_bytes = binascii.unhexlify(header_payload[0])
    headers = header_bytes.split(HEADER_DELIMITER)

    if DEBUG:
        print("header_values:", headers)

    kdf = headers[HEADER_KDF].decode()
    cipher = headers[HEADER_CIPHER].decode()
    hmac_hash = headers[HEADER_HMAC_HASH].decode()
    iterations = int(headers[HEADER_ITERATIONS])
    salt_master_key = headers[HEADER_SALT_MASTER_KEY].decode()
    salt_hmac_key = headers[HEADER_SALT_HMAC_KEY].decode()
    salt_encryption_key = headers[HEADER_SALT_ENCRYPTION_KEY].decode()

    if DEBUG:
        print(kdf, cipher, hmac_hash, iterations, salt_master_key, salt_hmac_key, salt_encryption_key)

    return kdf, cipher, hmac_hash, iterations, salt_master_key, salt_hmac_key, salt_encryption_key


def __get_payload(data: bytes) -> bytes:
    header_payload = data.split(HEADER_PAYLOAD_SEPARATOR)
    return header_payload[1]


def __get_scheme_impl(cipher: str, hmac_sha: str) -> dict:
    scheme_name = "".join([cipher.upper(), "With", hmac_sha.upper()])
    try:
        return scheme_impls[scheme_name]
    except KeyError:
        raise ValueError("Unsupported cipher or hmac_hash: " + cipher + "/" + hmac_sha)


def __pad_message(base: bytes, block_length: int, style: str = "pkcs7"):
    val = pad(base, block_length, style)
    return val


def __unpad_message(base: bytes, block_length: int, style: str = "pkcs7"):
    val = unpad(base, block_length, style)
    return val


with open("ProdComp.xlsx", "rb") as f:
    file_to_encrypt = f.read()

encrypted_value = encrypt(file_to_encrypt, "password")
decrypted_value = decrypt(encrypted_value, "password")

print("encValue:", encrypted_value, "|", len(encrypted_value))
print("oriValue:", file_to_encrypt, "|", len(file_to_encrypt))
print("decValue:", decrypted_value, "|", len(decrypted_value))
