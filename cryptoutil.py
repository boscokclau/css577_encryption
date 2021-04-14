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

from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Hash import SHA512
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

from keycreationlib import *

# Verbosity
DEBUG = False

# dict key names
NAME = "name"
CIPHER_IMPL = "cipher"
HASH_IMPL = "hash_impl"
OP_MODE = "op_mode"

scheme_impls = {
    "AES128WithSHA256": {NAME: "AES128WithSHA256", CIPHER_IMPL: AES, HASH_IMPL: SHA256, OP_MODE: AES.MODE_CBC},
    "AES128WithSHA512": {NAME: "AES128WithSHA512", CIPHER_IMPL: AES, HASH_IMPL: SHA512, OP_MODE: AES.MODE_CBC},

    "AES256WithSHA256": {NAME: "AES256WithSHA256", CIPHER_IMPL: AES, HASH_IMPL: SHA256, OP_MODE: AES.MODE_CBC},
    "AES256WithSHA512": {NAME: "AES256WithSHA512", CIPHER_IMPL: AES, HASH_IMPL: SHA512, OP_MODE: AES.MODE_CBC},

    "3DESWithSHA256": {NAME: "3DESWithSHA256", CIPHER_IMPL: DES3, HASH_IMPL: SHA256, OP_MODE: AES.MODE_CBC},
    "3DESWithSHA512": {NAME: "3DESWithSHA512", CIPHER_IMPL: DES3, HASH_IMPL: SHA512, OP_MODE: AES.MODE_CBC}
}


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
    # Generate keys
    #######################################
    master_key = create_master_key(secret, SALT_MASTER_KEY, iterations, key_length, hmac_hash, kdf)
    encryption_key = create_encryption_key(master_key, cipher, hmac_hash, kdf)
    hmac_key = create_hmac_key(master_key, cipher, hmac_hash, kdf)

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

    # TODO: Meta data

    if DEBUG:
        print("    hmac:", hmac.digest(), "|", len(hmac.digest()))
        print("      iv:", iv)
        print("env_data:", data_encrypted)
        print("   final:", hmac.digest() + iv_data_encrypted)

    return hmac_iv_data_encrypted


def decrypt(data: bytes, secret: str) -> bytes:
    #######################################
    # Get scheme operating parameters
    #######################################
    cipher, hmac_hash, iterations, kdf = __get_header_info(data)

    #######################################
    # Get scheme operating parameters
    #######################################
    cipher_impl, op_mode, hmac_hash_impl, key_length, block_size = __get_operation_parameters(cipher, hmac_hash)

    #######################################
    # Generate keys
    #######################################
    master_key = create_master_key(secret, SALT_MASTER_KEY, iterations, key_length, hmac_hash, kdf)
    decryption_key = create_encryption_key(master_key, cipher, hmac_hash, kdf)  # symmetric cipher
    hmac_key = create_hmac_key(master_key, cipher, hmac_hash, kdf)

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
    # TODO: Remove header.

    # 2. Extract HMAC, IV, and data_encrypted
    hmac_extracted = data[0:hmac_hash_impl.digest_size]
    iv_data_encrypted = data[hmac_hash_impl.digest_size:]
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


def __get_header_info(data: bytes) -> (str, str, str, str):
    # TODO: Code to extract header
    header = {"scheme": "aes128", "hmac_hash": "sha256", "rounds": 1000, "kdf": "pbkdf2"}
    cipher = header["scheme"]
    hmac_hash = header["hmac_hash"]
    iterations = header["rounds"]
    kdf = header["kdf"]

    return cipher, hmac_hash, iterations, kdf


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

print("oriValue:", encrypted_value, "|", len(encrypted_value))
print("oriValue:", file_to_encrypt, "|", len(file_to_encrypt))
print("decValue:", decrypted_value, "|", len(decrypted_value))
