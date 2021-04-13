#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Apr 05, 2021

@author: boscolau

This is the module defining the API for UI application to create keys given a secret and several cryptographic
parameters.
"""

import binascii
import Crypto.Hash.SHA256
import Crypto.Hash.SHA512

from config import *

from Crypto.Protocol.KDF import PBKDF2
from metricsutil import timing

from ciphershemes import *

### Debugging switch ###
DEBUG = True

### Constants
KDF_PBKDF2 = "pbkdf2"

### Reference Data
pbkdf2_hmac_hash_modules = {"sha256": Crypto.Hash.SHA256, "sha512": Crypto.Hash.SHA512}


########################################################################################################################
## Public APIs
##  APIs for application use. These APIs are agnostic to KDF implementations, hence hmac_hash and kdf are indicated by
##  str type so the selection of the actual implementation module is deferred to the corresponding methods in the
##  KDF specific implementation section
########################################################################################################################
@timing
def create_master_key(secret: str, salt: str, iterations: int = 1000, key_length: int = 32,
                      hamc_hash: str = "sha256", kdf="pbkdf2") -> str:
    """
        Create a master key from the secret and salt, with  operation parameters.
    :param secret: The secret, which can be password, pass-phrase, etc using which to create a master key for
                   subsequent key generations.
    :param salt: The salt used to generate the key.
    :param iterations: Number of iterations running in the KDF to generate the key. Default to 1000.
    :param key_length: Length of key being generated. Default to 32 bytes.
    :param hamc_hash: HMAC-Hash to use. Note that this is a string indicating the hash to use. Underlying implementation
                      per kdf will pick the corresponding implementation module.
    :param kdf: The name of the KDF to use. Default to pbkdf2.
    :return: A key of type str of length key-length
    """
    key = create_key(secret, salt, iterations, key_length, hamc_hash, kdf)
    key = binascii.hexlify(key).decode()

    return key


def create_encryption_key(master_key: str, cipher: str, hmac_hash: str = "sha256", kdf="pbkdf2") -> str:
    """
        Create an encryption key given a master key for cipher using hmac_hash and kdf. Size of key is determined by
        cipher (16 bytes for AES128, 32 bytes for AES256, 24 bytes for 3DES). Internally, salt for the operation is
        pre-defined by the system.
    :param master_key: Master key as the seed to generate the encryption key
    :param cipher: Cipher to use. Currently supports "aes128", "aes256", "3des".
    :param hmac_hash: HMAC hash to use. Currently supports "sha256", and "sha512". Default to "sha256"
    :param kdf: KDF to use. Default to "pbkdf2".
    :return: A well-formed encryption key of length pertained to cipher.
    """
    cipher_scheme = get_cipher_scheme(cipher, hmac_hash)
    key_length = cipher_scheme[KEY_LENGTH_IN_BYTES]

    enc_key = create_key(master_key, SALT_ENCRYPTION_KEY, ENCRYPTION_KEY_ROUNDS, key_length, hmac_hash, kdf)
    enc_key = binascii.hexlify(enc_key).decode()

    return enc_key


def create_hmac_key(master_key: str, cipher: str, hmac_hash: str = "sha256", kdf="pbkdf2") -> str:
    """
        Create an hmac key given a master key for cipher using hmac_hash and kdf. Size of key is determined by
        cipher (16 bytes for AES128, 32 bytes for AES256, 24 bytes for 3DES). Internally, salt for the operation is
        pre-defined by the system.
    :param master_key: Master key as the seed to generate the encryption key
    :param cipher: Cipher to use. Currently supports "aes128", "aes256", "3des".
    :param hmac_hash: HMAC hash to use. Currently supports "sha256", and "sha512". Default to "sha256"
    :param kdf: KDF to use. Default to "pbkdf2".
    :return: A well-formed encryption key of length pertained to cipher.
    """
    cipher_scheme = get_cipher_scheme(cipher, hmac_hash)
    key_length = cipher_scheme[KEY_LENGTH_IN_BYTES]

    enc_key = create_key(master_key, SALT_HMAC_KEY, ENCRYPTION_KEY_ROUNDS, key_length, hmac_hash, kdf)
    enc_key = binascii.hexlify(enc_key).decode()

    return enc_key


########################################################################################################################
## Key creation common code
##
########################################################################################################################
def create_key(secret: str, salt: str, iterations: int, key_length: int, hmac_hash: str, kdf: str) -> bytes:
    """
        The common implementation of all key generation APIs, given the parameters.
    :param secret: The secret, which can be password, pass-phrase, etc using which to create a master key for
                   subsequent key generations.
    :param salt: The salt used to generate the key.
    :param iterations: Number of iterations running in the KDF to generate the key.
    :param key_length: Length of key being generated.
    :param hmac_hash: HMAC-Hash to use. Note that this is a string indicating the hash to use. Underlying implementation
                      per kdf will pick the corresponding implementation module.
    :param kdf: The name of the KDF to use.
    :return: A key of type str of length key-length
    """
    if kdf.lower() == KDF_PBKDF2:
        key = create_key_with_pbkdf2(secret, salt, iterations, key_length, hmac_hash)
    else:
        raise ValueError("Unsupported kdf: " + kdf)

    return key


########################################################################################################################
## KDF specific implementations
########################################################################################################################
##################################################################################
##  PBKDF2 (Crypto.Protocol.KDF from PyCryptodome)
##################################################################################
def create_key_with_pbkdf2(secret: str, salt: str, iterations: int, key_length: int, hmac_hash: str) -> bytes:
    """
        A key derivation function using PBKDF2, given the parameters. The implementation is using
        Crypto.protocol.KDF.PBKDF2 from PyCryptodome.

        This method is using hmac_hash_module as specified by hmac_hash. It does not use the mutually exclusive prf
        parameter.
    :param secret: The secret, which can be password, pass-phrase, etc using which to create a master key for
                   subsequent key generations.
    :param salt: The salt used to generate the key.
    :param iterations: Number of iterations running in the KDF to generate the key.
    :param key_length: Length of key being generated.
    :param hmac_hash: HMAC-Hash to use. Note that this is a string indicating the hash to use. Underlying implementation
                      per kdf will pick the corresponding implementation module.
    :return: A key of type str of length key-length
    """
    try:
        hmac_hash_module = pbkdf2_hmac_hash_modules[hmac_hash.lower()]
    except KeyError:
        raise ValueError("Unsupported hmac_hash: " + hmac_hash)

    key = PBKDF2(secret, salt, key_length, count=iterations, hmac_hash_module=hmac_hash_module)

    return key
