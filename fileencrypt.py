#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Apr 14, 2021

@author: boscolau
"""

import argparse
import configparser

import cryptoutil

from metricsutil import timing

# DEBUG
DEBUG = False

# File extension
FILE_EXTENSION = ".enc"


########################################################################################################################
## Runner
########################################################################################################################
@timing
def encrypt_file(filename: str, secret: str, kdf: str, cipher: str, hash_algorithm: str, iterations: int):
    """
        Proxy method doing file encryption.
    :param filename: File to encrypt
    :param secret: Secret to encrypt the file
    :param kdf: KDF to use
    :param cipher: Cipher scheme to use
    :param hash_algorithm: hash algorithm to use
    :param iterations: Number of iterations in KDF
    :return: None
    """
    print("Encrypting:", filename)

    with open(filename, "rb") as fr:
        file_to_encrypt = fr.read()

    encrypted_value = cryptoutil.encrypt(file_to_encrypt, secret, cipher, hash_algorithm, iterations, kdf)

    if DEBUG:
        decrypted_value = cryptoutil.decrypt(encrypted_value, secret)
        print("encValue:", encrypted_value, "|", len(encrypted_value))
        print("filValue:", file_to_encrypt, "|", len(file_to_encrypt))
        print("decValue:", decrypted_value, "|", len(decrypted_value))

    with open(filename + FILE_EXTENSION, "wb") as fw:
        fw.write(encrypted_value)

    print("Encryption completed. File name::", filename + FILE_EXTENSION)


########################################################################################################################
## Program Main
########################################################################################################################
if __name__ == '__main__':
    # Read command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help="File to encrypt.")
    parser.add_argument('password', help='Password')

    args = parser.parse_args()

    # Read configurations
    config = configparser.ConfigParser()
    config.read("filecrypto.ini")

    kdf = config["application"]["kdf"]
    cipher = config["application"]["cipher"]
    hash_algorithm = config["application"]["hash"]
    iterations = int(config["application"]["iterations"])

    filename = args.file
    password = args.password

    encrypt_file(filename, password, kdf, cipher, hash_algorithm, iterations)
