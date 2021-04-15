#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Apr 14, 2021

@author: boscolau
"""

import argparse
import cryptoutil

# DEBUG
DEBUG = False

# File extension
FILE_EXTENSION = ".enc"

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help="File to encrypt.")
    parser.add_argument('password', help='Password')

    args = parser.parse_args()

    filename = args.file
    print("Encrypting:", filename)

    with open(filename, "rb") as fr:
        file_to_encrypt = fr.read()

    encrypted_value = cryptoutil.encrypt(file_to_encrypt, "password")
    decrypted_value = cryptoutil.decrypt(encrypted_value, "password")

    if DEBUG:
        print("encValue:", encrypted_value, "|", len(encrypted_value))
        print("filValue:", file_to_encrypt, "|", len(file_to_encrypt))
        print("decValue:", decrypted_value, "|", len(decrypted_value))

    with open(filename + FILE_EXTENSION, "wb") as fw:
        fw.write(encrypted_value)

    print("Encryption completed. File name::", filename + FILE_EXTENSION)
