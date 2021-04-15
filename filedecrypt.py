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
FILE_PREFIX = "decrypted_"

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help="File to decrypt.")
    parser.add_argument('password', help='Password')

    args = parser.parse_args()

    filename = args.file
    print("Decrypting:", filename)

    with open(filename, "rb") as fr:
        file_to_decrypt = fr.read()

    decrypted_value = cryptoutil.decrypt(file_to_decrypt, "password")

    with open(FILE_PREFIX + filename[0:-len(FILE_EXTENSION)], "wb") as fw:
        fw.write(decrypted_value)

    if DEBUG:
        with open(filename[0:-len(FILE_EXTENSION)], "rb") as ofr:
            file_to_encrypt = ofr.read()
        print("decValue:", decrypted_value, "|", len(decrypted_value))
        print("oriValue:", file_to_encrypt, "|", len(file_to_encrypt))

    print("Decryption Completed. File name::", FILE_PREFIX + filename[0:-len(FILE_EXTENSION)])
