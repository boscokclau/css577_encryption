#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Apr 15, 2021

@author: boscolau
"""

import time

from Crypto.Random import get_random_bytes

from keycreationlib import create_key


########################################################################################################################
## Perf number decorator
########################################################################################################################
def perf(fn):
    def function_timer(*args, **kwargs):
        start = time.time()
        value = fn(*args, **kwargs)
        end = time.time()
        runtime = end - start

        return runtime

    return function_timer


########################################################################################################################
## Runner
########################################################################################################################
@perf
def run(secret: str, salt: str, iterations: int, key_length: int, hmac_hash: str, kdf: str) -> float:
    create_key(secret, salt, iterations, key_length, hmac_hash, kdf)


########################################################################################################################
## Main
########################################################################################################################

# Perf number captures, comma-delimited to create a csv files
perf_results = list()

# Test parameters
kdfs = ["pbkdf2"]
# ciphers = ["aes128", "aes256", "3des"]
hmac_hashes = ["sha256", "sha512"]
key_lengths = [16, 24, 32]
start_iterations = 1000
max_iterations = 100000
steps = 500
secret = "password"
salt = get_random_bytes(16)

# Tests for all combos
for i_k, kdf in enumerate(kdfs):
    for i_h, hmac_hash in enumerate(hmac_hashes):
        for i_kl, key_length in enumerate(key_lengths):

            perf_numbers = list()

            for iterations in range(start_iterations, max_iterations + 1, steps):
                # Run test
                print(f"Running: {hmac_hash} : {key_length} : {iterations}")

                ex_time = run(secret=secret, salt=salt, iterations=iterations, key_length=key_length,
                              hmac_hash=hmac_hash, kdf=kdf)
                perf_numbers.append(f"{iterations}, {ex_time}")

                with open(f"{hmac_hash}_{key_length}.csv", "w") as f:
                    f.writelines("\n".join(perf_numbers))
