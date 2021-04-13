#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Apr 12, 2021

@author: boscolau

This file holds the constants for keycreationlib tests, which were broken up into multiple file for maintainability.
"""

# Dictionary keys
SECRET = "secret"
SALT = "salt"
ITERATIONS = "iterations"
KEY_LENGTH = "key_length"
HMAC_HASH = "hmac_hash"
KDF = "kdf"
KEY = "KEY"
CIPHER = "cipher"

# Expects
NONE_EXCEPTION_CLASS_EXPECT = None
NONE_EX_MSG = None

# This value is obtained from https://neurotechnics.com/tools/pbkdf2-test as the base value for all verifications.
BASE_KEY = "632c2812e46d4604102ba7618e9d6d7d2f8128f6266b4a03264d2a0460b7dcb3"

EXPECT_ENC_KEY_SHA256_16b = "23207a0f669755c1a8cfe625d438d32a"
EXPECT_ENC_KEY_SHA256_24b = "23207a0f669755c1a8cfe625d438d32a69eca4156b43b51c"
EXPECT_ENC_KEY_SHA256_32b = "23207a0f669755c1a8cfe625d438d32a69eca4156b43b51c771c2e72097a8148"

EXPECT_HMAC_KEY_SHA256_16b = "5df5399ba11b6b2240f10977d3a6ca50"
EXPECT_HMAC_KEY_SHA256_24b = "5df5399ba11b6b2240f10977d3a6ca5052675650eece9a40"
EXPECT_HMAC_KEY_SHA256_32b = "5df5399ba11b6b2240f10977d3a6ca5052675650eece9a40eb769cdd2d95d301"

# Values for SHA512 comes from https://stuff.birkenstab.de/pbkdf2/
EXPECT_ENC_KEY_SHA512_16b = "ea95166422f87de58c5ac52ea9e7c180"
EXPECT_ENC_KEY_SHA512_24b = "ea95166422f87de58c5ac52ea9e7c180ca5e52021a58f07e"
EXPECT_ENC_KEY_SHA512_32b = "ea95166422f87de58c5ac52ea9e7c180ca5e52021a58f07e45f645fde7f0bcb9"

EXPECT_HMAC_KEY_SHA512_16b = "5759dfc98da1cfecb2c86f32f53d3849"
EXPECT_HMAC_KEY_SHA512_24b = "5759dfc98da1cfecb2c86f32f53d3849023e73ea838b899c"
EXPECT_HMAC_KEY_SHA512_32b = "5759dfc98da1cfecb2c86f32f53d3849023e73ea838b899c6f3e2cc7f7243168"
