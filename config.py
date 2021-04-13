#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Apr 11, 2021

@author: boscolau

Application configurations.

"""

# Make it none for cipher library that can generate random IVs when no specified.
DEFAULT_IV = None

SALT_MASTER_KEY = "582f03cbf658bbaaa4deb41586c7bda8aab44b11e6b5cb9541c9881bf6a12ca3"
SALT_ENCRYPTION_KEY = "encryption key"
SALT_HMAC_KEY = "hmac key"

ENCRYPTION_KEY_ROUNDS = 1
HMAC_KEY_ROUNDS = 1
