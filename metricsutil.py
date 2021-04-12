#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Apr 11, 2021

@author: boscolau
"""

from time import time


def timing(fn):
    """
    Timing interceptor. Used as a decorator as @time will generate in console execution time in seconds and throughput per sec.
    :param fn: Function on which the decorator is applied.
    :return: The decorator wrapping function.
    """
    def wrapper(*args, **kwargs):
        start = time()
        result = fn(*args, **kwargs)
        end = time()
        print("Time spent =", end - start, "secs")
        print("Throughput = ", 1 / (end - start), "/sec")
        return result

    return wrapper
