#!/usr/bin/python3
"""
Standard functions.
"""

import subprocess
import sys
#import base64
#import threading
#import re
#import math
#import traceback
#import matplotlib.pyplot as plt
#import matplotlib.ticker as ticker
#import random
from source import log

"""
Constants
"""

character_frequencies = {
    'english': {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
}

debug_flag = False
wordlist = []

"""
Standard functions
"""
def debug(*args, **kwargs):
    if debug_flag:
        print('\033[90m[.]', *args, '\033[0m', **kwargs)

def run_command(command):
    p = subprocess.Popen(command, 
                         shell=True, 
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    (out, err) = p.communicate()
    return (p.returncode, out, err)

def prynt(*args, end='\n'):
    """
    Universal printing of str and bytes to terminal or file.
    """
    if sys.stdout.isatty():
        try:
            print(*[(arg.decode() 
                     if (type(arg) == bytes)
                     else arg)
                    for arg in args], end=end)
        except:
            print(*args, end=end)
    else:
        sys.stdout.buffer.write(b' '.join(args))

def quit_string(x):
    if type(x) != str:
        return False
    x = x.lower()
    if x in ['quit', 'exit', 'q', 'end', ':wq']:
        return True
    return False


def exit_program(signal, frame):
    """immediate termination due to -h, bad parameter or bind() fail"""
    if signal == -1:
        sys.exit(0)

    log.newline() # newline
    #log.info('Killing all the threads...') # TODO
    sys.exit(0 if signal is None else 1)

def size_human(value, integer=False):
    format_string = '{0:.0f}' if integer else '{0:.3f}'
    if value > 1024**4:
        return ('%s TB' % format_string).format(value / (1024**4))
    if value > 1024**3:
        return ('%s GB' % format_string).format(value / (1024**3))
    if value > 1024**2:
        return ('%s MB' % format_string).format(value / (1024**2))
    if value > 1024:
        return ('%s kB' % format_string).format(value / (1024))
    return '{0} B'.format(value)

def chunks(data, chunksize):
    """
    Split data in sequential chunks.
    """
    # TODO option for alternating chunks
    return [data[i:i+chunksize] for i in range(0, len(data), chunksize)]

def rotate_left(value, shift):
    return ((value << shift) & 0xffffffff) | (value >> (32 - shift))

def root(x, n):
    """
    Finds n-th root of x using binary search.
    """
    low = 0
    high = x
    while low < high:
        mid = (low + high) // 2
        if mid ** n < x:
            low = mid + 1
        else:
            high = mid
    return low

def int_to_bytes(x, length=None, byteorder='big'):
    if not length:
        length = (x.bit_length() + 7) // 8
    return x.to_bytes(length, byteorder=byteorder)

def bytes_to_int(x, byteorder='big'):
    return int.from_bytes(x, byteorder=byteorder)

