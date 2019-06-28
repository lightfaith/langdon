#!/usr/bin/python3
"""
Standard functions.
"""

import signal
import subprocess
import sys
import tempfile
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

debug_flag = True
wordlist = []

background_jobs = []

"""
Standard functions
"""
def debug(*args, **kwargs):
    if debug_flag:
        print('\033[90m[.]', *args, '\033[0m', **kwargs, file=sys.stderr)

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

def edit_in_file(data):
    """
    Runs vim and allows the user to alter data.
    """
    # TODO favourite editor
    with tempfile.NamedTemporaryFile() as f:
        f.write(data)
        f.flush()
        subprocess.call(['vim', f.name])
        f.seek(0)
        changes = f.read()
    return changes

def exit_program(signal, frame):
    if background_jobs:
        """only terminate background jobs"""
        for b in background_jobs:
            b.stop()
    else:
        """immediate termination due to -h, bad parameter or bind() fail"""
        if signal == -1:
            sys.exit(0)

        log.newline() # newline
        #log.info('Killing all the threads...') # TODO
        sys.exit(0 if signal is None else 1)
signal.signal(signal.SIGINT, exit_program)

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

def get_colored_printable(b):
    """

    """
    color = log.COLOR_BROWN
    if b in (0x9, 0xa, 0xd):
        color = log.COLOR_DARK_GREEN
        b = ord('.')
    elif b<0x20 or b>=0x7f:
        color = log.COLOR_NONE
        b = ord('.')
    return color+chr(b)+log.COLOR_NONE

def get_colored_printable_hex(b):
    """

    """
    color = log.COLOR_NONE
    if b>=0x20 and b<0x7f:
        color = log.COLOR_BROWN
    elif b in (0x9, 0xa, 0xd):
        color = log.COLOR_DARK_GREEN
    return color + '%02x' % b + log.COLOR_NONE

def hexdump(data):
    """
    Prints data as with `hexdump -C` command.
    """
    result = []
    line_count = 0
    for chunk in chunks(data, 16):
        hexa = ' '.join(''.join(get_colored_printable_hex(b) for b in byte)
                        for byte in [chunk[start:start+2]
                                     for start in range(0, 16, 2)])

        """add none with coloring - for layout"""
        if len(hexa)<199:
            hexa += (log.COLOR_NONE+'  '+log.COLOR_NONE)*(16-len(chunk))

        result.append(log.COLOR_DARK_GREEN
                      + '%08x' % (line_count*16)
                      + log.COLOR_NONE
                      + '  %-160s' % (hexa)
                      + ' |'
                      + ''.join(get_colored_printable(b) for b in chunk) + '|')
        line_count += 1
    return result

def parse_algorithm_params(command, variables):
    kvs = {}
    for kv in command.split():
        k, _, v = kv.partition('=')
        if v:
            # standard key=value format
            kvs[k] = v
        else:
            # only key (flag) -> key=True
            kvs[k] = True
    result = {}
    for k, v in kvs.items():
        if v in variables.keys():
            result[k] = variables[v]
        elif isinstance(v, str) and '.' in v:
            algo, _, param = v.partition('.')
            if algo in variables.keys() and param in variables[algo].params.keys():
                result[k] = variables[algo].params[param]
        else:
            result[k] = v
    return result

