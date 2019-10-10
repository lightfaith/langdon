#!/usr/bin/python3
"""
General functions used by main script, classes and attacks.
"""
import re
import math
import random
import traceback
import time
from struct import pack, unpack

from Crypto.Util import number

from source import lib
from source.lib import *

"""
Crypto functions
"""


def binary(data):
    return b''.join([bin(b)[2:].rjust(8, '0').encode() for b in data])


def unbinary(data):
    if isinstance(data, str):
        data = data.encode()
    padding_length = ((8 - len(data) % 8) % 8)
    data = b'0' * padding_length + data
    return bytes([int(c, 2) for c in chunks(data, 8)])


def hexadecimal(data):
    return b''.join(b'%02x' % c for c in data)


def unhexadecimal(stream):
    return b''.join(b'%c' % int(stream[i:i+2], 16)
                    for i in range(0, len(stream), 2))


def gray(data):
    as_int = bytes_to_int(data)
    return int_to_bytes(as_int ^ (as_int >> 1))


def ungray(data):
    as_int = bytes_to_int(data)
    result = 0
    while as_int:
        result ^= as_int
        as_int >>= 1

    return int_to_bytes(result)


def histogram(data):
    byte_counts = [0 for _ in range(256)]
    for byte in data:
        byte_counts[byte] += 1
    return byte_counts


def entropy(data):
    e = 0.0
    byte_counts = histogram(data)
    for count in byte_counts:
        if not count:
            continue
        p = count / len(data)
        e -= p * math.log(p, 256)
    return e


def entropy_chunks(data, chunksize):
    xx = []
    yy = []
    for i in range(len(data)//chunksize + 1):
        xx.append(i*chunksize)
        yy.append(entropy(data[i*chunksize:min(
            (i+1)*chunksize, len(data))]))
    return (xx, yy)


def get_frequency_error(data, language):
    try:
        fs = character_frequencies[language]
    except:
        traceback.print_exc()
        return 0
    actual = {c: (data.lower().count(c.encode()) / len(data))
              for c in fs.keys()}
    return sum(abs((fs[c]-actual[c]) / len(actual)) for c in actual.keys())


def bitwise(data1, data2, operation):
    if not data1 or not data2:
        log.warn('Using XOR with empty value.')
        return data1 + data2
    return b''.join(b'%c' % operation(data1[i % len(data1)], data2[i % len(data2)])
                    for i in range(max(len(data1), len(data2))))


def xor(data1, data2):
    return bitwise(data1, data2, lambda x, y: x ^ y)


def bitwise_or(data1, data2):
    return bitwise(data1, data2, lambda x, y: x | y)


def bitwise_and(data1, data2):
    return bitwise(data1, data2, lambda x, y: x & y)


def bitwise_not(data):
    return b''.join(b'%c' % (255 - c) for c in data)


def bruteforce_xor(data1, keys):
    for key in keys:
        yield xor(data1, key)


def bruteforce(data, keys, f):
    for key in keys:
        yield f(data, key)


# TODO or different constants?
def dict_success(sample, wordlist=None, min_word_match=1, min_word_len=1):
    """
    Return how many of given words are actually in wordlist (as fraction).
    """
    wordlist = wordlist or []

    #match_count = 0
    words = [w for w in re.sub(b'[^a-z]+', b' ', sample.lower()).split()
             if len(w) >= min_word_len]
    if not words:
        return 0
    found = [w for w in words if w in wordlist]
    if len(found) < min_word_match:
        return 0
    success = len(found) / len(words)
    # print(found)
    return success


def hamming(data1, data2):
    result = 0
    for i in range(max(len(data1), len(data2))):
        c1 = data1[i] if i < len(data1) else 0
        c2 = data2[i] if i < len(data2) else 0
        xored = c1 ^ c2
        for bit in range(8):
            result += (xored >> bit) & 0x1
    return result


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def lcm(a, b):
    return a // gcd(a, b) * b


def invmod(a, b):
    t, r = 0, b
    new_t, new_r = 1, a
    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    if r > 1:
        return None
    if t < 0:
        return t + b
    return t


def debruijn(length, unique_length=3, alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890', params=(1, 1)):
    # https://gist.github.com/rgov/891712
    # DIFFERENT FROM r2!
    a = [0] * (unique_length + 1)
    k = len(alphabet)

    def gen(t, p):
        if t > unique_length:
            for v in a[1:p+1]:
                yield v
        else:
            a[t] = a[t-p]
            for v in gen(t+1, p):
                yield v
            for j in range(a[t-p]+1, k):
                a[t] = j
                for v in gen(t+1, t):
                    yield v
    g = gen(*params)
    return ''.join([alphabet[next(g) % len(alphabet)] for _ in range(length)])


def random_stream(start, end, count):
    return b''.join(int_to_bytes(random.randint(start, end)) or b'\x00'
                    for i in range(count))


def random_bytes(count):
    return random_stream(0, 255, count)


def parse_int(value, variable_pool):
    result = None
    for f in [
            lambda x: int(variable_pool[x].as_int()),
            int,
            lambda x: int(x, 16),
    ]:
        try:
            result = f(value)
            break
        except:
            continue
    if result is None:
        raise ValueError
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
            # allow specific keywords to not create variables
            # beacuse of AES mode=cbc, optional RSA padding etc.
            if k in ('mode'):
                result[k] = v
            elif v == 'True':
                result[k] = True
            elif v == 'False':
                result[k] = False
            else:
                try:  # as int
                    from source.classes import Variable
                    result[k] = Variable(parse_int(v, variables))
                except:
                    traceback.print_exc()
                    result[k] = v
    return result


def prime(bits=1024):
    return number.getPrime(bits)


def pkcs7_pad(data, blocksize=16):
    """
    Pad with PKCS#7 method - bytes (how many bytes to blocksize) up to blocksize

    Example (blocksize = 8):
        Ninja -> Ninja\x03\x03\x03
        Warrior -> Warrior\x01
        Evernote -> Evernote\x08\x08\x08\x08\x08\x08\x08\x08
    """
    needed = blocksize - (len(data) % blocksize)
    if not needed:
        needed = blocksize
    result = data + (b'%c' % needed) * needed
    return result


def pkcs7_unpad(data):
    """
    Remove PKCS#7, throw error if incorrect.
    """
    padding_value = data[-1]
    if padding_value > len(data):
        raise ValueError('Padding value is bigger than the message length.')
    for padding in data[-padding_value:]:
        if padding != padding_value:
            raise ValueError('Invalid bytes in the padding.')
    return data[:-padding_value]


def find_repeating_patterns(data, min_size=8):
    """
    Return whether there are repeating blocks of given size in the data.
    """
    result = []  # tuples of indices with identical blocks
    for i in range(0, len(data)-min_size):
        reference = data[i:i+min_size]
        tmp_result = [i]
        for j in range(i+1, len(data)-min_size):
            block = data[j:j+min_size]
            if block == reference:
                tmp_result.append(j)
        if len(tmp_result) > 1:
            result.append(tuple(tmp_result))
    return result


"""
RNG functions
"""


def diehard(rng_path):
    """
    https://en.wikipedia.org/wiki/Diehard_tests
    """
    pass
