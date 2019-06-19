#!/usr/bin/python3
"""
Sophisticated attacks are here
"""
import pdb
import traceback

from source.log import *
from source.functions import *
from source.classes import *


def break_xor(data, language):
    result = None
    # get normalized hamming for keysizes, smallest should be correct
    distances = {}
    for keysize in range(2, min(40, len(data))):
        tmp_distance = 0
        sample_count = 0
        #go through keysize block pairs, get average hamming
        for i in range(0, len(data) - keysize, keysize):
            sample1 = data[i:i+keysize]
            sample2 = data[i+keysize:i+2*keysize]
            sample_count += 1
            tmp_distance += hamming(sample1, sample2)
            distances[keysize] = tmp_distance / sample_count / keysize
    #for k,v in distances.items():
    #    print(k, v)
    best = sorted(distances.items(), key=lambda x: x[1])

    # use 2 best distances and try to get characters based on best frequency
    #for keysize, distance in best[:2]:
    for keysize, distance in best[:1]:
        key = b''
        debug('Trying keysize %d (distance %.3f)' % (keysize, distance))
        for offset in range(keysize):
            transposed = data[offset::keysize]
            xors = list(bruteforce(transposed,
                                   [b'%c' % c for c in range(256)],
                                   lambda a, b: xor(a, b)))
            best = sorted(xors, key=lambda x: get_frequency_error(x, language))
            #for i in range(3):
            #    print(get_frequency_error(best[i], language))
            key += b'%c' % (xors.index(best[0]))
            #for i in range(3):
            #    print(get_frequency_error(best[i], language))
        if not result:
            result = XORAlgorithm(key=Variable(key),
                                  ciphertext=Variable(data),
                                  plaintext=Variable(xor(data, key)))
        #print('Key for keysize %d:' % keysize, key)
        #print('Deciphered message:')
        #prynt(xor(data, key))
    return result
