#!/usr/bin/python3
"""

"""
import re
import math
import traceback
import time
from struct import pack, unpack

from source import lib
from source.lib import *
from source.classes import *

"""
Crypto functions
"""
def binary(data):
    return b''.join([bin(b)[2:].rjust(8, '0').encode() for b in data])
        
def unbinary(data):
    return int(data, 2).to_bytes(len(data) // 8, 'big')
    
def hexadecimal(data):
    return b''.join(b'%02x' % c for c in data)

def unhexadecimal(stream):
    return b''.join(b'%c' % int(stream[i:i+2], 16) 
                    for i in range(0, len(stream), 2))

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
        e -= p* math.log(p, 256)
    return e

def entropy_chunks(data, chunksize):
    X = []
    Y = []
    for i in range(len(data)//chunksize + 1):
        X.append(i*chunksize)
        Y.append(entropy(data[i*chunksize:min(
            (i+1)*chunksize, len(data))]))
    return (X, Y)

def get_frequency_error(data, language):
    try:
        fs = character_frequencies[language]
        #return sum([fs.get(chr(c), 0) 
        #            for c in data.lower()]) / len(data)
    except:
        traceback.print_exc()
        return 0
    actual = {c:(data.lower().count(c.encode()) / len(data)) for c in fs.keys()}
    return sum(abs((fs[c]-actual[c]) / len(actual)) for c in actual.keys())

def xor(data1, data2):
    return b''.join(b'%c' % (data1[i % len(data1)] ^ data2[i % len(data2)]) 
                    for i in range(max(len(data1), len(data2))))

def bruteforce_xor(data1, keys):
    for key in keys:
        yield xor(data1, key)

def dict_success(sample, min_word_match=1, min_word_len=1): # TODO or different constants?
    match_count = 0
    words = [w for w in re.sub(b'[^a-z]+', b' ', sample.lower()).split()
             if len(w) >= min_word_len]
    if not words:
        return 0
    found = [w for w in words if w in wordlist]
    if len(found) < min_word_match:
        return 0
    success = len(found) / len(words)
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

def oracle_send(payload, oracle_path):
    oracle = Oracle(oracle_path,
                    {0: payload},
                    lambda i,r,o,e,kw: True)
    oracle.start()
    oracle.join()
    result = oracle.matching[0].output
    return result

def pkcs7_pad(data, blocksize=16):
    needed = blocksize - (len(data)%blocksize)
    if not needed:
        needed = blocksize
    result = data + (b'%c' % needed) * needed
    return result

def pkcs7_unpad(data):
    padding_value = data[-1]
    if padding_value > len(data):
        raise ValueError('Padding value is bigger than the message length.')
    for padding in data[-padding_value:]:
        if padding != padding_value:
            raise ValueError('Invalid bytes in the padding.')
    return data[:-padding_value]

def ecb_suspect(data, blocksize=16):
    '''
    blocks = []
    for block in [data[i:i+blocksize] for i in range(0, len(data), blocksize)]:
        if block in blocks:
            return True
        blocks.append(block)
    return False
    '''
    return bool(find_repeating_patterns(data, min_size=blocksize))

def find_repeating_patterns(data, min_size=8):
    result = [] # tuples of indices with identical blocks
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

def aes_ecb_encrypt(data, key):
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(data))

def aes_ecb_decrypt(data, key):
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_ECB)
        return pkcs7_unpad(cipher.decrypt(data))

def aes_cbc_encrypt(data, key, iv, blocksize=16):
    padded = pkcs7_pad(data)
    result = b''
    previous_block = iv
    blocks = [padded[i:i+blocksize] for i in range(0, len(padded), blocksize)]
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_ECB)
    for block in blocks:
        tmp = xor(block, previous_block)
        previous_block = cipher.encrypt(tmp)
        result += previous_block
    return result

def aes_cbc_decrypt(data, key, iv, blocksize=16, ignore_padding=False):
    result = b''            
    previous_block = iv
    blocks = [data[i:i+blocksize] for i in range(0, len(data), blocksize)]
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_ECB)
    for block in blocks:
        tmp = cipher.decrypt(block)
        result += xor(tmp, previous_block)
        previous_block = block
    if ignore_padding:
        return result
    else:
        return pkcs7_unpad(result)


def ctr_keystream(key, nonce, count):
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = [cipher.encrypt(bytes(bytearray(pack('<Q', nonce)) 
                                   + bytearray(pack('<Q', block_count))))
              for block_count in range((count // 16) + 1)]
    return b''.join(blocks)[:count]

def aes_ctr_crypt(data, key, nonce):
    result = xor(data, ctr_keystream(key, nonce, len(data)))
    return result

def aes_ctr_edit(ciphertext, key, nonce, offset, newtext):
    decrypted = aes_ctr_crypt(ciphertext, key, nonce)
    decrypted = decrypted[:offset] + newtext + decrypted[offset + len(newtext):]
    return aes_ctr_crypt(decrypted, key, nonce)



def sha1_pad(payload, bits_len=None):
    if not bits_len:
        bits_len = len(payload) * 8
    payload += b'\x80'
    while (len(payload) * 8) % 512 != 448:
        payload += b'\x00'
    payload += pack('>Q', bits_len)
    return payload

def sha1(
        payload, 
        bits_len=None, 
        h=(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)):
    # https://github.com/ricpacca/cryptopals/blob/master/S4C28.py
    h = list(h)
    #print('SHA1 values:', ['%08x' % hx for hx in h], end=' ')
    if not bits_len:
        bits_len = len(payload) * 8
    payload = sha1_pad(payload, bits_len)
    #data_chunks = chunks(binary(payload), 32)
    #for chunk in data_chunks:
    #    print(chunk)
    
    for chunk in chunks(payload, 64):
        w = [0] * 80
        for i in range(16):
            w[i] = unpack('>I', chunk[i*4:i*4 + 4])[0]
        for i in range(16, 80):
            w[i] = rotate_left(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)
        
        a, b, c, d, e = tuple(h)
        for i in range(80):
            if i < 20:
                k = 0x5a827999
                f = d ^ (b & (c ^ d))
            elif i < 40:
                k = 0x6ed9eba1
                f = b ^ c ^ d
            elif i < 60:
                k = 0x8f1bbcdc
                f = (b & c) | (d & (b | c))
            else:
                k = 0xca62c1d6
                f = b ^ c ^ d
            temp = rotate_left(a, 5) + f + e + k + w[i] & 0xffffffff
            e = d
            d = c
            c = rotate_left(b, 30)
            b = a
            a = temp
        h = [(hx + val) & 0xffffffff for hx,val in zip(h, (a, b, c, d, e))]
    #print('SHA1 values:', ['%08x' % hx for hx in h], end=' ')
    return b''.join(b'%c' % b for hx in h for b in pack('>I', hx))
    #return b'%08x%08x%08x%08x%08x' % tuple(h)

def hash_extension(algorithm, data, digest, append, oracle_path):
    """
    We try to create MAC of new data replacing key with arbitrary characters.
    The SHA1 state will be restored from provided digest -> key is not needed.
    """
    #print(digest)
    #print(hexadecimal(digest))
    h = unpack('>5I', digest)
    payloads = {}
    debug('Preparing payloads up to key_length == 256...')
    for key_length in range(256):
        #print('Key len:', key_length)
        if algorithm == 'sha1':
            forged_data = sha1_pad(b'A' * key_length + data)[key_length:] + append
            #print('Forged:', forged_data)
            forged_digest = sha1(append, 
                                 bits_len=(key_length + len(forged_data)) * 8, 
                                 h=h)
            #print(forged_digest)
        else:
            break
        payloads[key_length] = (forged_digest, forged_data)
        #result = oracle_send(forged_digest + forged_data, oracle)
        #for line in result.splitlines():
        #    print(line)
        #print()
    debug('Testing payloads...')
    oracle_count = 1 # TODO more when thread termination is ready
    oracles = [Oracle(oracle_path, 
                      {k:b''.join(v) for k,v in payloads.items()
                           if k % oracle_count == i},
                      lambda i,r,o,e,kw: (r == 0))
               for i in range(oracle_count)]
    for oracle in oracles:
        oracle.start()
    for oracle in oracles:
        oracle.join()
        if oracle.matching:
            key_length = oracle.matching[0].payload_id
            print('Key length:', key_length)
            print('Digest:    ', hexadecimal(payloads[key_length][0]).decode())
            print('Message:')
            prynt(payloads[key_length][1])

"""
Specific functions (e.g. print all ROTs or the valid one)
"""
def analyze(data, interactive=False):
    """

    analyze levels:
        0: entropy, histogram
    """
    analysis_level = 0
    ent = entropy(data)
    his = histogram(data)
    performed_tests = []
    ubc = len([x for x in his if x]) # unique byte count
    print('Entropy:', ent)

    ubc_hint = ''
    if ubc == 2:
        ubc_hint = '(binary?)'
    elif ubc == 3:
        ubc_hint = '(morse/binary with separators?)'
    elif ubc == 16:
        ubc_hint = '(hex?)'
    elif ubc == 17:
        ubc_hint = '(hex with separators?)'
    elif ubc == 32:
        ubc_hint = '(base32?)'
    elif ubc == 33:
        ubc_hint = '(base32 with separators?)'
    elif ubc == 58:
        ubc_hint = '(base58?)'
    elif ubc == 59:
        ubc_hint = '(base58 with separators?)'
    elif ubc == 64:
        ubc_hint = '(base64?)'
    elif ubc == 65:
        ubc_hint = '(base64 with separators?)'
    print('Unique byte count', ubc, ubc_hint)
            
    if ent > 0.99:
        print('Huge entropy; stronger crypto is expected.')

    while True:
        found_something = False
        lib.debug('Level %d analysis.' % analysis_level)
        if ('REPEATING_PATTERNS' not in performed_tests
                and (ent > 0.99 or analysis_level >= 5)):
            performed_tests.append('REPEATING_PATTERNS')
            lib.debug('  Testing REPEATING_PATTERNS.')
            if ecb_suspect(data):
                print('Repeating patterns detected -> possible ECB')
                found_something = True
        analysis_level += 1
        if interactive and found_something:
            answer = input('Continue with level %d analysis? ' % analysis_level)
            if answer.lower() not in ['y', 'yes', 't', 'true', '1', 'a']:
                break
        if analysis_level > 10:
            break
            
    

def single_xor_print(data):
    results = bruteforce_xor(data, [b'%c' % i for i in range(256)])
    for byte, result in enumerate(results):
        if wordlist:
            if dict_success(result, 
                            min_word_match=3, 
                            min_word_len=3) > 0.2:
                print('0x%02x: ' % byte, end='')
                prynt(result)
        else:
            #print(result, ', english error: %f' % get_frequency_error(result, 'english'))
            print(result)

"""
RNG functions
"""
def diehard(rng_path):
    """
    https://en.wikipedia.org/wiki/Diehard_tests
    """
    

"""
Cryptopals challenges
"""
def cp_4_function(indices, lines):
    for index, line in zip(indices, lines):
        unhexed = unhexadecimal(line)
        results = bruteforce_xor(unhexed, [b'%c' % i for i in range(256)])
        for byte, result in enumerate(results):
            if dict_success(result, min_word_match=3, min_word_len=3)>0.8:
                prynt('%d: 0x%02x:' % (index, byte), result)
    return []

