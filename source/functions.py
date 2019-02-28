#!/usr/bin/python3
"""

"""
import re
import math
import traceback
from struct import pack

from source import lib
from source.lib import *
from source.classes import *

"""
Crypto functions
"""
def hex(data):
    return b''.join(b'%02x' % c for c in data)

def unhex(stream):
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

def aes_cbc_decrypt(data, key, iv, blocksize=16):
    result = b''            
    previous_block = iv
    blocks = [data[i:i+blocksize] for i in range(0, len(data), blocksize)]
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_ECB)
    for block in blocks:
        tmp = cipher.decrypt(block)
        result += xor(tmp, previous_block)
        previous_block = block
    return pkcs7_unpad(result)


def ctr_keystream(key, nonce, count):
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = [cipher.encrypt(bytes(bytearray(pack('<Q', nonce)) 
                                   + bytearray(pack('<Q', block_count))))
              for block_count in range((count // 16) + 1)]
    # TODO fix
    return b''.join(blocks)[:count]

def aes_ctr_crypt(data, key, nonce):
    result = xor(data, ctr_keystream(key, nonce, len(data)))
    return result
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
Cryptopals challenges
"""
def cp_4_function(indices, lines):
    for index, line in zip(indices, lines):
        unhexed = unhex(line)
        results = bruteforce_xor(unhexed, [b'%c' % i for i in range(256)])
        for byte, result in enumerate(results):
            if dict_success(result, min_word_match=3, min_word_len=3)>0.8:
                prynt('%d: 0x%02x:' % (index, byte), result)
    return []

