#!/usr/bin/python3
"""

"""
import re
import math
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
    except:
        traceback.print_exc()
        return 0
    actual = {c:(data.lower().count(c.encode()) / len(data)) for c in fs.keys()}
    return sum(abs((fs[c]-actual[c]) / len(actual)) for c in actual.keys())

def xor(data1, data2):
    #print(len(data1), len(data2))
    if not data1 or not data2:
        log.warn('Using XOR with empty value.')
        return data1 + data2
    return b''.join(b'%c' % (data1[i % len(data1)] ^ data2[i % len(data2)]) 
                    for i in range(max(len(data1), len(data2))))

def bruteforce_xor(data1, keys):
    for key in keys:
        yield xor(data1, key)

# generalization of bruteforce_xor
def bruteforce(data, keys, f):
    for key in keys:
        yield f(data, key)

def dict_success(sample, wordlist=None, min_word_match=1, min_word_len=1): # TODO or different constants?
    """
    Return how many of given words are actually in wordlist (as fraction).
    """
    wordlist = wordlist or []

    match_count = 0
    words = [w for w in re.sub(b'[^a-z]+', b' ', sample.lower()).split()
             if len(w) >= min_word_len]
    if not words:
        return 0
    found = [w for w in words if w in wordlist]
    if len(found) < min_word_match:
        return 0
    success = len(found) / len(words)
    #print(found)
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
        a, b = b, a%b
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
    #print(''.join(chr(x) for x in list(gen(1, 1))[:length]))
    #for x in gen(1, 1):
    #    print(alphabet[x % k], end='')
    #    sys.stdout.flush()
    #    time.sleep(0.1)
    g = gen(*params)
    return ''.join([alphabet[next(g) % len(alphabet)] for _ in range(length)])


def parse_int(value, variable_pool):
    result = None
    for f in [
        lambda x: int(variable_pool[x].as_int()),
        lambda x: int(x),
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
            if k in ('mode',): # beacuse of AES mode=cbc
                result[k] = v
            else:
                try: # as int
                    from source.classes import Variable
                    result[k] = Variable(parse_int(v, variables))
                except:
                    traceback.print_exc()
                    result[k] = v
    return result


def prime(bits=1024):
    return number.getPrime(bits)

def oracle_send(payload, oracle_path):
    '''"""
    Quick method to run an oracle with given payload and receive output.
    """
    oracle = Oracle(oracle_path,
                    {0: payload},
                    lambda i,r,o,e,kw: True)
    oracle.start()
    oracle.join()
    result = oracle.matching[0].output
    return result
    '''
    from source.classes import Oracle
    return Oracle.once(payload, oracle_path)

def pkcs7_pad(data, blocksize=16):
    """
    Pad with PKCS#7 method - bytes (how many bytes to blocksize) up to blocksize

    Example (blocksize = 8):
        Ninja -> Ninja\x03\x03\x03
        Warrior -> Warrior\x01
        Evernote -> Evernote\x08\x08\x08\x08\x08\x08\x08\x08
    """
    needed = blocksize - (len(data)%blocksize)
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

def ecb_suspect(data, blocksize=16):
    """
    Test ECB (try to find repeating blocks).
    """
    return bool(find_repeating_patterns(data, min_size=blocksize))

def find_repeating_patterns(data, min_size=8):
    """
    Return whether there are repeating blocks of given size in the data.
    """
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
    """
    Manual AES-CBC encryption implementation.

           P1      P2
           |       |
    IV ---(X)  ,--(X)
           |   |   |
           |   |   |
    key --AES  |  AES-- key
           |__/    |__ ...
           |       |
           C1      C2
    """
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
    """
    Manual AES-CBC decryption implementation.

           C1      C2
           |____   |__ ...
           |    |  |
    key --AES   | AES-- key
           |    |  |
    IV ---(X)    `(X)
           |       |
           P1      P2
    """
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
    """
    Manual AES-CTR encryption/decryption implementation

      Nonce;Counter
           |
    Key --AES
           |
    P ----(X)
           |
           C
    """
    result = xor(data, ctr_keystream(key, nonce, len(data)))
    return result

def aes_ctr_edit(ciphertext, key, nonce, offset, newtext):
    """
    Edit CTR ciphertext if key, nonce and expected offset are known.
    """
    decrypted = aes_ctr_crypt(ciphertext, key, nonce)
    decrypted = decrypted[:offset] + newtext + decrypted[offset + len(newtext):]
    return aes_ctr_crypt(decrypted, key, nonce)


def hmac(algorithm, data, key):
    methods = {
        'sha1': (sha1, 64, 20),
        'md4': (md4, 64, 16),
    }
    f, block_size, output_size = methods.get(algorithm) or (None, None, None)
    if not f:
        return b''
    if len(key) > block_size:
        key = f(key)
    if len(key) < block_size:
        key += b'\x00' * (block_size - len(key))
    return f(xor(key, b'\x5c' * block_size)
             + f(xor(key, b'\x36' * block_size)
                 + data))
    

def hash_pad(algorithm, payload, bits_len=None):
    """
    Pad data for hashing.
    """
    if not bits_len:
        bits_len = len(payload) * 8
    if algorithm == 'sha1':
        payload += b'\x80'
        while (len(payload) * 8) % 512 != 448:
            payload += b'\x00'
        payload += pack('>Q', bits_len)
    elif algorithm == 'md4':
        payload += b'\x80'
        #payload += bytes((56 - len(payload) % 64) % 64)
        while (len(payload) * 8) % 512 != 448:
            payload += b'\x00'
        payload += pack('<Q', bits_len)
    return payload

def sha1(
        payload, 
        bits_len=None, 
        h=(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)):
    """
    SHA1 implementation
    """
    # https://github.com/ricpacca/cryptopals/blob/master/S4C28.py
    h = list(h)
    #print('SHA1 values:', ['%08x' % hx for hx in h], end=' ')
    if not bits_len:
        bits_len = len(payload) * 8
    payload = hash_pad('sha1', payload, bits_len)
    debug('Hashing', payload)
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
    debug('final state:', ['0x%x' % hh for hh in h])
    return b''.join(b'%c' % b for hx in h for b in pack('>I', hx))
    #return b'%08x%08x%08x%08x%08x' % tuple(h)

def md4(payload, 
        bits_len=None, 
        h=(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)):
    """
    MD4 implementation
    """
    F = lambda x, y, z: ((x & y) | (~x & z))
    G = lambda x, y, z: ((x & y) | (x & z) | (y & z))
    H = lambda x, y, z: x ^ y ^ z

    #print('DEFAULT:', hexadecimal(b''.join(b'%c' % b for x in h for b in pack('<I', x))))
    h = list(h)
    if not bits_len:
        bits_len = len(payload) * 8

    last_chunk_altered = False
    order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
    while len(payload):
        if len(payload) < 64 and not last_chunk_altered:
            payload = hash_pad('md4', payload)
            last_chunk_altered = True
        #print('after padding (len %d):' % len(payload))
        #print(payload)
        #print()
       
        chunk = payload[:64]
        X = list(unpack('<16I', chunk))
        a, b, c, d = tuple(h)
        for i in range(16):
            k = i
            if i % 4 == 0:
                a = rotate_left((a + F(b, c, d) + X[k]) & 0xffffffff, 3)
            elif i % 4 == 1:
                d = rotate_left((d + F(a, b, c) + X[k]) & 0xffffffff, 7)
            elif i % 4 == 2:
                c = rotate_left((c + F(d, a, b) + X[k]) & 0xffffffff, 11)
            elif i % 4 == 3:
                b = rotate_left((b + F(c, d, a) + X[k]) & 0xffffffff, 19)
        for i in range(16):
            k = i // 4 + (i % 4) * 4
            if i % 4 == 0:
                a = rotate_left((a + G(b, c, d) + X[k] + 0x5a827999) & 0xffffffff, 3)
            elif i % 4 == 1:
                d = rotate_left((d + G(a, b, c) + X[k] + 0x5a827999) & 0xffffffff, 5)
            elif i % 4 == 2:
                c = rotate_left((c + G(d, a, b) + X[k] + 0x5a827999) & 0xffffffff, 9)
            elif i % 4 == 3:
                b = rotate_left((b + G(c, d, a) + X[k] + 0x5a827999) & 0xffffffff, 13)
        for i in range(16):
            k = order[i]
            if i % 4 == 0:
                a = rotate_left((a + H(b, c, d) + X[k] + 0x6ed9eba1) & 0xffffffff, 3)
            elif i % 4 == 1:
                d = rotate_left((d + H(a, b, c) + X[k] + 0x6ed9eba1) & 0xffffffff, 9)
            elif i % 4 == 2:
                c = rotate_left((c + H(d, a, b) + X[k] + 0x6ed9eba1) & 0xffffffff, 11)
            elif i % 4 == 3:
                b = rotate_left((b + H(c, d, a) + X[k] + 0x6ed9eba1) & 0xffffffff, 15)
        
        h = [(x + y) & 0xffffffff for x,y in zip(h, (a, b, c, d))]
        payload = payload[64:]

    #print('MD4 values:', ['%08x' % hx for hx in h], end=' ')
    return b''.join(b'%c' % b for x in h for b in pack('<I', x))


def hash_extension(algorithm, data, digest, append, oracle_path):
    """
    We try to create MAC of new data replacing key with arbitrary characters.
    The hash state will be restored from provided digest -> key is not needed.
    """
    # TODO MD4 does not work properly
    #print(digest)
    #print(hexadecimal(digest))
    payloads = {}
    debug('Preparing payloads up to key_length == 256...')
    for key_length in range(256):
        print('Key len:', key_length)
        if algorithm == 'sha1':
            h = unpack('>5I', digest)
            print('restoring h:', ['0x%x' % hh for hh in h])
            forged_data = hash_pad('sha1', 
                                   b'A' * key_length + data)[key_length:] + append
            print('Forged data:', forged_data)
            forged_digest = sha1(append, 
                                 bits_len=(key_length + len(forged_data)) * 8, 
                                 h=h)
            print('Forged digest:', forged_digest)
        elif algorithm == 'md4':
            # TODO not working properly
            h = unpack('<4I', digest)
            #print('H from digest:', ['0x%08x' % x for x in h])
            forged_data = hash_pad('md4', 
                                   b'A' * key_length + data)[key_length:] + append
            print('Forged data:', forged_data)
            forged_digest = md4(append, 
                                bits_len=(key_length + len(forged_data)) * 8, 
                                h=h)
            print('Forged digest:', forged_digest)
        else:
            break
        payloads[key_length] = (forged_digest, forged_data)
        result = oracle_send(forged_digest + forged_data, oracle_path)
        for line in result.splitlines():
            print(line)
        print()

"""
Specific functions (e.g. print all ROTs or the valid one)
"""

def analyze(data, interactive=False):
    # TODO ALREADY OBSOLETE, objects have analyze() method
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
    """
    Try single-XOR on the data, only show matches if wordlist is defined.
    """
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
    """
    Try single-XOR bruteforce on given lines, print if kinda matches wordlist. 
    """
    for index, line in zip(indices, lines):
        unhexed = unhexadecimal(line)
        results = bruteforce_xor(unhexed, [b'%c' % i for i in range(256)])
        for byte, result in enumerate(results):
            if dict_success(result, min_word_match=3, min_word_len=3)>0.8:
                prynt('%d: 0x%02x:' % (index, byte), result)
    return []

