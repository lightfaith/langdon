#!/usr/bin/python3
"""
Classes of more complex objects
"""
#import subprocess
#import sys
import base64
import pdb
import random
import string
import threading
import time
import traceback

from Crypto.Cipher import AES as AESCipher
from PIL import Image

from source.lib import *
from source.functions import *

"""
Vital classes
"""
class Parallelizer():
    """
    This classes runs given function on given data on multiple threads.
    """
    # TODO terminate stuff
    def __init__(self, thread_count, data, function, kwargs):
        self.thread_count = thread_count
        self.data = data
        self.function = function
        self.threads = []
        self.results = []
        self.kwargs = kwargs

    def start(self):
        background_jobs.append(self)
        chunk_size = len(self.data) // self.thread_count
        if not chunk_size:
            chunk_size = 1
        indexed_data = list(enumerate(self.data, 1))
        data_chunks = [indexed_data[i:i+chunk_size] 
                       for i in range(0, len(indexed_data), chunk_size)]
        self.threads = [ParallelizerThread(data_chunks[i], self.function, self.kwargs)
                        for i in range(len(data_chunks))]
        #print(self.threads)
        for t in self.threads:
            t.start()

    def waitfor(self):
        for t in self.threads:
            t.join()
            self.results += t.results
        try:
            background_jobs.remove(self)
        except:
            pass

    def stop(self):
        for t in self.threads:
            t.stop()
        self.waitfor()


class ParallelizerThread(threading.Thread):
    """
    Thread for Parallelizer class.
    """
    # TODO terminate stuff...
    def __init__(self, data, function, kwargs):
        threading.Thread.__init__(self)
        self.data = data
        self.function = function
        self.results = []
        self.kwargs = kwargs
        self.terminate = False

    def run(self):
        indices, samples = zip(*self.data)
        debug('Running thread (samples %d through %d).' 
              % (indices[0], indices[-1]))
        #pdb.set_trace()
        self.results = self.function(indices, samples, thread_ref=self, **(self.kwargs))

    def stop(self):
        self.terminate = True

class OracleResult:
    """
    Simple object for Oracle data passing.
    """
    def __init__(self, payload_id, output, duration=None):
        self.payload_id = payload_id
        self.output = output
        self.time = duration

####################################################
class Variable:
    """
    Class loads given value (from user, file, etc.)
    and can yield different representations.
    """
    def __init__(self, value, constant=False):
        self.preferred_form = self.as_escaped
        #pdb.set_trace()
        # instance of variable
        if isinstance(value, Variable):
            self.value = value.value
            self.preferred_form = value.preferred_form
            return

        # instance of algorithm
        if isinstance(value, Algorithm):
            self.value = value
            self.preferred_form = self.as_algorithm
            return

        if constant:
            # value in quotes - as string
            if value[0] in ('\'', '"') and value[-1] in ('\'', '"'):
                self.value = value[1:-1].encode()
                self.preferred_form = self.as_raw
                return
            # starts with 'file:' - load as bytes
            if value.startswith('file:'):
                try:
                    with open(value[5:], 'r') as f:
                        loaded = f.read()
                        if len(x for x in loaded if x in string.printable) != len(loaded):
                            raise UnicodeDecodeError
                        #self.value = f.read().encode()
                        #self.preferred_form = self.as_raw
                except:
                    try:
                        with open(value[5:], 'rb') as f:
                            self.value = f.read()
                    except FileNotFoundError:
                        log.err('No such file.')
                        self.value = ''
                return
            # starts with 'base64:' - decode
            if value.startswith('base64:'):
                try:
                    self.value = base64.b64decode(value[7:])
                    printables = string.printable.encode()
                    if all(c in printables for c in self.value):
                        self.preferred_form = self.as_raw
                    return
                except:
                    log.err('Cannot decode \'%s\' as Base64.' % value)
                    self.value = b''

            # starts with 'image:' - load pixel values
            # grayscale is expected now...
            # TODO recognize BW and use as bin
            # TODO how to deal with colors
            if value.startswith('image:'):
                try:
                    image = Image.open(value[6:])
                    width, height = image.size
                    debug('Loaded image; width = %d, height = %d' % image.size)
                    
                    p = image.load()
                    self.value = bytes([p[x, y] for x in range(width) for y in range(height)])
                    self.preferred_form = self.as_escaped
                except:
                    log.err('Cannot decode \'%s\' as image.' % value)
                    self.value = b''
                return

        # as bytearray - convert to bytes
        if isinstance(value, bytearray):
            value = bytes(value)
        # as bytes:
        if isinstance(value, bytes):
            self.value = value
            printables = string.printable.encode()
            if all(c in printables for c in self.value):
                self.preferred_form = self.as_raw
            return
        # value as bin
        try:
            #to_unbin = value[2:] if value.startswith('0b') else value
            self.value = unbinary(value)
            #self.value = int_to_bytes(int(value, 16))
            self.preferred_form = self.as_raw
            return
        except:
            #traceback.print_exc()
            pass
        # value as int
        try:
            self.value = int_to_bytes(int(value))
            self.preferred_form = self.as_int
            return
        except:
            pass
        # value as hex number/stream
        try:
            #to_unhex = value[2:] if value.startswith('0x') else value
            to_unhex = value
            #if len(to_unhex) % 2 == 1:
            #    to_unhex = '0' + to_unhex
            self.value = unhexadecimal(to_unhex)
            #self.value = int_to_bytes(int(value, 16))
            self.preferred_form = self.as_hex
            return
        except:
            pass
        # try to unescape
        try:
            value = value.encode().decode('unicode_escape')
        except:
            pass
        # finally, use as string
        if constant:
            self.value = value.encode()
            self.preferred_form = self.as_raw
            return
            
        log.err('Not parsed!', value)

    @staticmethod
    def get_reversed(v, chunk_size=8):
        return Variable('0b' + ''.join(chunks(v.as_binary(), chunk_size)[::-1]))


    def analyze(self, output_offset=0, interactive=False): # Variable analysis
        output = []
        # get basic statistics 
        ent = entropy(self.value)
        his = histogram(self.value)
        ioc = coincidence(self.value)
        ubc = len(set(self.value)) # unique byte count
        entropy_hint = ''
        coincidence_hint = '' # TODO
        if ent > 0.998:
            entropy_hint = '(probably encrypted)'
        if ent > 0.95:
            entropy_hint = '(probably compressed)'
        ubc_hints = {
            2: '(binary?)',
            3: '(morse/binary with separators?)',
            16: '(hex?)',
            17: '(hex with separators?)',
            32: '(base32?)',
            33: '(base32 with separators?)',
            58: '(base58?)',
            59: '(base58 with separators?)',
            64: '(base64?)',
            65: '(base64 with separators?)',
        }
        output.append(log.info('Value:            ', self.short(), offset=output_offset, stdout=False))
        output.append(log.info('Length (B):       ', len(self.as_raw()), offset=output_offset, stdout=False))
        output.append(log.info('Unique byte count:', ubc, ubc_hints.get(ubc) or '', offset=output_offset, stdout=False))
        output.append(log.info('Entropy:          ', ent, entropy_hint, offset=output_offset, stdout=False))
        output.append(log.info('IOC:              ', ioc,
                               coincidence_hint, offset=output_offset, stdout=False))
        # short key XOR detection
        repeating_lengths = {}
        for size in range(2, 17): # TODO too long on big data
            #print('size', size)
            for pattern in find_repeating_patterns(self.value, min_size=size):
                #print(' found new pattern:', pattern)
                if not repeating_lengths.get(size):
                    repeating_lengths[size] = []
                to_add = [y for x in pattern for y in range(x, x + size-2+1)]
                #print('to add', to_add)
                repeating_lengths[size].extend(to_add)
        #print('rl:', repeating_lengths)
        used = []
        candidates = []
        for length in sorted(repeating_lengths.keys(), reverse=True):
            #print('dealing with', length)
            to_add = [x for x in repeating_lengths[length] if x not in used]
            #print(' to_add:', to_add)
            if to_add:
                candidates.append(length)
                used.extend(to_add)
        #print('rl count:', {k:len(v) for k,v in repeating_lengths.items()})
        #print('rl to len:', {k:len(v)/len(self.value) for k,v in repeating_lengths.items()})
        #print('rl to len wei:', {k:len(v)/len(self.value)/2/(k-1) for k,v in repeating_lengths.items()})
        #TODO not accurate; find proper metric

        for candidate in sorted(candidates):
            output.append(log.warn('Repeating patterns of blocksize={0} found, this could be XOR ciphertext with keysize={0}.'.format(candidate), offset=output_offset, stdout=False))
                
        # ECB detection
        if find_repeating_patterns(self.value, min_size=16):
            output.append(log.warn('Repeating patterns of blocksize=16 found, this could be AES-ECB ciphertext.', offset=output_offset, stdout=False))

        # TODO low number of 1's in graycoded -> xor of 2 similar things?
        # TODO more
        # TODO CP 3.24 Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded with the current time. 
        return output

    """
    representation methods
    """
    def as_int(self):
        return bytes_to_int(self.value)

    def as_hex(self):
        return '0x' + ''.join('%02x' % c for c in self.value)

    def as_raw(self):
        return self.value
    
    def as_binary(self):
        return binary(self.as_raw()).decode()

    def as_escaped(self):
        #  \xAA values
        return ''.join(chr(c) if chr(c) in string.printable else ('\\x%02x' % c) for c in self.value)

    def as_base64(self):
        return base64.b64encode(self.value).decode()

    def as_algorithm(self):
        return str(self.value)

    def short(self):
        preferred = self.preferred_form()
        for continuation, replaces in [
                ('...', [('\x0a', '\\n'), ('\x0d', '\\r'), ],),
                (b'...', [(b'\x0a', b'\\n'), (b'\x0d', b'\\r'), ],),
        ]:
            try:
                preferred = (preferred 
                             if len(str(preferred)) <= 50 
                             else str(preferred)[:24] + continuation + str(preferred)[-24:])
                for replace in replaces:
                    preferred = preferred.replace(*replace)
                break
            except:
                continue
        if type(preferred) == bytes:
            try:
                return preferred.decode()
            except UnicodeDecodeError:
                return str(preferred)[3:-2]
        return preferred
        
    def __str__(self):
        preferred = self.preferred_form()
        if type(preferred) == bytes:
            try:
                return preferred.decode()
            except:
                return self.as_escaped()
        if type(preferred) == int:
            return str(preferred)
        return preferred

    def __repr__(self):
        return str(self)

#############################################

class Algorithm:
    def __init__(self, name):
        self.name = name
        # important parameters of given algorithm, e.g. plaintext, key, ...
        self.params = {}
        # temporary stuff for remembering some states
        self.tmp = {}

    def short(self):
        return self.name

    def detail(self):
        print('Detailed overview not implemented.')

    def analyze(self, output_offset=0, interactive=False):
        output = []
        output.append(log.err('Analysis not implemented for', self.name, offset=output_offset+2, stdout=False))
        return output
    
    def analyze_params(self, output_offset=0, interactive=False):
        # run analysis for all params, collect output
        output = []
        for k,v in self.params.items():
            if isinstance(v, Variable) or isinstance(v, Algorithm):
                output.append(log.info('Analysis for %s%s%s:' % (log.COLOR_PURPLE, k, log.COLOR_NONE), 
                                       offset=output_offset+2, stdout=False))
                output += v.analyze(output_offset+4, interactive)
        return output

    @staticmethod
    def help():
        return []


class SymmetricCipher(Algorithm):
    def __init__(self, name):
        super().__init__(name)

    @staticmethod
    def help():
        return Algorithm.help() + """
{bold}Symmetric Cipher{unbold}

""".format(bold=log.COLOR_BOLD, unbold=log.COLOR_UNBOLD).splitlines()


class AES(SymmetricCipher):
    def __init__(self, **kwargs):
        super().__init__('AES()')
        self.params = {
            'mode': None,
            'blocksize': '16',
            'key': None,         # the password
            'iv': None,          # for CBC mode, fictional previous block
            'nonce': 0,          # for CTR mode, similar to IV
            'plaintext': None,
            'ciphertext': None,
            'ignore_padding': False,
        }
        # apply defined values
        for k, v in kwargs.items():
            if k in self.params.keys():
                self.params[k] = v
    
    @staticmethod
    def help():
        return SymmetricCipher.help() + """
{color}{bold}AES{unbold}
Advanced Encryption Standard, also known as Rijndael has been established in 2001. It supersedes DES algorithm.

AES uses a fixed block size of 128 bits and a key size of 128, 192 or 256 bits. It operates on a 4x4 array of bytes (the state). AES blocks are used in several modes (see below). 

Standards:
    FIPS PUB 197
    ISO/IEC 18033-3

Use following commands to create AES objects:{command}
plaintext = file:/etc/passwd
key = 'YELLOW SUBMARINE'
iv = random 0 255 16
nonce = 1337

a = AES mode=ecb key=key plaintext=plaintext
a = AES mode=cbc key=key plaintext=plaintext iv=iv
a = AES mode=ctr key=key plaintext=plaintext nonce=nonce
ciphertext = encrypt a
{color}
Analogically, you can provide ciphertext and get plaintext instead.

{bold}ECB mode{unbold}{schema}
               P1      P2                  C1      C2        
               |       |                   |       |
               |       |                   |       |
        key --AES     AES-- key     key --AES     AES-- key
               |       |                   |       |
               |       |                   |       |
               C1      C2                  P1      P2       {color}
               Encryption                  Decryption

In ECB mode, every block is encrypted/decrypted independently, which is very insecure. It means 2 equivalent plaintext blocks are encrypted in to 2 equivalent ciphertext blocks (Google for 'ECB Penguin' to see the problem). ECB mode should NOT be used anywhere for security purposes.

Repeating 128b blocks in ciphertext usually reveal that ECB mode is used. If an attacker has control of the plaintext and is able to observe resulting ciphertext, he can submit long string of identical characters. In ciphertext, this will result in repeating 128b blocks.

{bold}ECB chosen-plaintext attack{unbold}

If an attacker can read resulting ciphertext and controls a portion of plaintext, he can decrypt everything after that. Consider following blocks of ciphertext:

    {schema}|?????????????con|trolled-plainte|xt??????????????|...{color}

The attacker must first discover block alignment, this can be done by submitting a long string of identical characters and computing offset for the repeating block. Then he must align the message so one block have exactly one unknown byte:

    {schema}|?????????????AAA|AAAAAAAAAAAAAA?|????????????????|...{color}

After encryption, that block will have some value, e.g. 7ab17310f536a7cdaacbd4b06be2d2a3
Now the attacker tries all possible values for the unknown byte, one of them ('H' in this case) will yield the same ciphertext (BTW the key is 'YELLOW SUBMARINE'). Next byte will be discovered in similar fashion:
    
    {schema}|?????????????AAA|AAAAAAAAAAAAAH?|????????????????|...{color}

To execute this attack, you must compose an oracle that receives attacker-controlled plaintext and returns complete ciphertext. Then run:{command}
o = /tmp/oracle.sh
ecb-chosen-plaintext o
{color}

{bold}ECB cut-and-paste attack{unbold}

Because individual blocks in ECB mode are completely independent, nothing stops the attacker from reordering, duplicating and ommiting some of them.

Consider the following cookie before encryption:

    email=foo@bar.com&uid=10&role=user

where email is controlled by the attacker. The attacker would like very much to become the admin. In ECB mode, this is possible.

    {schema}|email=foo@bar.co|m&uid=10&role=us|er.............|{color}

First, the cookie must be properly aligned, something like:

    {schema}|email=AAAAAAAAAA|AAA&uid=10&role=|user............|{color}

Then, the attacker creates fake block holding desired value. In this case, the string 'admin' with valid PKCS#7 padding (because the implementation expects the string to replace to be at the end - if that is not your case, you must provide correct plaintext and then reorder ciphertext blocks manually).
    
    {schema}|email=AAAAAAAAAA|admin-----------|AAA&uid=10&role=|user............|
    {color:}                        ^- valid PKCS#7 padding

Finally, after encryption, the last block can be dropped and crafted block is put at the end - the ECB mode allows that. The server will decrypt the cookie as:

    {schema}|email=AAAAAAAAAA|AAA&uid=10&role=|admin-----------|{color}
                                      
To execute this attack, you must an oracle that receives the attacker-controlled string, sends that to the server and returns the ciphertext and another one that decrypts given ciphertext. Furthermore, you must define a value that is expected at the end of the plaintext and a value to replace it. Optionally, you also provide the string to be used. Then run:{command}
e_oracle = ecb/cryptopals_13_encrypt.py
d_oracle = ecb/cryptopals_13_decrypt.py
expected = user
desired = admin
payload = nul@gmail.com
x = ecb-cut-paste e_oracle d_oracle expected desired payload
{color}

If you are not able to create a decryption oracle, Langdon cannot compute offsets. In this case use {command}oracle e_oracle <payload>{color} and finish the work manually.

{bold}CBC mode{unbold}{schema}
               P1      P2                  C1      C2
               |       |                   |____   |__ ...
        IV ---(X)  ,--(X)                  |    |  |
               |   |   |            key --AES   | AES-- key
               |   |   |                   |    |  |
        key --AES  |  AES-- key            |    |  |  
               |__/    |__ ...      IV ---(X)    `(X)  
               |       |                   |       |   
               C1      C2                  P1      P2   {color}
               Encryption                  Decryption            

In CBC mode, blocks are no longer independent. In encryption, plaintext for given block is first XORed with ciphertext of previous block. For first block, a value known as Initialization Vector is used. IV should be different for every message sent, and in CBC it also must be upredictable at encryption time (unlike SSLv2, where last ciphertext block of last message has been used as the IV for new message). After encryption, the IV can be made public (often prepended to the ciphertext).
Because all blocks are entangled, AES-CBC can be used to create fixed-length authentication code - last ciphertext block is resulting MAC (while IV is usually set to 0).

{bold}CBC bitflipping{unbold}

When decrypting, ciphertext of previous block is XORed with AES decryption to get plaintext of current block. That means that attacker can accurately flip correct bits to achieve desired plaintext. Of course, the block with altered ciphertext will be destroyed.

For example, string 'some_garbage=XXXXXXXXXXX&admin=0' is encrypted with key 'YELLOW SUBMARINE' and IV f370d32fcca1e9ac9c36605b1e4e0408 as (ignoring the padding):{schema}

    P |s o m e _ g a r b a g e = X X X |X X X X X X X X & a d m i n = 0 |
    C |e2fcbc5c59b705f2e428363b1b0189c7|e99e062faa57cd4624a685252a3cb4b9|{color}

The attacker knows he must flip the very last bit in the second plaintext block. To achieve that, same bit in previous block's ciphertext must be flapped:{schema}

    C |e2fcbc5c59b705f2e428363b1b0189c6|e99e062faa57cd4624a685252a3cb4b9|{color}
                                     ^^

After decryption, entire block 1 is destroyed, but block 2 has the desired value:{schema}

    P |c9429c2a0bae8b9b83d30b4bf26a3f1b|X X X X X X X X & a d m i n = 1 |{color}
       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^                               ^^

To execute this attack, you must compose encryption and decryption oracle, provide block index that should be changed and the desired value. Run:{command}
e_oracle = cbc/cryptopals_16_encrypt.py
d_oracle = cbc/cryptopals_16_decrypt.py
payload = ';admin=true;a='

# first run oracles to see how the message will look
input = 'AAAAAAAAAAAAAAA'
c = oracle e_oracle input
p = oracle d_oracle c
hexdump p

# block index is known, now attack!
target_block = 3
x = cbc-bitflipping e_oracle d_oracle target_block payload
hexdump x
{color}

{bold}CBC padding oracle attack{unbold}

From definition of block algorithms, AES uses padding to ensure all plaintext (and therefore ciphertext) blocks are 128 bits long. PKCS#7 padding is commonly used and works as follows:

- Number of "missing bytes" is determined.
- That value is used to fill the last incomplete block.
- If block is complete, whole new padding block is appended.

Examples:
    ninja_warrior    -> ninja_warrior\\x03\\x03\\x03
    ABC              -> ABC\\x0d\\x0d\\x0d\\x0d\\x0d\\x0d\\x0d\\x0d\\x0d\\x0d\\x0d\\x0d\\x0d
    YELLOW SUBMARINE -> YELLOW SUBMARINE\\x10\\x10\\x10\\x10\\x10\\x10\\x10\\x10\\x10\\x10\\x10\\x10\\x10\\x10\\x10\\x10

When the padding is incorrect after deciphering, the message is damaged and should not be used as legitimate. However, the reason (that padding is invalid) should not be presented to the user, otherwise CBC padding oracle attack can be performed.

The CBC padding oracle attack allows the attacker to fully decrypt an encrypted message if he can use oracle to determine whether submitted ciphertext has valid padding. The plaintext will be revealed in reverse order - from the last byte of the last block. Check the decryption routine:
{schema}
        C1      C2
        |____   |__ ...
        |    |  |
 key --AES   | AES-- key
        |    |  |
     I1 |    |  | I2
        |    |  |
 IV ---(X)    `(X)  
        |       |   
        P1      P2   {color}
        Decryption  
        
        P2 = AES(C2, key) ^ C1
        P2 = I2           ^ C1

The goal is to get the value right after AES decryption, that is AES(C2, key) - let's call that Intermediate state I2. If I2 is known, the plaintext can be easily revealed by XORing the value with previous block of ciphertext (which is known). Also, as shown in the CBC bitflipping attack, we can directly manipulate resulting plaintext bits P2 with previous ciphertext block C1. 

Consider following schema of 2 successive blocks (key = 'YELLOW SUBMARINE', IV = 16 * \\x00 for simplification):

                                                               P2[15] -,   {schema}
    P: |L o r e m   i p s u m   d o l o |r   s i t   a m e t . 0505050505| (unknown)
    C: |eadcc5aa4800dff175a49cf3a0f2041d|f476548f1806681d6b265735ead1458f| {color}
                                      ^- C1[15]                      

We now want to alter the C1 block to give new plaintext: 'Lorem ipsum dolor sit amet\\x05\\x05\\x05\\x05\\x01'. The padding will now be only the last byte, \\x01. This last byte is, unlike original padding, known to the attacker. The altered C1 block shall be named C1', the plaintext block P2 with altered padding shall be named P2'. The C1' block will consist of 15 bytes of any value and the last important byte C1'[15]. The C1'[15] byte will be bruteforced - sent to oracle waiting for 'No padding error'. Two of the tries may be successful, but only one C1'[15] value will be different from the original C1[15] byte - that is what we want.

Then we can use those last bytes C1'[15] and P2'[15] to compute the last byte of the Intermediate state I2[15]:

    I2[15] = C1'[15] ^ P2'[15]

In our example, correct C1'[15] value will be \\x19, found by bruteforce (in this case \\x1d would also result into the valid padding \\x05, but we don't know the value now - we expect \\x01). I2[15] will therefore be \\x19 ^ \\x01 = \\x18. We will now use the value and original ciphertext byte C1[15] to compute correct plaintext byte P2[15]:

    P2[15] = C1[15] ^ I2[15]

In our example, we get P2[15] = \\x1d ^ \\x18 = \\x05 - the last byte in the (padded) original plaintext. Next byte is computed in similar way, just P2' will now end with \\x02\\x02 and C1' with \\x??\\x1a (the last byte is computed as I2[15] ^ P2'[15] = \\x18 ^ \\x02). Continue in the same fashion.

The first block can be decrypted only if the IV is known or guessable.


To execute this attack, you must compose an oracle that takes a ciphertext and returns 0 if the padding is correct, otherwise 1. Then run:{command}
ciphertext = ...
o = /tmp/oracle.sh
p = cbc-padding ciphertext o
{color}

{bold}CBC chosen-ciphertext attack{unbold}

If attacker is able to forge a ciphertext and get it decrypted, he can reveal the IV value. This is especially dangerous if IV and key are equivalent (this might make sense because the key has to be known to both parties anyway, so why not save some bandwidth and keep the IV secret as well?).

Attacker needs at least 3 successive blocks. From the CBC mode diagrams, the equations are:

    C1 = AES(P1 ^ IV, key)
    C2 = AES(P2 ^ C1, key)
    C3 = AES(P3 ^ C2, key)
    P1 = AES(C1, key) ^ IV
    P2 = AES(C2, key) ^ C1
    P3 = AES(C3, key) ^ C2

But if the attacker can replace blocks (C1, C2, C3) with (C1, 0, C1):

    P1 = AES(C1, key) ^ IV
    P2 = AES(0, key) ^ C1
    P3 = AES(C1, key) ^ 0
       = AES(C1, key)

    P1 = P3 ^ IV
    IV = P1 ^ P3

To execute this attack, you must compose an oracle that takes a ciphertext, sends it to the server and returns the resulting plaintext. Then run:{command}
ciphertext = ...
o = /tmp/oracle.sh
iv = cbc-chosen-ciphertext o ciphertext
hexdump iv
{color}

{bold}CTR mode{unbold}{schema}
              Nonce;Counter
                   |
            Key --AES
                   |
            P ----(X)
                   |
                   C {color}
         Encryption/Decryption

In CTR mode, encryption and decryption operations are identical, it is a simple XOR with generated keystream. That also means it can be easily used as stream cipher. The keystream itself is AES encryption of nonce (similar to IV) concatenated with counter value. See the following example for clarification (nonce = 0xdeadbeef, key = 'YELLOW SUBMARINE'):
{schema}             
    Nonce;Counter   |efbeadde000000000000000000000000|efbeadde000000000100000000000000|
    Keystream       |5f59005d4288baa18a8546f6ee4230bd|9d1bad6e2932f9398b2ee4793ee6c699|
    Plaintext       |L o r e m   i p s u m   d o l o |r   s i t   a m e t .  
    Plaintext (hex) |4c6f72656d20697073756d20646f6c6f|722073697420616d65742e
    Ciphertext      |133672382fa8d3d1f9f02bd68a2d5cd2|ef3bde075d129854ee5aca {color}

{bold}CTR fixed-nonce attack{unbold}

The issue is obvious - if you use same nonce and same key, you receive same keystream. That is:
    
         P1 = C1 ^ K
         P2 = C2 ^ K          | ^ P1
    P1 ^ P2 = P1 ^ C2 ^ K
    P1 ^ P2 = C1 ^ K ^ C2 ^ K
    P1 ^ P2 = C1 ^ C2         # and ECB Penguin's cousin is here

If captured enough ciphertexts, you transpose them (so each transposition is XORed with single byte), then XOR it with brute force and use frequency analysis to get the best. Run:{command}
c1 = ...
c2 = ...
c3 = ...
c4 = ...
...
key = ctr-fixed-nonce c1 c2 c3 c4 ... english
xor c1 key
{color}

{bold}CTR random access read/write{unbold}

Because encryption and decryption are in CTR equivalent, you can use exposed encryption routine to decrypt provided ciphertext. Of course, you can use it only in fixed-nonce situations or in systems where you include data into an existing ciphertext (imagine an encrypted drive).

To execute this attack, you must prepare an oracle that takes given plaintext and returns corresponding ciphertext. Then provide ciphertext:{command}
plaintext = file:/tmp/actually_a_ciphertext
o = /tmp/oracle.sh
oracle o plaintext
{color}

{bold}CTR bitflipping attack{unbold}

Plaintext and corresponding ciphertext are entangled by XOR operation, where change of bit in source changes only bit of the same position in target. Therefore, with specifically crafted ciphertext, we can get arbitrary plaintext. It is similar to CBC bitflipping attack, but here we are not limited by block. Assume P' is desired plaintext and C' is ciphertext modified by adversary:
    
     P = C ^ K
    P' = C' ^ K
    C' = P' ^ K
       = P' ^ P ^ C

To execute this attack, you must compose encryption and decryption oracle, provide offset and the desired value. Run:{command}
e_oracle = ctr/cryptopals_26_encrypt.py
d_oracle = ctr/cryptopals_26_decrypt.py

offset = 3
payload = ';admin=true;'
ctr-bitflipping e_oracle d_oracle offset payload
{color}

{clear}""".format(color=log.COLOR_DARK_GREEN,
                  clear=log.COLOR_NONE,
                  schema=log.COLOR_RED,
                  command=log.COLOR_BROWN,
                  bold=log.COLOR_BOLD, 
                  unbold=log.COLOR_UNBOLD).splitlines()

    def detail(self):
        try:
            print('Mode:', self.params['mode'])
        except:
            pass
        try:
            print('Block size: %s B' % self.params['blocksize'])
        except:
            pass
        try:
            print('Key:', self.params['key'].short())
        except:
            pass
        try:
            print('IV:', self.params['iv'].short())
        except:
            pass
        try:
            print('Plaintext:', self.params['plaintext'].short())
        except:
            pass
        try:
            print('Ciphertext:', self.params['ciphertext'].short())
        except:
            pass

    def encrypt(self): # AES encrypt
        plaintext = self.params['plaintext'].as_raw()
        key = self.params['key'].as_raw()
        if self.params.get('iv'):
            iv = self.params['iv'].as_raw()
        if self.params.get('nonce'):
            nonce = int(self.params['nonce'].as_int())
        cipher = AESCipher.new(key, AESCipher.MODE_ECB)
        blocksize = int(self.params['blocksize'])
        ciphertext = b''
        
        padded = pkcs7_pad(plaintext)
        blocks = [padded[i:i+blocksize] 
                  for i in range(0, len(padded), blocksize)]

        if self.params['mode'] == 'ecb':
            ciphertext = cipher.encrypt(padded)
        elif self.params['mode'] == 'cbc':
            """
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
            previous_block = iv
            for block in blocks:
                tmp = xor(block, previous_block)
                previous_block = cipher.encrypt(tmp)
                ciphertext += previous_block
        elif self.params['mode'] == 'ctr':
            """
              Nonce;Counter
                   |
            Key --AES
                   |
            P ----(X)
                   |
                   C
            """
            ciphertext = self.ctr_crypt(plaintext, cipher, nonce)

        elif not self.params['mode']:
            log.err('Mode is not specified.')
            return None
        else:
            log.err('Unsupported mode.')
            return None

        self.params['ciphertext'] = Variable(ciphertext)
        return self.params['ciphertext']

    def decrypt(self): # AES decrypt
        ciphertext = self.params['ciphertext'].as_raw()
        key = self.params['key'].as_raw()
        if self.params.get('iv'):
            iv = self.params['iv'].as_raw()
        if self.params.get('nonce'):
            nonce = int(self.params['nonce'].as_int())
        cipher = AESCipher.new(key, AESCipher.MODE_ECB)
        blocksize = int(self.params['blocksize'])
        
        padded = b''
        blocks = [ciphertext[i:i+blocksize] 
                  for i in range(0, len(ciphertext), blocksize)]
        
        if self.params['mode'] == 'ecb':
            padded = cipher.decrypt(ciphertext)
            if self.params['ignore_padding']:
                plaintext = padded
        elif self.params['mode'] == 'cbc':
            """
               C1      C2
               |____   |__ ...
               |    |  |
        key --AES   | AES-- key
               |    |  |
        IV ---(X)    `(X)
               |       |
               P1      P2
            """
            previous_block = iv
            for block in blocks:
                tmp = cipher.decrypt(block)
                padded += xor(tmp, previous_block)
                previous_block = block
            if self.params['ignore_padding']:
                plaintext = padded
        elif self.params['mode'] == 'ctr':
            """
              Nonce;Counter
                   |
            Key --AES
                   |
            P ----(X)
                   |
                   C
            """
            plaintext = self.ctr_crypt(ciphertext, cipher, nonce)
        
        else:
            log.err('Unsupported mode.')
            return None

        if self.params['mode'] in ('ecb', 'cbc') and not self.params['ignore_padding']:
            try:
                plaintext = pkcs7_unpad(padded)
            except:
                plaintext = ''
        self.params['plaintext'] = Variable(plaintext)
        return self.params['plaintext']


    def ctr_crypt(self, source, cipher, nonce):
        # Same approach for both encryption and decryption
        """
          Nonce;Counter
               |
        Key --AES
               |
        P ----(X)
               |
               C
        """
        blocks = [cipher.encrypt(bytes(bytearray(pack('<Q', nonce))
                                       + bytearray(pack('<Q', block_counter))))
                  for block_counter in range(len(source) // 16 + 1)]
        #for b in blocks:
        #    for line in hexdump(b):
        #        print(line)
        return xor(source, b''.join(blocks)[:len(source)])

    def mac(self):
        mode = self.params['mode']
        if mode == 'cbc':
            plaintext = self.params['plaintext'].as_raw()
            key = self.params['key'].as_raw()
            iv = self.params['iv'].as_raw()
            blocksize = int(self.params['blocksize'])
            
            cipher = AESCipher.new(key, AESCipher.MODE_ECB)
            padded = pkcs7_pad(plaintext)
            blocks = [padded[i:i+blocksize] 
                  for i in range(0, len(padded), blocksize)]
            previous_block = iv

            for block in blocks:
                xored = xor(block, previous_block)
                previous_block = cipher.encrypt(xored)
            return Variable(previous_block)

        else:
            log.err('Mode %s cannot be used for MAC.' % mode)
            return Variable(b'')

    def analyze(self, output_offset=0, interactive=False): # AES analysis
        # TODO
        output = []
        output.append(log.err('Analysis not implemented for', self.name, offset=output_offset, stdout=False))
        output += self.analyze_params(output_offset, interactive)
        return output


class XOR(SymmetricCipher):
    def __init__(self, **kwargs):
        super().__init__('XOR()')

        # parameters of the algorithm
        # Variable objects are expected as values
        self.params = {
            'key': None,
            'plaintext': None,
            'ciphertext': None,
        }
        # apply defined values
        for k, v in kwargs.items():
            if k in self.params.keys():
                self.params[k] = v

    @staticmethod
    def help():
        return SymmetricCipher.help() + """
{color}{bold}XOR{unbold}
XOR (also known as exclusive disjunction) is a binary operation fundamental to modern cryptography. XOR operates on bit level and can be used as stream symmetric cipher. It works as follows:{schema}

    A B | A^B
    ---------
    0 0 |  0
    0 1 |  1
    1 0 |  1
    1 1 |  0 {color}

In human words, XOR shows whether 2 given bits are different.

XOR has truly incredible properties:

    commutativity - order of operands is not relevant (A ^ B = B ^ A),
    associativity - if multiple operations are performed, their order is not relevant
                    (A ^ (B ^ C)) = ((A ^ B) ^ C),
    XOR's inverse operation is XOR again (A = B ^ C; B = A ^ C; C = A ^ B),
    A ^ A = 0,
    A ^ 0 = A.

With complete control of one operand, we are able to change any input into arbitrary output. This property is abused in bitflipping attacks. 

    A         |A t t a c k   a t   d a w n .
    A (hex)   |41747461636b206174206461776e2e
    B         |06151a060d0a4d4107541d0d124f0f
    A^B (hex) |47616e676e616d207374796c652121
    A^B       |G a n g n a m   s t y l e ! !

It is viable to use random data as keystream and XOR it with plaintext to get ciphertext. This is so-called One-Time Password, and for a reason. See what happens if same key is used more than once:
         C1 = P1 ^ K
         C2 = P2 ^ K          | ^ C1
    C1 ^ C2 = P1 ^ K ^ P2 ^ K
    C1 ^ C2 = P1 ^ P2

P1 ^ P2 is not secure at all. First of all, if we can guess alphabets used in plaintext, we greatly reduce number of possible combinations. Rule of thumb is: XORed Gray-coded bytes of similar value give result with very few binary 1's. Furthermore, an effect similar to ECB Penguin can be observed (especially in XOR of 2 BMP images).

XOR key must also be sufficiently long, ideally of plaintext's length. Short keys allow quick bruteforce (especially because key length can be discovered). Short key can create repeating patterns.

{bold}XOR detection{unbold}

If single-byte XOR key is used, total and chunk entropies do not change (it is about 0.5 for ASCII text). In histogram, columns would show same frequencies as normally, but shuffled in unusual fashion.

Entropy gets bigger as key length increases and histogram gets 'flatter'. For smaller key lengths, repeating patterns may be observed.

Also, if we can expect the plaintext has long streams of \\x00 bytes (e.g. executable files), we can see the key itself on those spots. If key is some phrase, this is very obvious.

{bold}Discovering key length{unbold}

Repeating patterns
Hamming distance
Chi test


{bold}Frequency analysis{unbold}



{clear}""".format(color=log.COLOR_DARK_GREEN,
                  clear=log.COLOR_NONE,
                  schema=log.COLOR_RED,
                  command=log.COLOR_BROWN,
                  bold=log.COLOR_BOLD, 
                  unbold=log.COLOR_UNBOLD).splitlines()

    def detail(self):
        try:
            print('Key:', self.params['key'].short())
        except:
            pass
        try:
            print('Plaintext:', self.params['plaintext'].short())
        except:
            pass
        try:
            print('Ciphertext:', self.params['ciphertext'].short())
        except:
            pass

    def encrypt(self): # XOR encrypt
        if isinstance(self.params['key'], Variable):
            key = self.params['key'].as_raw()
        elif isinstance(self.params['key'], RNG):
            key = self.params['key'].get('bytes', 
                                         len(self.params['plaintext'].as_raw()))

        self.params['ciphertext'] = Variable(
            xor(self.params['plaintext'].as_raw(), 
                key))
        return self.params['ciphertext']

    def decrypt(self): # XOR decrypt
        if isinstance(self.params['key'], Variable):
            key = self.params['key'].as_raw()
        elif isinstance(self.params['key'], RNG):
            key = self.params['key'].get('bytes', 
                                         len(self.params['ciphertext'].as_raw()))

        self.params['plaintext'] = Variable(
            xor(self.params['ciphertext'].as_raw(), 
                key))
        return self.params['plaintext']

    def update_key(self, param, new_value):
        """
        Find difference between old and new plaintext (ciphertext, respectively)
        and update the key accordingly.
        """
        if param not in ('plaintext', 'ciphertext'):
            log.err('You can only use plaintext or ciphertext to update key.')
            return
        new_key = bytearray(self.params['key'].as_raw())
        old_value = self.params[param].as_raw()
        modulos = set()

        for i in range(min([len(old_value), len(new_value)])):
            if old_value[i] != new_value[i]:
                modulo = i % len(new_key)
                if modulo not in modulos:
                    debug('Detected change at %d (modulo = %d): 0x%02x != 0x%02x' % (i, modulo, old_value[i], new_value[i]))
                    modulos.add(modulo)
                    new_key[modulo] = (new_key[modulo]
                                       ^ (old_value[i]
                                          ^ new_value[i]))
                    log.info('New key:', Variable(new_key))

        if new_key != self.params['key'].as_raw():
            debug('The key has changed, applying...')
        self.params['key'] = Variable(new_key)
        if param == 'plaintext':
            self.decrypt()
        else:
            self.encrypt()

    def analyze(self, output_offset=0, interactive=False): # XOR analysis
        # TODO
        output = []
        output.append(log.err('Analysis not implemented for', self.name, offset=output_offset, stdout=False))
        # key present in ciphertext?
        # something with key entropy?
        output += self.analyze_params(output_offset, interactive)
        return output

#############################################

class RNG(Algorithm):
    def __init__(self, name):
        super().__init__(name)
    
    @staticmethod
    def help():
        return Algorithm.help() + """
{bold}RNG{unbold}

""".format(bold=log.COLOR_BOLD, unbold=log.COLOR_UNBOLD).splitlines()


    def get(self, mode, count=1):
        if mode == 'int':
            results = [self.randint() for i in range(count)]
            # one int? return as int
            if count == 1:
                return results[0]
            # many ints? return as string, separate by newline
            else:
                return b'\n'.join(b'%d' % x for x in results)
        elif mode == 'float':
            # float(s); return as string, separate by newline
            return b'\n'.join([b'%f' % self.randfloat() for i in range(count)])
        elif mode == 'bytes':
            # bytes, return as bytes
            ints = [self.randint() for _ in range(count // 4 + 1)]
            # USING BIG ENDIANESS
            # so we can compare ints and bytes successfully 
            # (e.g. for brute_timestamp_seed)
            stream = pack('>' + self.params['packer']*len(ints), *ints)
            return stream[:count]
        else:
            log.err('Invalid mode.')
            return None
    
    def randint(self):
        raise NotImplementedError

    def randfloat(self):
        raise NotImplementedError

class MersenneTwister(RNG):
    def __init__(self, name):
        super().__init__(name)
    
    @staticmethod
    def help():
        return RNG.help() + """
    
{bold}Mersenne Twister{unbold}

""".format(bold=log.COLOR_BOLD, unbold=log.COLOR_UNBOLD).splitlines()
    
    def randint(self):
        raise NotImplementedError

    def randfloat(self):
        raise NotImplementedError


class MersenneTwister32(MersenneTwister):
    """
    https://github.com/james727/MTP/blob/master/mersenne_twister.py
    https://en.wikipedia.org/wiki/Mersenne_Twister
    https://en.wikipedia.org/wiki/Diehard_tests
    http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/mt19937-64.out.txt
    """
    def __init__(self, seed):
        super().__init__('Mersenne32()')
        self.params = {
            'w': 32,                  # bits for one state
            'n': 624,                 # number of states
            'm': 397,                 # middle word 
            'r': 31,                  # separation point of one word
            'a': 0x9908b0df,          # coefficients of the radional normal form twist matrix
            'u': 11,                  # additional 
            'd': 0xffffffff,          # additional
            's': 7,                   # TGFSR(R) tempering bit shift
            'b': 0x9D2C5680,          # TGFSR(R) tempering bit mask
            't': 15,                  # TGFSR(R) tempering bit shift
            'c': 0xEFC60000,          # TGFSR(R) tempering bit mask
            'l': 18,                  # additional
            'f': 1812433253,          # generator parameter
            'seed': seed,
            'packer': 'L',
        }
        
        self.lower_mask = (1 << self.params['r']) - 1
        self.upper_mask = 1 << self.params['r']
        self.params['index'] = self.params['n']
        self.state = [0] * self.params['n']    # states
        
        self.state[0] = int(seed)
        for i in range(1, self.params['n']):
            self.state[i] = ((self.params['f'] 
                              * (self.state[i-1] 
                                 ^ (self.state[i-1] >> (self.params['w'] - 2)))
                              + i)
                             & ((1 << self.params['w']) - 1)) # wrap to bits
    
    @staticmethod
    def help():
        return MersenneTwister.help() + """
{bold}Mersenne Twister (32b){unbold}

""".format(bold=log.COLOR_BOLD, unbold=log.COLOR_UNBOLD).splitlines()

    def twist(self):
        for i in range(self.params['n']):
            temp = (((self.state[i] & self.upper_mask)
                     + (self.state[(i+1) % self.params['n']] 
                        & self.lower_mask))
                    & ((1 << self.params['w']) - 1)) # wrap to bits
            temp_shift = temp >> 1
            if temp % 2 != 0:
                temp_shift = temp_shift ^ self.params['a']
            self.state[i] = self.state[(i + self.params['m']) % self.params['n']] ^ temp_shift
        self.params['index'] = 0

    def get_random_number(self):
        if self.params['index'] >= self.params['n']:
            self.twist()
        y = self.state[self.params['index']]
        y = y ^ (y >> self.params['u'] & self.params['d'])
        y = y ^ ((y << self.params['s']) & self.params['b'])
        y = y ^ ((y << self.params['t']) & self.params['c'])
        y = y ^ (y >> self.params['l'])
        self.params['index'] += 1
        return y

    def randint(self):
        return self.get_random_number() & ((1 << self.params['w']) - 1)
    
    def randfloat(self):
        return self.randint() / ((1 << self.params['w']) - 1)
    
    def analyze(self, output_offset=0, interactive=False): # Mersenne Twister analysis
        # TODO
        output = []
        output.append(log.err('Analysis not implemented for', self.name, offset=output_offset, stdout=False))
        output += self.analyze_params(output_offset, interactive)
        return output


class MersenneTwister64(RNG):
    def __init__(self, seed):
        super().__init__('Mersenne64()')
        self.params = {
            'w': 64,                  # bits for one state
            'n': 312,                 # number of states
            'm': 156,                 # middle word 
            'r': 31,                  # separation point of one word
            'a': 0xb5026f5aa96619e9,  # coefficients of the radional normal form twist matrix
            'u': 29,                  # additional 
            'd': 0x5555555555555555,  # additional
            's': 17,                  # TGFSR(R) tempering bit shift
            'b': 0x71D67FFFEDA60000,  # TGFSR(R) tempering bit mask
            't': 37,                  # TGFSR(R) tempering bit shift
            'c': 0xFFF7EEE000000000,  # TGFSR(R) tempering bit mask
            'l': 43,                  # additional
            'f': 6364136223846793005, # generator parameter
            'seed': seed,
            'packer': 'Q',
        }
        
        self.lower_mask = (1 << self.params['r']) - 1
        self.upper_mask = (1 << self.params['w']) - 1 - self.lower_mask #1 << self.r
        self.params['index'] = self.params['n']
        self.state = [0] * self.params['n']    # states
        
        self.state[0] = int(self.params['seed'])
        for i in range(1, self.params['n']):
            self.state[i] = ((self.params['f'] 
                              * (self.state[i-1] 
                                 ^ (self.state[i-1] >> (self.params['w'] - 2)))
                              + i)
                             & ((1 << self.params['w']) - 1)) # wrap to bits
    
    @staticmethod
    def help():
        return MersenneTwister.help() + """
{bold}Mersenne Twister (64b){unbold}

""".format(bold=log.COLOR_BOLD, unbold=log.COLOR_UNBOLD).splitlines()

    
    def twist(self):
        for i in range(self.params['n']):
            temp = (((self.state[i] & self.upper_mask)
                     + (self.state[(i+1) % self.params['n']]
                        & self.lower_mask))
                    & ((1 << self.params['w']) - 1)) # wrap to bits
            temp_shift = temp >> 1
            if temp % 2 != 0:
                temp_shift = temp_shift ^ self.params['a']
            self.state[i] = self.state[(i + self.params['m']) % self.params['n']] ^ temp_shift
        self.params['index'] = 0

    def get_random_number(self):
        if self.params['index'] >= self.params['n']:
            self.twist()
        y = self.state[self.params['index']]
        y = y ^ (y >> self.params['u'] & self.params['d'])
        y = y ^ ((y << self.params['s']) & self.params['b'])
        y = y ^ ((y << self.params['t']) & self.params['c'])
        y = y ^ (y >> self.params['l'])
        self.params['index'] += 1
        return y

    def randint(self):
        return self.get_random_number() & ((1 << self.params['w']) - 1)
    
    def randfloat(self):
        return self.randint() / ((1 << self.params['w']) - 1)

    def analyze(self, output_offset=0, interactive=False): # Mersenne Twister analysis
        # TODO
        output = []
        output.append(log.err('Analysis not implemented for', self.name, offset=output_offset, stdout=False))
        output += self.analyze_params(output_offset, interactive)
        return output

#############################################
class Hash(Algorithm):
    def __init__(self, name):
        super().__init__(name)
        self.params = {
            'data': None,
            'key': None,
            'block_size': None,
            'output_size': None,
        }
    
    @staticmethod
    def help():
        return Algorithm.help() + """
{bold}Hash{unbold}

""".format(bold=log.COLOR_BOLD, unbold=log.COLOR_UNBOLD).splitlines()

    
    def hash(self, data_modifier, bits_len=0):
        raise NotImplementedError()

    @staticmethod
    def mac_modifier(hash_algorithm):
        return hash_algorithm.params['key'].as_raw() + hash_algorithm.params['data'].as_raw()
    
    def mac(self):
        return self.hash(Hash.mac_modifier)

    @staticmethod
    def hmac_modifier(hash_algorithm):
        key = hash_algorithm.params['key'].as_raw()
        data = hash_algorithm.params['data'].as_raw()
        block_size = hash_algorithm.params['block_size']

        if len(key) > block_size:
            key = hash_algorithm.run(key) # TODO fixed correctly?
        if len(key) < block_size:
            key += b'\x00' * (block_size - len(key))
        return (xor(key, b'\x5c' * block_size)
                + hash_algorithm.__class__(data=Variable(xor(key, b'\x36' * block_size)+data)).hash())
    
    def hmac(self):
        return self.hash(Hash.hmac_modifier)

    @staticmethod
    def get_algorithm_from_digest_info(digest_info):
        """
        Return subclass whose digest_info is at the beginning of 
        provided value.
        """
        # first get all implemented hashes recursively
        hashes = set([Hash])
        while True:
            new_hashes = set(hashes)
            for h in hashes:
                for sub in h.__subclasses__():
                    new_hashes.add(sub)
            if not new_hashes.difference(hashes): # no change, we have everything
                break
            hashes = new_hashes
        hashes.remove(Hash)
        for h in hashes:
            try:
                if digest_info.startswith(h().params['digest_info'].as_raw()):
                    return h
            except:
                pass
        return None

        


class SHA1(Hash):
    def __init__(self, **kwargs):
        super().__init__('SHA1()')
        for k,v in kwargs.items():
            if k in self.params.keys():
                self.params[k] = v
        self.params['block_size'] = 64
        self.params['output_size'] = 20
        self.params['digest_info'] = Variable(b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14')
        self.tmp = {}
        self.reset()
    
    @staticmethod
    def help():
        return Hash.help() + """
{bold}SHA1{unbold}

""".format(bold=log.COLOR_BOLD, unbold=log.COLOR_UNBOLD).splitlines()


    def reset(self):
        self.tmp['h'] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
    
    def pad(self, data, bits_len=None):
        if not bits_len:
            #debug('Setting new bits_len')
            bits_len = len(data) * 8
        data += b'\x80'
        while (len(data) * 8) % 512 != 448:
            data += b'\x00'
        data += pack('>Q', bits_len)
        #debug('   appending bits_len', bits_len)
        return data
   
    def restore(self, digest):
        self.tmp['h'] = unpack('>5I', digest)

    def hash(self, data_modifier=lambda x: x.params['data'].as_raw(), bits_len=0):
        data = self.pad(data_modifier(self), bits_len)
        for chunk in chunks(data, 64):
            w = [0] * 80
            for i in range(16):
                w[i] = unpack('>I', chunk[i*4:i*4 + 4])[0]
            for i in range(16, 80):
                w[i] = rotate_left(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)

            a, b, c, d, e = tuple(self.tmp['h'])
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
            self.tmp['h'] = [(hx + val) & 0xffffffff 
                             for hx,val in zip(self.tmp['h'], (a, b, c, d, e))]
        
        result = b''.join(b'%c' % b for hx in self.tmp['h'] for b in pack('>I', hx)) # TODO immediately as Variable?
        self.params['digest'] = Variable(result)
        return result

    def analyze(self, output_offset=0, interactive=False): # SHA1 analysis
        # TODO
        output = []
        output.append(log.err('Analysis not implemented for', self.name, offset=output_offset, stdout=False))
        output += self.analyze_params(output_offset, interactive)
        return output

        
        
class MD4(Hash):
    def __init__(self, **kwargs):
        super().__init__('MD4()')
        for k,v in kwargs.items():
            if k in self.params.keys():
                self.params[k] = v
        self.params['block_size'] = 64
        self.params['output_size'] = 16
        self.tmp = {}
        self.reset()
    
    @staticmethod
    def help():
        return Hash.help() + """
{bold}MD4{unbold}

""".format(bold=log.COLOR_BOLD, unbold=log.COLOR_UNBOLD).splitlines()


    def reset(self):
        self.tmp['h'] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    
    def pad(self, data, bits_len=0):
        if not bits_len:
            bits_len = len(data) * 8
            # unlike SHA1, only last chunk is usually sent here, so
            # bits_len is specified
            # but we need this default value for length extension
        data += b'\x80'
        data += bytes((56 - len(data) % 64) % 64)
        data += pack('<Q', bits_len)
        return data
   
    def restore(self, digest):
        self.tmp['h'] = unpack('<4I', digest)

    def hash(self, data_modifier=lambda x: x.params['data'].as_raw(), bits_len=0):
        data = data_modifier(self)
        if not bits_len:
            bits_len = len(data) * 8
        ff = lambda x, y, z: ((x & y) | (~x & z))
        gg = lambda x, y, z: ((x & y) | (x & z) | (y & z))
        hh = lambda x, y, z: x ^ y ^ z

        last_chunk_altered = False
        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        while data:
            if len(data) < 64 and not last_chunk_altered:
                data = self.pad(data, bits_len=bits_len)
                last_chunk_altered = True

            chunk = data[:64]
            xx = list(unpack('<16I', chunk))
            a, b, c, d = self.tmp['h']
            for i in range(16):
                k = i
                if i % 4 == 0:
                    a = rotate_left((a + ff(b, c, d) + xx[k]) & 0xffffffff, 3)
                elif i % 4 == 1:
                    d = rotate_left((d + ff(a, b, c) + xx[k]) & 0xffffffff, 7)
                elif i % 4 == 2:
                    c = rotate_left((c + ff(d, a, b) + xx[k]) & 0xffffffff, 11)
                elif i % 4 == 3:
                    b = rotate_left((b + ff(c, d, a) + xx[k]) & 0xffffffff, 19)
            for i in range(16):
                k = i // 4 + (i % 4) * 4
                if i % 4 == 0:
                    a = rotate_left((a + gg(b, c, d) + xx[k] + 0x5a827999) & 0xffffffff, 3)
                elif i % 4 == 1:
                    d = rotate_left((d + gg(a, b, c) + xx[k] + 0x5a827999) & 0xffffffff, 5)
                elif i % 4 == 2:
                    c = rotate_left((c + gg(d, a, b) + xx[k] + 0x5a827999) & 0xffffffff, 9)
                elif i % 4 == 3:
                    b = rotate_left((b + gg(c, d, a) + xx[k] + 0x5a827999) & 0xffffffff, 13)
            for i in range(16):
                k = order[i]
                if i % 4 == 0:
                    a = rotate_left((a + hh(b, c, d) + xx[k] + 0x6ed9eba1) & 0xffffffff, 3)
                elif i % 4 == 1:
                    d = rotate_left((d + hh(a, b, c) + xx[k] + 0x6ed9eba1) & 0xffffffff, 9)
                elif i % 4 == 2:
                    c = rotate_left((c + hh(d, a, b) + xx[k] + 0x6ed9eba1) & 0xffffffff, 11)
                elif i % 4 == 3:
                    b = rotate_left((b + hh(c, d, a) + xx[k] + 0x6ed9eba1) & 0xffffffff, 15)

            self.tmp['h'] = [(x + y) & 0xffffffff for x,y in zip(self.tmp['h'], (a, b, c, d))]
            data = data[64:]

        result = b''.join(b'%c' % b for hx in self.tmp['h'] for b in pack('<I', hx))
        self.params['digest'] = Variable(result)
        return result

    def analyze(self, output_offset=0, interactive=False): # MD4 analysis
        # TODO
        output = []
        output.append(log.err('Analysis not implemented for', self.name, offset=output_offset, stdout=False))
        output += self.analyze_params(output_offset, interactive)
        return output

######################################################

class AsymmetricCipher(Algorithm):
    def __init__(self, name):
        super().__init__(name)
    
    @staticmethod
    def help():
        return Algorithm.help() + """
{bold}Asymmetric Cipher{unbold}

""".format(bold=log.COLOR_BOLD, unbold=log.COLOR_UNBOLD).splitlines()


class DH(AsymmetricCipher):
    def __init__(self, **kwargs):
        super().__init__('DH()')
        self.params = {
            'g': None,      # the base
            'p': None,      # the modulus
            'priv': None,   # private key
            'pub': None,    # public key
            'shared': None, # shared key
        }
        # apply defined values
        for k, v in kwargs.items():
            if k in self.params.keys():
                self.params[k] = Variable(v)

        if not self.params['g']:
            log.warn('The \'g\' parameter (generator; base) is not specified.')
        if not self.params['p']:
            log.warn('The \'p\' parameter (exponent) is not specified.')
        # generate unspecified values
        if not self.params['priv']:
            self.params['priv'] = Variable(random.randint(0, 2**16)) # TODO what value?
        if not self.params['pub']:
            self.params['pub'] = Variable(pow(int(self.params['g'].as_int()), 
                                              int(self.params['priv'].as_int()), 
                                              int(self.params['p'].as_int())))
    @staticmethod
    def help():
        return AsymmetricCipher.help() + """
{bold}Diffie-Hellman{unbold}

""".format(bold=log.COLOR_BOLD, unbold=log.COLOR_UNBOLD).splitlines()

    
    def analyze(self, output_offset=0, interactive=False): # DH analysis
        # TODO
        output = []
        output.append(log.err('Analysis not implemented for', self.name, offset=output_offset, stdout=False))
        output += self.analyze_params(output_offset, interactive)
        return output


class SRP(AsymmetricCipher):
    def __init__(self, name):
        super().__init__(self, name)
    
    @staticmethod
    def help():
        return AsymmetricCipher.help() + """
{bold}SRP{unbold}

""".format(bold=log.COLOR_BOLD, unbold=log.COLOR_UNBOLD).splitlines()

class SRPClient(AsymmetricCipher):
    def __init__(self, **kwargs):
        super().__init__('SRPClient()')
        self.params = {
            'N': None,
            'g': None,
            'k': None,
            'a': None,
            'username': None,
            'password': None,
        }
        # apply defined values
        for k, v in kwargs.items():
            if k in self.params.keys():
                self.params[k] = Variable(v)
        # generate keypair
        self.params['a'] = Variable(random.randint(0, 65536))
        self.params['A'] = Variable(pow(self.params['g'].as_int(),
                                        self.params['a'].as_int(),
                                        self.params['N'].as_int()))
    
    @staticmethod
    def help():
        return SRP.help() + """
{bold}SRP Client{unbold}

""".format(bold=log.COLOR_BOLD, unbold=log.COLOR_UNBOLD).splitlines()


    def get_auth_hash(self):
        try:
            return Variable(SHA1(data=self.params['S']).hash())
        except:
            return None

    def compute_session_key(self, salt, pubkey):
        salt = salt.as_raw()
        if pubkey.as_int() % self.params['N'].as_int() == 0:
            log.warn('Client received zero public key (mod N), it is insecure now.')
        hashed = Variable(SHA1(data=Variable(salt + self.params['password'].as_raw())).hash())

        # compute random scrambling parameter
        self.params['u'] = Variable(SHA1(data=Variable(self.params['A'].as_raw() + pubkey.as_raw())).hash())
        if self.params['u'].as_int() == 0:
            log.warn('Client computed zero scrambler, it is insecure now.')

        # compute session key
        self.params['S'] = Variable(pow((pubkey.as_int() 
                                         - self.params['k'].as_int()
                                         * pow(self.params['g'].as_int(),
                                               hashed.as_int(),
                                               self.params['N'].as_int())),
                                        (self.params['a'].as_int() 
                                         + self.params['u'].as_int()
                                         * hashed.as_int()),
                                        self.params['N'].as_int()))
        debug('Client computed session key:', self.params['S'])
    
    def analyze(self, output_offset=0, interactive=False): # SRP Client analysis
        # TODO
        output = []
        output.append(log.err('Analysis not implemented for', self.name, offset=output_offset, stdout=False))
        output += self.analyze_params(output_offset, interactive)
        return output


class SRPServer(AsymmetricCipher):
    def __init__(self, **kwargs):
        super().__init__('SRPServer()')
        self.params = {
            'N': None,
            'g': None,
            'k': None,
            'b': None,
        }
        # apply defined values
        for k, v in kwargs.items():
            if k in self.params.keys():
                self.params[k] = Variable(v)
        self.tmp = {
            'accounts': {},
        }
        # generate private key
        self.params['b'] = Variable(random.randint(0, 65536)) # TODO maybe new for each client?
    
    @staticmethod
    def help():
        return SRP.help() + """
{bold}SRP Server{unbold}

""".format(bold=log.COLOR_BOLD, unbold=log.COLOR_UNBOLD).splitlines()

    
    def register(self, username, password):
        username = username.as_raw()
        password = password.as_raw()
        # generate salt
        salt = bytes([random.getrandbits(8) for _ in range(16)])
        # store username, salt and password verifier
        hashed = Variable(SHA1(data=Variable(salt + password)).hash())
        verifier = pow(self.params['g'].as_int(),
                       hashed.as_int(),
                       self.params['N'].as_int())
        self.tmp['accounts'][username] = (salt, verifier)
        debug('User %s registered:' % username, self.tmp['accounts'][username])

    def compute_session_key(self, username, pubkey):
        username = username.as_raw()
        if pubkey.as_int() % self.params['N'].as_int() == 0:
            log.warn('Server received zero public key (mod N), it is insecure now.')
        # get verifier for user
        if username not in self.tmp['accounts'].keys():
            return (None, None)
        salt, verifier = self.tmp['accounts'][username]
        # generate own pubkey # UNIQUE for each client!
        self.params['B'] = Variable(self.params['k'].as_int() 
                                    * verifier
                                    + pow(self.params['g'].as_int(),
                                          self.params['b'].as_int(),
                                          self.params['N'].as_int()))

        # compute random scrambling parameter
        self.params['u'] = Variable(SHA1(data=Variable(pubkey.as_raw() + self.params['B'].as_raw())).hash())

        # compute session key
        self.params['S'] = Variable(pow(pubkey.as_int() * pow(verifier,
                                                              self.params['u'].as_int(),
                                                              self.params['N'].as_int()),
                                        self.params['b'].as_int(),
                                        self.params['N'].as_int()))
        debug('Server computed session key:', self.params['S'])
        return (Variable(salt), self.params['B'])

    def auth(self, key_hash):
        if key_hash.as_raw() == SHA1(data=self.params['S']).hash():
            return True
        return False

    def analyze(self, output_offset=0, interactive=False): # SRP Server analysis
        # TODO
        output = []
        output.append(log.err('Analysis not implemented for', self.name, offset=output_offset, stdout=False))
        output += self.analyze_params(output_offset, interactive)
        return output



class RSA(AsymmetricCipher):
    def __init__(self, **kwargs):
        super().__init__('RSA()')
        self.params = {
            'p': None,              # prime number
            'q': None,              # prime number
            'n': None,              # p*q
            'et': None,             # totient(p, q)
            'e': Variable(65537),   # public key
            'd': None,              # private key
            'bits': Variable(1024), # n bit length
            'plaintext': None,
            'ciphertext': None,
            'padding': False,       # PKCS #1v1.5
        }
        # apply defined values
        for k, v in kwargs.items():
            if k in self.params.keys():
                self.params[k] = Variable(v)

        # generate and validate parameters
        p = self.params['p'].as_int() if self.params.get('p') else None
        q = self.params['q'].as_int() if self.params.get('q') else None
        n = self.params['n'].as_int() if self.params.get('n') else None
        et = self.params['et'].as_int() if self.params.get('et') else None
        e = self.params['e'].as_int() if self.params.get('e') else None
        d = self.params['d'].as_int() if self.params.get('d') else None
        
        if d and e and n:
            # priv, pub
            # ok, just check at the end
            pass
        elif e and n:
            # pub, can encrypt and verify
            # ok, just check at the end
            pass
        elif d and n:
            # priv, can decrypt and sign
            # ok, just check at the end
            pass
        else:
            # no valid config, generate missing
            # generate p, q (use what is given)
            debug('Generating undefined values...')
            pq_generated = False   
            while True:
                if n:
                    if p and not q:
                        q = n // p
                    elif q and not p:
                        p = n // q
                elif et:
                    if p and not q:
                        q = et / (p - 1) + 1
                    elif q and not p:
                        p = et / (q - 1) + 1
                else:
                    if not p:
                        p = prime(self.params['bits'].as_int() // 2)
                        pq_generated = True
                    if not q:
                        q = prime(self.params['bits'].as_int() // 2)
                        pq_generated = True
                
                # compute n, et (use what is given)
                if not n:
                    n = p * q
                if not et:
                    et = (p - 1) * (q - 1)
                
                # compute d
                if not d:
                    d = invmod(e, et)
                # try again if invalid
                if pq_generated and not d:
                    p = self.params['p'].as_int() if self.params.get('p') else None
                    q = self.params['q'].as_int() if self.params.get('q') else None
                    n = self.params['n'].as_int() if self.params.get('n') else None
                    et = self.params['et'].as_int() if self.params.get('et') else None
                    continue
                break
            
        # parameter assertion
        if (p and q and p * q != n or
            p and q and (p - 1) * (q - 1) != et or
            e and et and invmod(e, et) != d):
            log.err('Invalid RSA configuration (parameters do not match).')
        else:
            self.params['p']  = Variable(p)  if p  else None
            self.params['q']  = Variable(q)  if q  else None
            self.params['n']  = Variable(n)  if n  else None
            self.params['et'] = Variable(et) if et else None
            self.params['d']  = Variable(d)  if d  else None
            self.params['e']  = Variable(e)  if e  else None


    @staticmethod
    def help():
        return AsymmetricCipher.help() + """
{bold}RSA{unbold}

""".format(bold=log.COLOR_BOLD, unbold=log.COLOR_UNBOLD).splitlines()

    def encrypt(self):
        if self.params['padding']:
            # TODO check padding_string for no zeros?
            padding_string = random_bytes(self.params['bits'].as_int() // 8 - 3 - len(self.params['plaintext'].as_raw()))
            plaintext = Variable(b'\x00\x02' + padding_string + b'\x00' + self.params['plaintext'].as_raw()).as_int()
        else:
            plaintext = self.params['plaintext'].as_int()
        try:
            result = pow(plaintext,
                         self.params['e'].as_int(),
                         self.params['n'].as_int())
            self.params['ciphertext'] = Variable(result)
            return self.params['ciphertext']
        except:
            traceback.print_exc()
    
    def decrypt(self):
        try:
            result = pow(self.params['ciphertext'].as_int(),
                         self.params['d'].as_int(),
                         self.params['n'].as_int())
            # TODO remove padding
            self.params['plaintext'] = Variable(result)
            return self.params['plaintext']
        except:
            traceback.print_exc()

    def sign(self, hash_algorithm):
        hash_instance = hash_algorithm(data=self.params['plaintext'])
        try:
            digest_info = hash_instance.params['digest_info'].as_raw() # constant value
        except:
            log.err('Hashing algorithm is not supported (unknown digest_info).')
            return None
        h = Variable(hash_instance.hash())
        block = Variable(b'\x00\x01'
                         + b'\xff' * max(8, len(self.params['plaintext'].as_raw()) - len(digest_info) - 3)
                         + b'\x00'
                         + digest_info
                         + h.as_raw())
        result = pow(block.as_int(),
                     self.params['d'].as_int(),
                     self.params['n'].as_int())
        return Variable(result)


    def verify(self, signature, hash_algorithm, bleichenbacher=False):
        decrypted = Variable(pow(signature.as_int(),
                                 self.params['e'].as_int(),
                                 self.params['n'].as_int()))
        debug('decrypted:', decrypted.as_raw())
        # remove the padding
        padding_match = re.match(b'\x01(\xff+)\x00', decrypted.as_raw())
        if not padding_match:
            debug('Incorrect padding.')
            return False

        fs = padding_match.groups(1)[0]
        asn_and_hash = decrypted.as_raw()[len(fs) + 2:]
        
        if hash_algorithm:
            hash_algorithm = hash_algorithm(data=self.params['plaintext'])
        else:
            # get hash type from DigestInfo
            try:
                hash_algorithm = Hash.get_algorithm_from_digest_info(asn_and_hash)(data=self.params['plaintext'])
            except:
                debug('Unknown ASN.1 DigestInfo.')
                return False

        # get correct hash, verify given hash has no garbage after it
        hash_offset = len(fs) + 2 + len(hash_algorithm.params['digest_info'].as_raw())
        given_hash = decrypted.as_raw()[hash_offset:hash_offset+hash_algorithm.params['output_size']]
        if not bleichenbacher and hash_offset + len(given_hash) != len(decrypted.as_raw()):
            debug('Hash not at the end of the signature. Hello, Mr. Bleichenbacher!')
            return False
        
        # check plaintext length vs padding
        if not bleichenbacher and len(fs) != max(8, len(self.params['plaintext'].as_raw()) - len(hash_algorithm.params['digest_info'].as_raw()) - 3):
            debug('Incorrect padding length.')
            return False

        # compare hashes
        correct_hash = hash_algorithm.hash()
        debug('given hash:  ', given_hash)
        debug('correct hash:', correct_hash)
        if correct_hash == given_hash:
            debug('Signature is OK.')
            return True
        else:
            debug('Hash is different.')
            return False
        return False


        
    def analyze(self, output_offset=0, interactive=False): # RSA analysis
        # TODO
        output = []
        output.append(log.err('Analysis not implemented for', self.name, offset=output_offset, stdout=False))
        output += self.analyze_params(output_offset, interactive)
        return output


class DSA(AsymmetricCipher):
    def __init__(self, **kwargs):
        super().__init__('DSA()')
        self.params = {
            'l': Variable(1024), # TODO use 3072, 256 as default 
            'n': Variable(160),  # after pqg generation is implemented
            'p': Variable(0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1),
            'q': Variable(0xf4f47f05794b256174bba6e9b396a7707e563c5b),
            'g': Variable(0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291),
            'plaintext': None,
            'ciphertext': None,
            'x': None,
            'y': None,
        }
        # apply defined values
        for k, v in kwargs.items():
            if k in self.params.keys():
                self.params[k] = Variable(v)

        # TODO implement automatic parameter generation
        # using l and n as bit lengths for p and q, respectively

        # generate private key
        g = self.params['g'].as_int()
        p = self.params['p'].as_int()
        q = self.params['q'].as_int()

        x = int(random.random() * q)
        self.params['x'] = Variable(x)
        # compute public key
        # actually public key is (p, q, g, y)
        y = pow(g, x, p)
        self.params['y'] = Variable(y)

        # overwrite private/public parts, discard computed ones
        for k in ('x', 'y'):
            if k in self.params.keys() and k in kwargs.keys():
                self.params[k] = Variable(kwargs[k])
        

    @staticmethod
    def help():
        return AsymmetricCipher.help() + """
{bold}DSA{unbold}

""".format(bold=log.COLOR_BOLD, unbold=log.COLOR_UNBOLD).splitlines()

    def encrypt(self):
        log.warn('DSA cannot be used for encryption/decryption.')
        return b''

    def decrypt(self):
        log.warn('DSA cannot be used for encryption/decryption.')
        return b''

    def sign(self, hash_algorithm):
        n = self.params['n'].as_int()
        p = self.params['p'].as_int()
        q = self.params['q'].as_int()
        g = self.params['g'].as_int()
        x = self.params['x'].as_int()
        plaintext = self.params['plaintext']

        if g == 0:
            log.err('The g parameter cannot be zero!')
            return 0
        hash_instance = hash_algorithm(data=plaintext)
        h = Variable(hash_instance.hash()).as_int()

        # signature
        r = 0
        s = 0
        while s == 0:
            # generate signature key
            try:
                # user-defined value
                k = self.params['k'].as_int()
            except:
                k = int(random.random() * q)
            r = pow(g, k, p) % q
            if r == 0:
                continue
            s = invmod(k, q) * (h + x * r) % q
        return Variable((r << n) + s) # concatenated
        
    def verify(self, signature, hash_algorithm):
        if not hash_algorithm:
            log.err('You must specify hash algorithm.')
            return False

        n = self.params['n'].as_int()
        p = self.params['p'].as_int()
        q = self.params['q'].as_int()
        g = self.params['g'].as_int()
        y = self.params['y'].as_int()

        
        signature = signature.as_int()
        r = signature >> n
        s = signature & ((1 << n) - 1)
        if not 0 < r < q or not 0 < s < q:
            return False

        hash_instance = hash_algorithm(data=self.params['plaintext'])
        h = Variable(hash_instance.hash()).as_int()

        w = invmod(s, q)
        u1 = (h * w) % q
        u2 = (r * w) % q
        v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
        return v == r

    def analyze(self, output_offset=0, interactive=False): # DSA analysis
        # TODO
        output = []
        output.append(log.err('Analysis not implemented for', self.name, offset=output_offset, stdout=False))
        output += self.analyze_params(output_offset, interactive)
        return output
