#!/usr/bin/python3
"""
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

from Crypto.Cipher import AES

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
    def __init__(self, payload_id, ret, output, error):
        self.payload_id = payload_id
        self.ret = ret
        self.output = output
        self.error = error

class Oracle(threading.Thread):
    """
    Runs given program (oracle) for given payloads providing one argument.

    Internally, the argument is encoded as Base64 to prevent problems.
    
    Desired results (selected by validate argument) are stored in self.matching
    list as OracleResults.
    The validate argument takes form of 
    (lambda id,return_value,output,error,**kwargs: bool).

    Payloads are given in dictionary, so they can be processed as threads.
    
    Oracle can terminate on first matching result.

    Time of the oracle processing is measured and stored in self.time.
    """
    def __init__(
            self, 
            oracle_path, 
            payloads, 
            validate, 
            break_on_success=True,
            **kwargs):
        threading.Thread.__init__(self)
        self.oracle_path = oracle_path
        self.payloads = payloads
        #print('Payloads:', payloads.keys())
        self.matching = []
        self.validate = validate
        self.break_on_success = break_on_success
        self.kwargs = kwargs
        self.time = None
        
    def run(self):
        """
        Sends payloads to given oracle, successful results 
        (validated by self.validate() function) are stored in 
        self.matching.

        The payload is internally base64-encoded.
        Oracle output is expected to be base64-encoded.
        """
        start = time.time()
        for payload_id, payload in self.payloads.items():
            #debug('Oracle testing 0x%02x' % payload_id, payload)
            payload_based = base64.b64encode(payload).decode()
            #print('based payload:', payload_based)
            r, o, e = run_command('%s "%s"' % (self.oracle_path, 
                                               payload_based))
            #print('result:', r, o, e)
            o = base64.b64decode(o)
            if self.validate(payload_id, r, o, e, self.kwargs):
                #debug('Payload 0x%02x matches condition!' % payload_id)
                self.matching.append(OracleResult(payload_id, r, o, e))
                if self.break_on_success:
                    break
        self.time = time.time() - start

    @staticmethod
    def once(payload, oracle_path):
        """
        Quick method to run an oracle with given payload and receive output.
        """
        #print('RUNNING', oracle_path)
        #print('payload:', payload)
        #for line in hexdump(payload):
        #    print(line)
        oracle = Oracle(oracle_path,
                        {0: (payload.as_raw() 
                             if isinstance(payload, Variable) 
                             else payload)},
                        lambda i,r,o,e,kw: True)
        oracle.start()
        oracle.join()
        #debug('once result:', oracle.matching[0].output)
        #for line in hexdump(oracle.matching[0].output):
        #    print(line)
        if oracle.matching[0].error:
            debug('Oracle has some error output:', oracle.matching[0].error)
        result = oracle.matching[0].output
        return result

####################################################
class Variable:
    """
    Class loads given value (from user, file, etc.)
    and can yield different representations.
    """
    def __init__(self, value, constant=False):
        self.preferred_form = self.as_escaped

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
                        self.value = f.read().encode()
                        self.preferred_form = self.as_raw
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
        # value as int
        try:
            self.value = int_to_bytes(int(value))
            self.preferred_form = self.as_int
            return
        except:
            pass
        # value as hex number/stream
        try:
            to_unhex = value[2:] if value.startswith('0x') else value
            self.value = unhexadecimal(to_unhex)
            #self.value = int_to_bytes(int(value, 16))
            self.preferred_form = self.as_hex
            return
        except:
            pass
        # finally, use as string
        if constant:
            self.value = value.encode()
            self.preferred_form = self.as_raw
            return
            
        log.err('Not parsed!', value)

    def analyze(self, output_offset=0, interactive=False): # Variable analysis
        output = []
        # get basic statistics 
        ent = entropy(self.value)
        his = histogram(self.value)
        ubc = len(set(self.value)) # unique byte count
        entropy_hint = ''
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
        # ECB detection
        if find_repeating_patterns(self.value, min_size=16):
            output.append(log.warn('Repeating patterns of blocksize=16 found, this could be AES-ECB ciphertext.', offset=output_offset, stdout=False))

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
        #return ''.join('\\x%02x' % c for c in self.value)
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
            return preferred.decode()
        return preferred
        
    def __str__(self):
        preferred = self.preferred_form()
        if type(preferred) == bytes:
            return preferred.decode()
        if type(preferred) == int:
            return str(preferred)
        return preferred


#############################################

class Algorithm:
    def __init__(self, name):
        self.name = name
        # important parameters of given algorithm, e.g. plaintext, key, ...
        self.params = {}
        # temporary stuff for remembering some states
        self.tmp = {}

    def short(self):
        return(self.name)

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


class SymmetricCipher(Algorithm):
    def __init__(self, name):
        super().__init__(name)


class AESAlgorithm(SymmetricCipher):
    def __init__(self, **kwargs):
        super().__init__('AESAlgorithm()')
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
        cipher = AES.new(key, AES.MODE_ECB)
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
        cipher = AES.new(key, AES.MODE_ECB)
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
                traceback.print_exc()
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
                  for block_counter in range((len(source) // 16) + 1)]
        return xor(source, b''.join(blocks)[:len(source)])


    def analyze(self, output_offset=0, interactive=False): # AES analysis
        # TODO
        output = []
        output.append(log.err('Analysis not implemented for', self.name, offset=output_offset, stdout=False))
        output += self.analyze_params(output_offset, interactive)
        return output


class XORAlgorithm(SymmetricCipher):
    def __init__(self, **kwargs):
        super().__init__('XORAlgorithm()')

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


class MersenneTwister32(RNG):
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
    
    def analyze(self, output_offset=0, interactive=False): # AES analysis
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

    def analyze(self, output_offset=0, interactive=False): # AES analysis
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
    
    def hash(self, data_modifier):
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
            key = self.__class__.run(key)
        if len(key) < block_size:
            key += b'\x00' * (block_size - len(key))
        return (xor(key, b'\x5c' * block_size)
                    + hash_algorithm.__class__(data=Variable(xor(key, b'\x36' * block_size)+data)).hash())
    
    def hmac(self):
        return self.hash(Hash.hmac_modifier)


class SHA1(Hash):
    def __init__(self, **kwargs):
        super().__init__('SHA1()')
        for k,v in kwargs.items():
            if k in self.params.keys():
                self.params[k] = v
        self.params['block_size'] = 64
        self.params['output_size'] = 20
        self.tmp = {}
        self.reset()

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
        #debug('  Hashing data of len', len(data))
        #debug('   Hashing padded:', data)
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
        #print('SHA1 values:', ['%08x' % hx for hx in h], end=' ')
        result = b''.join(b'%c' % b for hx in self.tmp['h'] for b in pack('>I', hx))
        self.params['digest'] = Variable(result)
        #debug('final state:', ['0x%x' % hh for hh in self.tmp['h']])
        return result

    def analyze(self, output_offset=0, interactive=False): # AES analysis
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
        #debug('   appending bits_len', bits_len)
        return data
   
    def restore(self, digest):
        self.tmp['h'] = unpack('<4I', digest)

    def hash(self, data_modifier=lambda x: x.params['data'].as_raw(), bits_len=0):
        data = data_modifier(self)
        #debug('  Hashing data of len', len(data))
        #debug('   Hashing padded:', data)
        if not bits_len:
            bits_len = len(data) * 8
        F = lambda x, y, z: ((x & y) | (~x & z))
        G = lambda x, y, z: ((x & y) | (x & z) | (y & z))
        H = lambda x, y, z: x ^ y ^ z

        #print('DEFAULT:', hexadecimal(b''.join(b'%c' % b for x in h for b in pack('<I', x))))

        last_chunk_altered = False
        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        while data:
            if len(data) < 64 and not last_chunk_altered:
                data = self.pad(data, bits_len=bits_len)
                last_chunk_altered = True
            #print('after padding (len %d):' % len(payload))
            #print(payload)
            #print()

            chunk = data[:64]
            #debug('chunk', chunk, len(chunk))
            X = list(unpack('<16I', chunk))
            a, b, c, d = self.tmp['h']
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

            self.tmp['h'] = [(x + y) & 0xffffffff for x,y in zip(self.tmp['h'], (a, b, c, d))]
            data = data[64:]

        result = b''.join(b'%c' % b for hx in self.tmp['h'] for b in pack('<I', hx))
        self.params['digest'] = Variable(result)
        return result

    def analyze(self, output_offset=0, interactive=False): # AES analysis
        # TODO
        output = []
        output.append(log.err('Analysis not implemented for', self.name, offset=output_offset, stdout=False))
        output += self.analyze_params(output_offset, interactive)
        return output

######################################################

class AsymmetricCipher(Algorithm):
    def __init__(self, name):
        super().__init__(name)

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
    
    def analyze(self, output_offset=0, interactive=False): # AES analysis
        # TODO
        output = []
        output.append(log.err('Analysis not implemented for', self.name, offset=output_offset, stdout=False))
        output += self.analyze_params(output_offset, interactive)
        return output


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
    
    def analyze(self, output_offset=0, interactive=False): # AES analysis
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

    def analyze(self, output_offset=0, interactive=False): # AES analysis
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
            'bits': Variable(1024), # p,q bits length
            'plaintext': None,
            'ciphertext': None,
        }
        # apply defined values
        for k, v in kwargs.items():
            if k in self.params.keys():
                self.params[k] = Variable(v)

        debug('Filling undefined values...')
        if not any(self.params[x] for x in ('p', 'q', 'n', 'et')):
            self.params['p'] = Variable(prime(self.params['bits'].as_int()))
            self.params['q'] = Variable(prime(self.params['bits'].as_int()))
            self.params['n'] = Variable(self.params['p'].as_int() * self.params['q'].as_int())
            self.params['et'] = Variable((self.params['p'].as_int() - 1) 
                                          * (self.params['q'].as_int() - 1))
        # try to compute private key
        if self.params['e'] and self.params['et']:
            self.params['d'] = Variable(invmod(self.params['e'].as_int(), 
                                               self.params['et'].as_int()))

    def encrypt(self):
        try:
            result = pow(self.params['plaintext'].as_int(),
                         self.params['e'].as_int(),
                         self.params['n'].as_int())
            self.params['ciphertext'] = Variable(result)
            return result
        except:
            traceback.print_exc()
    
    def decrypt(self):
        try:
            result = pow(self.params['ciphertext'].as_int(),
                         self.params['d'].as_int(),
                         self.params['n'].as_int())
            self.params['plaintext'] = Variable(result)
            return result
        except:
            traceback.print_exc()

    def analyze(self, output_offset=0, interactive=False): # AES analysis
        # TODO
        output = []
        output.append(log.err('Analysis not implemented for', self.name, offset=output_offset, stdout=False))
        output += self.analyze_params(output_offset, interactive)
        return output


