#!/usr/bin/python3
"""
"""

#import subprocess
#import sys
import base64
import pdb
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
            r, o, e = run_command('%s "%s"' % (self.oracle_path, 
                                             base64.b64encode(payload).decode()))
            #print(r, o, e)
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
                        {0: payload},
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
        output.append(log.info('Length (B):       ', len(self.as_raw()), offset=output_offset, stdout=False))
        output.append(log.info('Unique byte count:', ubc, ubc_hints.get(ubc) or '', offset=output_offset, stdout=False))
        output.append(log.info('Entropy:          ', ent, entropy_hint, offset=output_offset, stdout=False))
        # ECB detection
        if find_repeating_patterns(self.value, min_size=16):
            output.append(log.warn('Repeating patterns of blocksize=16 found, this could be AES-ECB ciphertext.', offset=output_offset, stdout=False))

        # TODO more
        return output

    """
    representation methods
    """
    def as_int(self):
        return str(bytes_to_int(self.value))

    def as_hex(self):
        return '0x' + ''.join('%02x' % c for c in self.value)

    def as_raw(self):
        return self.value
    
    def as_binary(self):
        return binary(self.as_raw()).decode()

    def as_escaped(self):
        #  \xAA values
        return ''.join('\\x%02x' % c for c in self.value)

    def as_base64(self):
        return base64.b64encode(self.value).decode()

    def as_algorithm(self):
        return str(self.value)

    def short(self):
        preferred = self.preferred_form()
        for continuation, replaces in [
            ('...', [('\x0a', '\\n'), ('\x0d', '\\r')], ),
            (b'...', [(b'\x0a', b'\\n'), (b'\x0d', b'\\r')], ),
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
            print('Block size: %s B', self.params['blocksize'])
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

        # TODO langdon-cli had ignore_padding flag...
        #      ... maybe for CBC oracle?
        try:
            plaintext = pkcs7_unpad(padded)
        except IndexError:
            # no padding (e.g. for CTR), continue
            pass
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
        self.params['ciphertext'] = Variable(
                                        xor(self.params['plaintext'].as_raw(), 
                                            self.params['key'].as_raw()))
        return self.params['ciphertext']

    def decrypt(self): # XOR decrypt
        self.params['plaintext'] = Variable(
                                        xor(self.params['ciphertext'].as_raw(), 
                                            self.params['key'].as_raw()))
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
