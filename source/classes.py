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
from source.lib import *
from source.functions import binary

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
        """
        start = time.time()
        for payload_id, payload in self.payloads.items():
            #print('Oracle testing 0x%02x' % payload_id)
            r, o, e = run_command('%s "%s"' % (self.oracle_path, 
                                             base64.b64encode(payload).decode()))
            #print(r, o, e)
            if self.validate(payload_id, r, o, e, self.kwargs):
                #print('Payload 0x%02x matches condition!' % payload_id)
                self.matching.append(OracleResult(payload_id, r, o, e))
                if self.break_on_success:
                    break
        self.time = time.time() - start


class Algorithm:
    def __init__(self):
        pass

class Variable:
    """
    Class loads given value (from user, file, etc.)
    and can yield different representations.
    """
    def __init__(self, value, constant=False):
        self.preferred_form = self.as_escaped

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
                    log.err('Cannot decode as Base64.')
                    self.value = b''

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
            self.value = int_to_bytes(int(value, 16))
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


