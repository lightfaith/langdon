#!/usr/bin/python3
"""
"""

#import subprocess
#import sys
import base64
import threading

from source.lib import *

"""
Vital classes
"""
class Parallelizer():
    # TODO terminate stuff
    def __init__(self, thread_count, data, function):
        self.thread_count = thread_count
        self.data = data
        self.function = function
        self.threads = []
        self.results = []

    def start(self):
        chunk_size = len(self.data) // self.thread_count
        if not chunk_size:
            chunk_size = 1
        indexed_data = list(enumerate(self.data, 1))
        data_chunks = [indexed_data[i:i+chunk_size] 
                       for i in range(0, len(indexed_data), chunk_size)]
        self.threads = [ParallelizerThread(data_chunks[i], self.function)
                        for i in range(len(data_chunks))]
        for t in self.threads:
            t.start()

    def waitfor(self):
        for t in self.threads:
            t.join()
            self.results += t.results


class ParallelizerThread(threading.Thread):
    # TODO terminate stuff...
    def __init__(self, data, function):
        threading.Thread.__init__(self)
        self.data = data
        self.function = function
        self.results = []

    def run(self):
        indices, samples = zip(*self.data)
        print('Running thread (samples %d through %d).' 
              % (indices[0], indices[-1]))
        self.results = self.function(indices, samples)


class OracleResult:
    def __init__(self, payload_id, ret, output, error):
        self.payload_id = payload_id
        self.ret = ret
        self.output = output
        self.error = error

class Oracle(threading.Thread):
    """

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
        
    def run(self):
        """
        Sends payloads to given oracle, successful results 
        (validated by self.validate() function) are stored in 
        self.matching.

        The payload is internally base64-encoded.
        """
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

