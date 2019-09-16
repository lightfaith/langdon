#!/usr/bin/python3
from source.classes import *
from source.functions import *
from threading import Thread


class Oracle():
    """
    This class is exposed for attacks, but actually 
    everything is done in OracleThread. Oracle just separates
    payload to allow multithreading.
    """

    def __init__(self):
        self.threads = []
        self.matching = []

    def reset(self, **kwargs):
        self.threads = []
        self.matching = []

    def terminate(self):
        for t in self.threads:
            t.terminate = True
            # TODO join? probably not...

    def run(self, *args, thread_count=1, condition=lambda i, o, kw: True, break_on_success=False, **kwargs):
        # separate payloads
        payloads = [list(enumerate(args))[i::thread_count]
                    for i in range(thread_count)]  # TODO or dict?
        # run threads
        self.threads = [OracleThread(payloads[i], condition=condition, break_on_success=break_on_success,
                                     peers=self.threads, **kwargs) for i in range(thread_count)]
        for t in self.threads:
            t.start()
        for t in self.threads:
            t.join()
            self.matching.extend(t.matching)


class OracleThread(Thread):
    """
    OracleThread class runs the actual oracle code,
    but should not be used directly. Use Oracle class instead.
    """

    def __init__(self, payloads, condition, break_on_success=False, peers=None, ** kwargs):
        Thread.__init__(self)
        #self.run_count = 0
        self.params = {}
        self.matching = []
        self.terminate = False

        self.payloads = payloads
        self.condition = condition
        self.break_on_success = break_on_success
        self.peers = peers
        self.kwargs = kwargs

        # here belongs code for first run only
        self.params['secret'] = Variable(
            'base64:Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK', constant=True)
        self.params['key'] = Variable('YELLOW SUBMARINE', constant=True)
        #####
    '''
    def reset(self, **kwargs):
        self.run_count = 0
        self.matching = []
        self.terminate = False
    '''

    def run(self):
        # if not self.run_count:
        #    self.init(**kwargs)
        for payload_id, payload in self.payloads:
            if self.terminate:
                break
            # here belongs code for every single iteration
            payload = Variable(payload)
            payload = Variable(payload.as_raw() +
                               self.params['secret'].as_raw())
            key = self.params['key']
            aes = AES(mode='ecb', plaintext=payload, key=key)
            aes.encrypt()
            output = aes.params['ciphertext'].as_raw()
            #####
            if self.condition(payload_id, output, self.kwargs):
                self.matching.append(OracleResult(payload_id, output))
                if self.break_on_success:
                    # signal other oracles to terminate
                    if self.peers:
                        for peer in self.peers:
                            peer.terminate = True
                    break
        #self.run_count += 1


def main():
    oracle = Oracle()
    oracle.run(payload=b'')
    print(oracle.matching)


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        pass
