#!/usr/bin/python3
"""
Oracle for Cryptopals 2.14 - ECB chosen plaintext attack

The oracle concatenates given payload with secret value (self.params['secret']),
like CP 2.12. Moreover, random data is prepended. Oracle then returns AES ECB 
ciphertext of the payload.

Langdon is able to recover the secret just by altering provided payload.
"""
from threading import Thread
from source.classes import *
from source.functions import *


class Oracle():
    """
    This class is exposed for attacks, but actually 
    everything is done in OracleThread. Oracle just separates
    payload to allow multithreading.
    """

    def __init__(self):
        self.threads = []
        self.matching = []
        """
        specify global args here that should be same for all runs
        even when the oracle is reset
        """
        self.immortal_args = {
            'prepend': Variable(b''.join(int_to_bytes(random.randint(0, 256))
                                         for i in range(random.randint(0, 10))))
        }
        """"""

    def reset(self, **kwargs):
        self.threads = []
        self.matching = []

    def terminate(self):
        for t in self.threads:
            t.terminate = True

    def run(self, *args, thread_count=1, condition=lambda i, o, kw: True, break_on_success=False, **kwargs):
        # separate payloads
        payloads = [list(enumerate(args))[i::thread_count]
                    for i in range(thread_count)]
        # add immortal args
        for k, v in self.immortal_args.items():
            kwargs[k] = v
        # run threads
        self.threads = [OracleThread(payloads[i], condition=condition, break_on_success=break_on_success,
                                     peers=self.threads, **kwargs) for i in range(thread_count)]
        for t in self.threads:
            t.start()
        # collect results
        for t in self.threads:
            t.join()
            self.matching.extend(t.matching)
        a = 1


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
        """
        here belongs code for first run only
        constant Variables should be created here
        """
        self.params['secret'] = Variable(
            'base64:Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK', constant=True)
        self.params['key'] = Variable('YELLOW SUBMARINE', constant=True)

        """"""

    def run(self):
        # run code for each payload
        for payload_id, payload in self.payloads:
            if self.terminate:
                break
            """
            here belongs code for every single iteration
            'output' variable should be set somehow
            """
            payload = Variable(payload)
            payload = Variable(self.kwargs['prepend'].as_raw() +
                               payload.as_raw() +
                               self.params['secret'].as_raw())
            key = self.params['key']
            aes = AES(mode='ecb', plaintext=payload, key=key)
            aes.encrypt()
            output = aes.params['ciphertext'].as_raw()
            """"""
            # use result if condition matches
            if self.condition(payload_id, output, self.kwargs):
                self.matching.append(OracleResult(payload_id, output))
                # decide whether to stop
                if self.break_on_success:
                    # signal other oracles to terminate
                    if self.peers:
                        for peer in self.peers:
                            peer.terminate = True
                    break


def main():
    oracle = Oracle()
    """
    specify test code here, run with python3 -m oracles.<module_name>
    """
    oracle.run('Hello')
    print(oracle.matching)
    """"""


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        pass

'''
#!/bin/bash
[ -f /tmp/prepend ] || dd if=/dev/urandom bs=1 count=$(( ( RANDOM % 20 )  + 1 )) of=/tmp/prepend

payload="
prepend = file:/tmp/prepend
payload = base64:$1
secret = YLLUMINATI
p = concat prepend payload secret
key = 'YELLOW SUBMARINE'
aes = AES mode=ecb plaintext=p key=key
c = encrypt aes
export c /tmp/c_$$
"

./langdon <<< "$payload" &> /dev/null
base64 -w 0 /tmp/c_$$

'''
