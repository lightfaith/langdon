#!/usr/bin/python3
"""
Oracle for Cryptopals 6.47 - Bleichenbacher

Oracle decrypts given ciphertext and just 0 if plaintext starts
with \x00\x02 (that is PKCS #1 v1.5), else 1.
Technically, when working with numbers, leading \x00 bytes will not
be present. Just... OK?

Langdon is able to recover original plaintext.
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

    def __init__(self, filename=''):
        self.filename = filename
        self.threads = []
        self.matching = []
        """
        specify global args here that should be same for all runs
        even when the oracle is reset
        """
        self.immortal_args = {
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

    def oneshot(self, *args, thread_count=1, condition=lambda i, o, kw: True, break_on_success=False, **kwargs):
        self.run(*args, thread_count=thread_count, condition=condition,
                 break_on_success=break_on_success, **kwargs)
        result = self.matching[0].output
        self.reset()
        return result

    def short(self):
        return 'Oracle(%s)' % self.filename


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
        this is rerun after oracle reset()
        constant Variables should be created here
        """
        self.params['d'] = Variable('file:/tmp/d', constant=True)
        self.params['n'] = Variable('file:/tmp/n', constant=True)
        """"""

    def run(self):
        desired_byte_count = 31
        # run code for each payload
        for payload_id, payload in self.payloads:
            if self.terminate:
                break
            start = time.time()
            """
            here belongs code for every single iteration
            'output' variable should be set somehow
            """
            d = self.params['d']
            n = self.params['n']
            payload = Variable(payload)
            rsa = RSA(ciphertext=payload, d=d, n=n)
            p = Variable(rsa.decrypt()).as_raw()
            output = b'0' if p[0] == 0x02 and len(
                p) == desired_byte_count else b'1'
            """"""
            end = time.time()
            # use result if condition matches
            if self.condition(payload_id, output, self.kwargs):
                self.matching.append(OracleResult(
                    payload_id, output, end - start))
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
