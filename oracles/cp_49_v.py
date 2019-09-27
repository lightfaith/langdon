#!/usr/bin/python3
"""
Verification oracle for Cryptopals 6.49 - CBC-MAC

Oracle takes attributes - (plaintext, CBC-MAC) or (plaintext, IV, CBC-MAC)
and validates the signature.

With IV controlled by attacker, CBC-MAC result can be same for arbitrary P1.
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
        key = Variable(b'YELLOW SUBMARINE')
        iv = Variable('0x00000000000000000000000000000000')

        self.immortal_args = {
            'aes': AES(mode='cbc', key=key, iv=iv),
        }

        """"""

    def reset(self, **kwargs):
        self.threads = []
        self.matching = []

    def detail(self):
        print(__doc__)

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
        # self.run_count = 0
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
        """"""

    def run(self):
        start = time.time()
        aes = self.kwargs['aes']

        plaintext = self.payloads[0][1]
        aes.params['plaintext'] = plaintext

        if len(self.payloads) == 2:
            mac = self.payloads[1][1].as_raw()
        else:
            iv = self.payloads[1][1]
            mac = self.payloads[2][1].as_raw()
            aes.params['iv'] = iv

        output = b'success' if aes.mac().as_raw() == mac else b'fail'
        end = time.time()
        self.matching.append(OracleResult(
            0, output, end - start))


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
