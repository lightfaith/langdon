#!/usr/bin/python3
"""

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
        self.params['key'] = Variable('YELLOW SUBMARINE', constant=True)
        self.params['plaintext'] = Variable('file:/tmp/p', constant=True)
        """"""

    def run(self):
         # load previously known data
        plaintext = self.params['plaintext']

        # get real hash (use hex form to speed up)
        key = self.params['key']
        sha = SHA1(data=plaintext, key=key)
        real_hash = Variable(sha.hmac()).as_hex().encode()

        # run code for each payload
        for payload_id, payload in self.payloads:
            if self.terminate:
                break
            start = time.time()
            """
            here belongs code for every single iteration
            'output' variable should be set somehow
            """

            # compare real hash to given value
            hash_guess = Variable(payload).as_raw()
            output = 'success'
            for i in range(max(len(real_hash), len(hash_guess))):
                try:
                    if real_hash[i] != hash_guess[i]:
                        output = 'fail'
                        break
                except:
                    output = 'fail'
                    break
                time.sleep(0.05)
                # time.sleep(0.005)

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
