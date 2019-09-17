#!/usr/bin/python3
"""
Encryption Oracle for Cryptopals 2.13 - ECB cut&paste attack

The oracle returns AES ECB ciphertext of 'email=...&uid=10&role=user' where
email value is controlled by user. The value is sanitized, 
so no &s, ;s or =s are allowed.

Langdon is able to use ECB cut&paste attack to change the role to admin.
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
        # run threads
        self.threads = [OracleThread(payloads[i], condition=condition, break_on_success=break_on_success,
                                     peers=self.threads, **kwargs) for i in range(thread_count)]
        for t in self.threads:
            t.start()
        # collect results
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

        """
        here belongs code for first run only
        constant Variables should be created here
        """
        self.params['message'] = Variable(
            'email=%s&uid=10&role=user', constant=True)
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
            payload = Variable(
                self.params['message'].as_raw() % Variable(payload).as_raw())

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
#!/usr/bin/python3

import sys
import os
import subprocess
import base64 

try:
    data = base64.b64decode(sys.argv[1].encode())
except:
    print('[-] Usage: %s <data>' % sys.argv[0])
    sys.exit(1)

"""
accepting email, sanitizing,
generating email,uid,role and encrypting with AES ECB
"""
data = (b'email=%s&uid=10&role=user'
        % data.replace(b'=', b'--').replace(b'&', b'aa').replace(b';', b',.'))
#datafile = '/tmp/cryptopals_13_%d_encryptdata' % os.getpid()
#keyfile = '/tmp/cryptopals_13_key'
#with open(datafile, 'wb') as f:
#    f.write(data)
#with open(keyfile, 'wb') as f:
#    f.write(b'YELLOW SUBMARINE')
result_file = '/tmp/c'
payload = b"""
plaintext = base64:%s
key = 'YELLOW SUBMARINE'
aes = AES mode=ecb plaintext=plaintext key=key
c = encrypt aes
export c %s
""" % (base64.b64encode(data), result_file.encode())

#p = subprocess.Popen('./langdon-cli --encrypt aes-ecb {0} {1}; rm {0}'.format( 
p = subprocess.Popen('./langdon',
                     shell=True,
                     stdin=subprocess.PIPE,
                     stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)
p.stdin.write(payload)
p.stdin.close()
p.wait()
with open(result_file, 'rb') as f:
    sys.stdout.buffer.write(base64.b64encode(f.read()))
#sys.stderr.buffer.write(data)
'''
