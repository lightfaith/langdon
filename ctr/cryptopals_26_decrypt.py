#!/usr/bin/python3

import sys
import os
import subprocess
import base64 

try:
    data = sys.argv[1]
except:
    print('[-] Usage: %s <base64>' % sys.argv[0])
    sys.exit(1)

result_file = '/tmp/p'
payload = b"""
c = base64:%s
nonce = 1337
key = 'YELLOW SUBMARINE'
aes = AES mode=ctr nonce=nonce key=key ciphertext=c
p = decrypt aes
export p %s
""" % (data.encode(), result_file.encode())

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
'''
data = base64.b64decode(data)
datafile = '/tmp/cryptopals_26_%d_decryptdata' % os.getpid()
keyfile = '/tmp/cryptopals_26_key'
with open(datafile, 'wb') as f:
    f.write(data)
with open(keyfile, 'wb') as f:
    f.write(b'YELLOW SUBMARINE')

#sys.stderr.buffer.write(data)
p = subprocess.Popen('./langdon-cli --decrypt aes-ctr {0} {1} 1337; rm {0}'.format(
    datafile, keyfile),
                     shell=True,
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
(out, err) = p.communicate()
sys.stdout.buffer.write(base64.b64encode(out))
#sys.stderr.buffer.write(err)
'''
