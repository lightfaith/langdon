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

'''
data = base64.b64decode(data)
datafile = '/tmp/cryptopals_16_%d_decryptdata' % os.getpid()
keyfile = '/tmp/cryptopals_16_key'
with open(datafile, 'wb') as f:
    f.write(data)
with open(keyfile, 'wb') as f:
    f.write(b'YELLOW SUBMARINE')

#sys.stderr.buffer.write(data)
p = subprocess.Popen('./langdon-cli --decrypt aes-cbc {0} {1} 0000000000000000; rm {0}'.format(
    datafile, keyfile),
                     shell=True,
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
(out, err) = p.communicate()
sys.stdout.buffer.write(base64.b64encode(out))
#sys.stderr.buffer.write(err)
'''
result_file = '/tmp/p'
payload = b"""
c = base64:%s
iv = 0x0000000000000000
key = 'YELLOW SUBMARINE'
aes = AES mode=cbc iv=iv key=key ciphertext=c
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
