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
generating email,uid,role and encrypting with AES CTR
"""
data = (b'comment1=cooking%%20MCs;userdata=%s;comment2=%%20like%%20a%%20pound%%20of%%20bacon'
        % data.replace(b'=', b'--').replace(b';', b',.'))
result_file = '/tmp/c'
payload = b"""
payload = %s
nonce = 1337
key = 'YELLOW SUBMARINE'
aes = AES mode=ctr nonce=nonce key=key plaintext=payload
c = encrypt aes
export c %s
""" % (data, result_file.encode())

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
data = (b'comment1=cooking%%20MCs;userdata=%s;comment2=%%20like%%20a%%20pound%%20of%%20bacon'
        % data.replace(b'=', b'--').replace(b';', b',.'))
datafile = '/tmp/cryptopals_26_%d_encryptdata' % os.getpid()
keyfile = '/tmp/cryptopals_26_key'
with open(datafile, 'wb') as f:
    f.write(data)
with open(keyfile, 'wb') as f:
    f.write(b'YELLOW SUBMARINE')

p = subprocess.Popen('./langdon-cli --encrypt aes-ctr {0} {1} 1337; rm {0}'.format( 
    datafile, keyfile),
                     shell=True,
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
(out, err) = p.communicate()
sys.stdout.buffer.write(base64.b64encode(out))
#sys.stderr.buffer.write(data)
'''
