#!/usr/bin/python3

import sys
import os
import subprocess
import base64 

try:
    data = sys.argv[1]
except:
    print('[-] Usage: %s <data>' % sys.argv[0])
    sys.exit(1)

result_file = '/tmp/c'
payload = b"""
payload = base64:%s
comment1 = cooking%%20MCs;userdata=
comment2 = ;comment2=%%20like%%20a%%20pound%%20of%%20bacon
p = concat comment1 payload comment2
key = 'YELLOW SUBMARINE'
iv = 0x0000000000000000
aes = AES mode=cbc key=key plaintext=p iv=iv
c = encrypt aes
export c %s
""" % (data.encode(), result_file.encode())

'''
data = (b'comment1=cooking%%20MCs;userdata=%s;comment2=%%20like%%20a%%20pound%%20of%%20bacon'
        % data.replace(b'=', b'--').replace(b';', b',.'))
datafile = '/tmp/cryptopals_16_%d_encryptdata' % os.getpid()
keyfile = '/tmp/cryptopals_16_key'
with open(datafile, 'wb') as f:
    f.write(data)
with open(keyfile, 'wb') as f:
    f.write(b'YELLOW SUBMARINE')

p = subprocess.Popen('./langdon-cli --encrypt aes-cbc {0} {1} 0000000000000000; rm {0}'.format( 
    datafile, keyfile),
                     shell=True,
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
(out, err) = p.communicate()
sys.stdout.buffer.write(base64.b64encode(out))
#sys.stderr.buffer.write(data)
'''
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
