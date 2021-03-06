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
