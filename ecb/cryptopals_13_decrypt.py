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
ciphertext = base64:%s
key = 'YELLOW SUBMARINE'
aes = AES mode=ecb ciphertext=ciphertext key=key
p = decrypt aes
export p %s
""" % (data.encode(), result_file.encode())

#p = subprocess.Popen('./langdon-cli --decrypt aes-ecb {0} {1}; rm {0}'.format(
#    datafile, keyfile),
p = subprocess.Popen('./langdon',
                     shell=True,
                     stdin=subprocess.PIPE,
                     stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)
p.stdin.write(payload)
p.stdin.close()
p.wait()
#(out, err) = p.communicate()
with open(result_file, 'rb') as f:
    sys.stdout.buffer.write(base64.b64encode(f.read()))

