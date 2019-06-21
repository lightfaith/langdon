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
