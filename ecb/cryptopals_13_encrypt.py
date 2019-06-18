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
datafile = '/tmp/cryptopals_13_%d_encryptdata' % os.getpid()
keyfile = '/tmp/cryptopals_13_key'
with open(datafile, 'wb') as f:
    f.write(data)
with open(keyfile, 'wb') as f:
    f.write(b'YELLOW SUBMARINE')

p = subprocess.Popen('./langdon --encrypt aes-ecb {0} {1}; rm {0}'.format( 
    datafile, keyfile),
                     shell=True,
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
(out, err) = p.communicate()
sys.stdout.buffer.write(out)
#sys.stderr.buffer.write(data)