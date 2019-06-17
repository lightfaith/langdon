#!/usr/bin/python3
"""

"""
import os
import sys
import base64
import subprocess
import itertools
import time

def run_command(command):
    p = subprocess.Popen(command,
                         shell=True,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    (out, err) = p.communicate()
    return (p.returncode, out, err)

#unbased = '/tmp/cryptopals_31_unbased_%d' % os.getpid()
hmacfile = '/tmp/cryptopals_31_hmac_%d' % os.getpid()
keyfile = '/tmp/cryptopals_31_key'

unbased = base64.b64decode(sys.argv[1])
hex_digest = unbased[:40]
filename = unbased[40:]

#print('Hex digest:', hex_digest)
#print('Filename:', filename)
with open(keyfile, 'wb') as f:
    f.write(b'YELLOW SUBMARINE')

_, hmac, _ = run_command('./langdon --hmac sha1 %s %s' % (filename.decode(), 
                                                            keyfile))
with open(hmacfile, 'wb') as f:
    f.write(hmac)
_, correct, _ = run_command('./langdon --hex %s' % hmacfile)

#print("Given:   %s" % hex_digest, type(hex_digest))
#print("Correct: %s" % correct, type(correct))

match = 0
for x, y in itertools.zip_longest(hex_digest, correct):
    #print(x, y)
    if x != y:
        match = 1
        break
    time.sleep(0.05)
run_command('rm %s' % hmacfile)
sys.exit(match)

