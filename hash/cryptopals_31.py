#!/usr/bin/python3
"""

"""
import os
import sys
import base64
import subprocess
import itertools
import time

#sys.stderr.buffer.write(sys.argv[1].encode())
try:
    data = sys.argv[1]
except:
    print('[-] Usage: %s <base64>' % sys.argv[0], file=sys.stderr)
    sys.exit(2)

#target_file = '/etc/passwd'
target_file = '/tmp/p'
tmp_file = '/tmp/h'
# get correct SHA1 for file
payload = b"""
f = file:%s
s = SHA1 data=f
h = hash s
export h %s hex
""" % (target_file.encode(), tmp_file.encode())
p = subprocess.Popen('./langdon',
                     shell=True,
                     stdin=subprocess.PIPE,
                     stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)
p.stdin.write(payload)
p.stdin.close()
p.wait()

# test byte by byte
with open(tmp_file, 'rb') as f:
    correct = f.read()
    #sys.stderr.buffer.write(b'Correct: ' + correct)
guessed = base64.b64decode(sys.argv[1])
if len(guessed) > len(correct):
    sys.exit(0)
for i in range(len(correct)):
    try:
        if guessed[i] != correct[i]:
            sys.exit(1)
    except: # end of one of the string
        sys.exit(1)
    time.sleep(0.05)

# succeeded!
sys.exit(0)

