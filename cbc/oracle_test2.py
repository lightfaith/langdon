#!/usr/bin/python3
import subprocess
import sys
import base64

def run_command(command):
    p = subprocess.Popen(command,
                         shell=True,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    (out, err) = p.communicate()
    return (p.returncode, out, err)

try:
    payload_based = sys.argv[1]
except:
    print('[-] Cannot load payload from argument.', file=sys.stderr)
    sys.exit(1)

r, o, e = run_command('echo "%s" | openssl enc -d -aes-128-cbc -iv 000102030405060708090a0b0c0d0e0f -nosalt -k password -base64' % payload_based)

#print(r)
#print()
#print(o)
#print()
#print(e)
sys.exit(1 if b'bad decrypt' in e else 0)
