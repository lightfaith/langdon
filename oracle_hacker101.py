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

payload_based = payload_based.replace('=', '~').replace('/', '!').replace('+', '-')
r, o, e = run_command('wget -qO- http://35.227.24.107:5001/464e14b3fb/?post=%s' % payload_based)
sys.exit(1 if b'PaddingException' in o else 0)
