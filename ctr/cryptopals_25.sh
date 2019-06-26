#!/bin/bash
# Simulating API for editation of CTR-encrypted value without known key.

payload="
c = file:/tmp/c
key = file:/tmp/key
nonce = file:/tmp/nonce
new = base64:$1
aes = AES mode=ctr key=key nonce=nonce ciphertext=c
p = decrypt aes
aes.plaintext = new
c2 = encrypt aes
export c2 /tmp/c2
"
./langdon <<< "$payload" &> /dev/null
base64 -w 0 < /tmp/c2

