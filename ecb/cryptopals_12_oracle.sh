#!/bin/bash

payload="
p1 = base64:$1
p2 = base64:Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK
p = concat p1 p2
key = 'YELLOW SUBMARINE'
aes = AES mode=ecb plaintext=p key=key
c = encrypt aes
export c /tmp/c_$$
"
./langdon <<< "$payload" &> /dev/null
base64 -w 0 /tmp/c_$$

