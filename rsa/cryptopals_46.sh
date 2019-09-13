#!/bin/bash

payload="
d = file:/tmp/d
n = file:/tmp/n
c = base64:$1
rsa = RSA d=d n=n ciphertext=c
p = decrypt rsa
export p /tmp/p bin
p~Int
"
./langdon <<< "$payload" >&2
#tail -c 1 /tmp/p | grep -q '0'
tail -c 1 /tmp/p | base64 -w 0

