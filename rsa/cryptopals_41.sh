#!/bin/bash

payload="
d = file:/tmp/d
n = file:/tmp/n
c = base64:$1
rsa = RSA d=d n=n ciphertext=c
p = decrypt rsa
export p /tmp/p
"
./langdon <<< "$payload" &> /dev/null
base64 -w 0 /tmp/p


