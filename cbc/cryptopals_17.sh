#!/bin/bash
#tmpfile="/tmp/cryptopals_17_$$_temp"
#base64 -d <<< "$1" > $tmpfile
#keyfile=/tmp/b
#./langdon-cli --decrypt aes-cbc $tmpfile /tmp/b 0000000000000000
#retvalue="$?"
#rm $tmpfile
#exit $retvalue
payload="
c = base64:$1
key = file:/tmp/key
iv = file:/tmp/iv
aes = AES mode=cbc key=key iv=iv ciphertext=c
p = decrypt aes
export p /tmp/p_$$
"
./langdon <<< "$payload" &> /dev/null
#base64 -w 0 /tmp/p_$$
[ -f /tmp/p_$$ ]
retvalue="$?"
rm /tmp/p_$$
exit $retvalue

