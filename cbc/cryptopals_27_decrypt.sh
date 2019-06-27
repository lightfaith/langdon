#!/bin/bash
#ciphertext="/tmp/cryptopals_27_ciphertext_$$"
#base64 -d <<< "$1" > $ciphertext
#key=/tmp/cryptopals_27_key
#iv="00112233445566778899aabbccddeeff"
#echo -en '\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff' > "$key"
#./langdon-cli --decrypt aes-cbc "$ciphertext" "$key" "$iv" --ignore-padding 2>> /tmp/langdon.log
payload="
c = base64:$1
key = file:/tmp/key
iv = file:/tmp/iv
aes = AES mode=cbc key=key iv=iv ciphertext=c ignore_padding 
p = decrypt aes
export p /tmp/p
"
./langdon <<< "$payload" &> /dev/null
base64 -w 0 /tmp/p
