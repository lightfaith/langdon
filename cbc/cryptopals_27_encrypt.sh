#!/bin/bash
plaintext="/tmp/cryptopals_27_plaintext_$$"
base64 -d <<< "$1" > "$plaintext"
key=/tmp/cryptopals_27_key
iv="00112233445566778899aabbccddeeff"
echo -en '\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff' > "$key"
./langdon --encrypt aes-cbc "$plaintext" "$key" "$iv"
