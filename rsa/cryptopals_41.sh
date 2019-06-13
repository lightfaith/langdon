#!/bin/bash
decryption_file=/tmp/d
modulus=/tmp/n

ciphertext="/tmp/cryptopals_41_cx"
base64 -d <<< "$1" > "$ciphertext"
./langdon --decrypt rsa "$ciphertext" "$decryption_file" "$modulus"

