#!/bin/bash
payload_based="$1"
filename="/tmp/cryptopals_12_$$_payload"
base64 -d <<< "$payload_based" > $filename
echo -n "YELLOW SUBMARINE" > /tmp/cryptopals_12_key
./langdon --encrypt aes-ecb $filename /tmp/cryptopals_12_key
rm $filename

