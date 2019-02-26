#!/bin/bash
payload_based="$1"
filename="/tmp/cryptopals_12_$$_payload"
base64 -d <<< "$payload_based" > $filename
base64 -d <<< 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK' >> $filename
#cat /tmp/a >> $filename
#echo -n 'ILLUMINATIRULETHEWORLD' >> $filename
#echo -n 'ILLUMINATI' >> $filename
#echo -n 'TOYOTAWITHLIGHTS' >> $filename
echo -n "YELLOW SUBMARINE" > /tmp/cryptopals_12_key
./langdon --encrypt aes-ecb $filename /tmp/cryptopals_12_key
rm $filename

