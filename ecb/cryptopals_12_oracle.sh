#!/bin/bash

#payload_based="$1"
#filename="/tmp/cryptopals_12_$$_payload"
#base64 -d <<< "$payload_based" > $filename
#base64 -d <<< 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK' >> $filename
##cat /tmp/a >> $filename
##echo -n 'ILLUMINATIRULETHEWORLD' >> $filename
##echo -n 'ILLUMINATI' >> $filename
##echo -n 'TOYOTAWITHLIGHTS' >> $filename
#echo -n "YELLOW SUBMARINE" > /tmp/cryptopals_12_key
#./langdon-cli --encrypt aes-ecb $filename /tmp/cryptopals_12_key > /tmp/output
#base64 -w 0 /tmp/output
#rm $filename /tmp/output
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

