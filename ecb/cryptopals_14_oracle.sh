#!/bin/bash
[ -f /tmp/prepend ] || dd if=/dev/urandom bs=1 count=$(( ( RANDOM % 20 )  + 1 )) of=/tmp/prepend

payload="
prepend = file:/tmp/prepend
payload = base64:$1
secret = YLLUMINATI
p = concat prepend payload secret
key = 'YELLOW SUBMARINE'
aes = AES mode=ecb plaintext=p key=key
c = encrypt aes
export c /tmp/c_$$
"

./langdon <<< "$payload" &> /dev/null
base64 -w 0 /tmp/c_$$

#payload_based="$1"
#filename="/tmp/cryptopals_14_$$_payload"
##prepend_size=$(( ( RANDOM % 20 )  + 1 )) # cannot work - must be constant for each oracle call
#prepend_size=16
#
##dd if=/dev/urandom of=$filename bs=1 count=$prepend_size
#python3 -c "print('A'*$prepend_size, end='')" > $filename
#
#base64 -d <<< "$payload_based" >> $filename
#echo -n 'YLLUMINATI' >> $filename
#echo -n "YELLOW SUBMARINE" > /tmp/cryptopals_14_key
##tail -c +$(( prepend_size + 1 )) $filename >> /tmp/cp_log
##echo >> /tmp/cp_log
#./langdon --encrypt aes-ecb $filename /tmp/cryptopals_14_key
#rm $filename

