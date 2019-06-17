#!/bin/bash
payload_based="$1"
filename="/tmp/cryptopals_14_$$_payload"
#prepend_size=$(( ( RANDOM % 20 )  + 1 )) # cannot work - must be constant for each oracle call
#prepend_size=3
#prepend_size=15
prepend_size=16

#dd if=/dev/urandom of=$filename bs=1 count=$prepend_size
python3 -c "print('A'*$prepend_size, end='')" > $filename

base64 -d <<< "$payload_based" >> $filename
echo -n 'YLLUMINATI' >> $filename
echo -n "YELLOW SUBMARINE" > /tmp/cryptopals_14_key
#tail -c +$(( prepend_size + 1 )) $filename >> /tmp/cp_log
#echo >> /tmp/cp_log
./langdon --encrypt aes-ecb $filename /tmp/cryptopals_14_key
rm $filename

