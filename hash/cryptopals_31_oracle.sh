#!/bin/bash
unbased=/tmp/cryptopals_31_unbased_$$
hmacfile=/tmp/cryptopals_31_hmac_$$
keyfile=/tmp/cryptopals_31_key

echo -n 'YELLOW SUBMARINE' > $keyfile
base64 -d <<< "$1" > $unbased
digest=`head -c 40 $unbased` # len of SHA1 * 2 (in hexadecimal)
filename=`tail -c +41 $unbased`

echo "Checking $filename"
./langdon --hmac sha1 $filename $keyfile > $hmacfile
echo "Given:   $digest"
correct=`./langdon --hex $hmacfile`
echo "Correct: $correct"

retvalue=0
i=0
while (( $i < ${#digest} )); do
	#echo -n "  ${digest:i:1}"
	if [[ "${digest:i:1}" -ne "${correct:i:1}" ]]; then
		retvalue=1
		break
	fi
	python -c "import time; time.sleep(0.5)"
	i=$(( i+1 ))
done <<< $i

exit $retvalue

