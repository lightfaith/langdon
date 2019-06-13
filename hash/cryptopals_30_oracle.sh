#!/bin/bash
unbased=/tmp/cryptopals_30_unbased_$$
plaintextfile=/tmp/cryptopals_30_plaintext_$$
macfile=/tmp/cryptopals_30_macfile_$$
correctfile=/tmp/cryptopals_30_correctfile_$$
keyfile=/tmp/cryptopals_30_key

echo -n 'YELLOW SUBMARINE' > $keyfile
base64 -d <<< "$1" > $unbased
head -c 16 $unbased > $macfile
tail -c +17 $unbased > $plaintextfile


#cat $plaintextfile

./langdon --mac md4 $plaintextfile $keyfile > $correctfile

echo "Correct: `./langdon --hex $correctfile`"
echo "Given:   `./langdon --hex $macfile`"
cmp $correctfile $macfile > /dev/null
return_value=$?
rm $unbased $plaintextfile $macfile $correctfile
exit $return_value
