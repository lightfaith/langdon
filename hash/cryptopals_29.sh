#!/bin/bash
#unbased=/tmp/cryptopals_29_unbased_$$
#plaintextfile=/tmp/cryptopals_29_plaintext_$$
#macfile=/tmp/cryptopals_29_macfile_$$
#correctfile=/tmp/cryptopals_29_correctfile_$$
#keyfile=/tmp/cryptopals_29_key
#
#echo -n 'YELLOW SUBMARINE' > $keyfile
#base64 -d <<< "$1" > $unbased
## expecting first 20 bytes to be the digest,
## the rest is message to validate
##mac=${unbased:0:20}
##payload=${unbased:20}
#head -c 20 $unbased > $macfile
#tail -c +21 $unbased > $plaintextfile
#
##cat $plaintextfile
#
#./langdon --mac sha1 $plaintextfile $keyfile > $correctfile
#
#echo "Correct: `./langdon --hex $correctfile`"
#echo "Given:   `./langdon --hex $macfile`"
#cmp $correctfile $macfile > /dev/null
#return_value=$?
#rm $unbased $plaintextfile $macfile $correctfile
#exit $return_value


# return MAC of given data and secret key
# $1 = base64(digest+data)

#echo "$1" >&2
echo "$1" | base64 -d | head -c 20 > /tmp/mac
echo "$1" | base64 -d | tail -c +21 > /tmp/plaintext
payload="
key = 'YELLOW SUBMARINE'
data = file:/tmp/plaintext
s = SHA1 data=data key=key
h = mac s
export h /tmp/h
"
./langdon <<< "$payload" &> /dev/null
cat /tmp/h >&2
cmp /tmp/mac /tmp/h > /dev/null

