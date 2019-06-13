#!/bin/bash
tmpfile="/tmp/cryptopals_17_$$_temp"
base64 -d <<< "$1" > $tmpfile
keyfile=/tmp/b
./langdon --decrypt aes-cbc $tmpfile /tmp/b 0000000000000000
retvalue="$?"
rm $tmpfile
exit $retvalue
