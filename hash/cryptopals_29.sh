#!/bin/bash

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

