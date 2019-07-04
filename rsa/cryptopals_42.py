#!/usr/bin/python3
"""
This oracle incorrectly verifies RSA PCKS1-padded signature.
"""
import sys
import base64
from source.classes import *

signature = base64.b64decode(sys.argv[1])


