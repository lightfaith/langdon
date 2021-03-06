#!/usr/bin/python3
"""
https://github.com/james727/MTP/blob/master/mersenne_twister.py
https://en.wikipedia.org/wiki/Mersenne_Twister
https://en.wikipedia.org/wiki/Diehard_tests
http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/mt19937-64.out.txt
"""
import sys
from struct import pack

class MersenneTwister64:
    def __init__(self, seed):
        self.w = 64                  # bits for one state
        self.n = 312                 # number of states
        self.m = 156                 # middle word 
        self.r = 31                  # separation point of one word
        self.a = 0xb5026f5aa96619e9  # coefficients of the radional normal form twist matrix
        self.u = 29                  # additional 
        self.d = 0x5555555555555555  # additional
        self.s = 17                  # TGFSR(R) tempering bit shift
        self.b = 0x71D67FFFEDA60000  # TGFSR(R) tempering bit mask
        self.t = 37                  # TGFSR(R) tempering bit shift
        self.c = 0xFFF7EEE000000000  # TGFSR(R) tempering bit mask
        self.l = 43                  # additional
        self.f = 6364136223846793005 # generator parameter
        
        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = (1 << self.w) - 1 - self.lower_mask #1 << self.r
        self.index = self.n
        self.state = [0] * self.n    # states
        
        self.state[0] = int(seed)
        for i in range(1, self.n):
            self.state[i] = ((self.f 
                              * (self.state[i-1] 
                                 ^ (self.state[i-1] >> (self.w - 2)))
                              + i)
                             & ((1 << self.w) - 1)) # wrap to bits
    
    def twist(self):
        for i in range(self.n):
            temp = (((self.state[i] & self.upper_mask)
                     + (self.state[(i+1) % self.n] 
                        & self.lower_mask))
                    & ((1 << self.w) - 1)) # wrap to bits
            temp_shift = temp >> 1
            if temp % 2 != 0:
                temp_shift = temp_shift ^ self.a
            self.state[i] = self.state[(i + self.m) % self.n] ^ temp_shift
        self.index = 0

    def get_random_number(self):
        if self.index >= self.n:
            self.twist()
        y = self.state[self.index]
        y = y ^ (y >> self.u & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)
        self.index += 1
        return y

    def randint(self):
        return self.get_random_number() & ((1 << self.w) - 1)
    
    def randfloat(self):
        return self.randint() / ((1 << self.w) - 1)


if __name__ == '__main__':
    try:
        mode = sys.argv[1]
        count = int(sys.argv[2])
        try:
            seed = int(sys.argv[3])
        except:
            seed = 0
    except:
        print('[-] Usage: %s int|float|bytes <count> <seed>' % sys.argv[0])
        sys.exit(1)

    mt = MersenneTwister64(seed)
    if mode == 'int':
        for i in range(count):
            print(mt.randint())
    elif mode == 'float':
        for i in range(count):
            print(mt.randfloat())
    elif mode == 'bytes':
        ints = [mt.randint() for _ in range(count // 8 + 1)]
        stream = pack('<' + 'Q'*len(ints), *ints)
        sys.stdout.buffer.write(stream[:count])
    else:
        print('[-] Invalid mode.')

