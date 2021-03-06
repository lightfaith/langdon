#!/usr/bin/python3
"""
Sophisticated attacks are here
"""
import pdb
import traceback
from datetime import datetime

from source.log import *
from source.functions import *
from source.classes import *

def ctr_fixed_nonce(texts, language):
    """
    If CTR mode is used with fixed nonce for multiple cases, it can be
    broken as XOR.
    """
    texts = [t.as_raw() for t in texts]
    min_length = min([len(l) for l in texts])
    aligned_lines = [l[:min_length] for l in texts]
    transposed_lines = [b''.join(b'%c' % l[i]
                                 for l in aligned_lines)
                        for i in range(min_length)]
    xor_key = b''
    #print('transposed count:', len(transposed_lines))
    for line in transposed_lines:
        #print('transposed len', len(line))
        xors = list(bruteforce(line,
                               [b'%c' % c for c in range(256)],
                               xor))
        best = sorted(xors, key=lambda x: get_frequency_error(x, language))
        #for i in range(3):
        #    print(get_frequency_error(best[i], language))
        xor_key += b'%c' % (xors.index(best[0]))
    #print(xor_key)
    log.info('Revealed XOR value:', Variable(xor_key))
    result = XOR(key=Variable(xor_key),
                 ciphertext=Variable(texts[0]),
                 plaintext=Variable(xor(texts[0], xor_key)))
    return result


def break_xor(data, language, keysize=None):
    result = None
    # get normalized hamming for keysizes, smallest should be correct
    distances = {}
    keysizes = [keysize] if keysize else range(2, min(60, len(data)))
    for keysize in keysizes:
        tmp_distance = 0
        sample_count = 0
        #go through keysize block pairs, get average hamming
        for i in range(0, len(data) - keysize, keysize):
            sample1 = data[i:i+keysize]
            sample2 = data[i+keysize:i+2*keysize]
            sample_count += 1
            tmp_distance += hamming(sample1, sample2)
            distances[keysize] = tmp_distance / sample_count / keysize
    #for k,v in distances.items():
    #    print(k, v)
    best = sorted(distances.items(), key=lambda x: x[1])
    # entropy can also be used - smallest non-zero should be correct (but 2*keysize might have smaller entropy...)
    #for keylen in range(2, 40):
    #    cs = chunks(data, keylen, transpose=True)
    #    print('Keylen: %2d, avg entropy: %f' %
    #            (keylen, sum(entropy(c) for c in cs)/len(cs)))


    # use 2 best distances and try to get characters based on best frequency
    #for keysize, distance in best[:2]:
    for keysize, distance in best[:1]:
        key = b''
        debug('Trying keysize %d (distance %.3f)' % (keysize, distance))
        for offset in range(keysize):
            transposed = data[offset::keysize]
            xors = list(bruteforce(transposed,
                                   [b'%c' % c for c in range(256)],
                                   xor))
            best = sorted(xors, key=lambda x: get_frequency_error(x, language))
            #for i in range(3):
            #    print(get_frequency_error(best[i], language))
            key += b'%c' % (xors.index(best[0]))
            debug('Adding 0x%02x to key.' % key[-1])
            #for i in range(3):
            #    print(get_frequency_error(best[i], language))
        if not result:
            result = XOR(key=Variable(key),
                         ciphertext=Variable(data),
                         plaintext=Variable(xor(data, key)))
        #print('Key for keysize %d:' % keysize, key)
        #print('Deciphered message:')
        #prynt(xor(data, key))
    return result


def ecb_chosen_plaintext(oracle):
    """
    ECB Chosen Plaintext Attack
    (Cryptopals 2.12, 2.14)
    
    We can decrypt message if start of the plaintext is under our control.
    
    UPDATE: We can decrypt message even if unknown data is prepended
            (expecting it does not cause repeated sequence trigger).
    """
    blocksize = 0
    start_offset = 0
    # find starting offset and block size by prepending A, AA, AAA, ..., 
    # sending for encryption and then looking for repeating patterns
    debug('Looking for starting offset and block size...')
    for prepend_len in range(16, 129):
        prepend = b'A' * prepend_len
        #oracle = Oracle(oracle_path, {0: prepend}, lambda i,r,o,e,kw: True)
        #oracle.start()
        #oracle.join()
        oracle.run(prepend)
        ciphertext = oracle.matching[0].output
        patterns = find_repeating_patterns(ciphertext)
        oracle.reset()
        if patterns:
            blocksize = patterns[0][1] - patterns[0][0]
            relative_start_offset = (blocksize - (prepend_len - 2 * patterns[0][0])) % blocksize # offset from left block align
            debug('Found repeating patterns.')
            debug('Block size:', blocksize)
            debug('Starting offset:', relative_start_offset)
            start_padding = b'B' * ((blocksize - relative_start_offset) % blocksize)
            break

    if not blocksize:
        log.err('Could not find repeating blocks -> probably not ECB.')
        return b''
    else:
        # Now do the attack:
        #   If there is some prepended stuffing, add chars to end the block.
        #
        #   Prepend block 1 byte short, e.g. 'AAAAAAA_' and get the ciphertext.
        #   That means the last byte will be first character from the unknown 
        #   plaintext.
        #   Next, get ciphertexts for all possible values for last byte. 
        #   If match, you know the byte.
        #
        #   Continue by shortening the prepended stuff (and using revealed byte),
        #   e.g. 'AAAAAAM_', etc. for whole block.
        #
        #   You can use found bytes as prepend value for next block.
        #   Again, omit the last byte, e.g. 'My Immo_'
        
        # create start padding 
        block_counter = math.ceil((start_offset + len(start_padding)) / blocksize)
        debug('Decryption will start at block %d.' % block_counter)
        plaintext = b''
        done = False
        while True:
            # align so 1 unknown character is included
            for offset in range(blocksize-1, -1, -1):
                debug('Using block offset', offset)
                # get reference cipher string
                reference_payload = start_padding + b'A' * offset
                #print('reference payload:', reference_payload)
                oracle.run(reference_payload)
                reference_index = block_counter * blocksize
                #print('reference index:', reference_index)
                reference = oracle.matching[0].output[reference_index:reference_index + blocksize]
                oracle.reset()
                if not reference:
                    # end of ciphertext
                    debug('No reference, this is the end.')
                    done = True
                    break
                #debug('Reference:', reference)
                
                # try all bytes instead of first text byte
                payloads = [(start_padding
                             + b'A' * offset
                             + plaintext
                             + b'%c' % byte_index)
                            for byte_index in range(256)]
                oracle.run(*payloads,
                           thread_count=8,
                           condition=(lambda i, o, kw:
                                      (o[kw['reference_index']:kw['reference_index']
                                        + kw['blocksize']] == kw['reference'])),
                           reference=reference,
                           reference_index=reference_index,
                           blocksize=blocksize)
                new_byte_found = False
                if oracle.matching:
                    plaintext += b'%c' % oracle.matching[0].payload_id
                    new_byte_found = True
                oracle.reset()
                if not new_byte_found:
                    debug('Oracles failed to find single answer, trying next block.')
                    break

                debug('Plaintext:', plaintext)
            if done:
                break
            block_counter += 1
            debug('Dealing with new block.')
            #prynt(plaintext, end='')
        return pkcs7_unpad(plaintext)


def ecb_cut_paste(e_oracle, d_oracle, expected, desired, payload=None):
    """
    ECB cut-and-paste
    (Cryptopals 2.13)

    With control of portion of the plaintext, we can create fake blocks
    that we can feed into decryption routine, in this case resulting in
    authorization bypass.

    This approach expect the sensitive value to spoof is at the end
    (or it matches a block perfectly, but you must manually order chunks).

    The final payload kept in the ciphertext must be fixed length, which
    is computed here.
    """
    # find blocksize
    blocksize_payload = b'A' * 129
    #encrypted = Oracle.once(blocksize_payload, e_oracle_path)
    e_oracle.run(blocksize_payload)
    encrypted = e_oracle.matching[0].output
    e_oracle.reset()

    patterns = find_repeating_patterns(encrypted)
    if not patterns:
        log.err('No patterns present -> probably not ECB.')
    else:
        blocksize = patterns[0][1] - patterns[0][0]
        debug('Determined blocksize:', blocksize)
        
        #decrypted = Oracle.once(encrypted, d_oracle_path)
        d_oracle.run(encrypted)
        decrypted = d_oracle.matching[0].output
        d_oracle.reset()
        
        # determine payload offset
        debug('Determining payload offset...')
        payload_offset = decrypted.index(blocksize_payload)
        debug('Payload offset:', payload_offset)
    
        debug('Determining size of data between payload and expected...')
        # find length of data between the 'A' payload and the expected value
        payload_to_expected = decrypted.index(expected.as_raw()) - payload_offset - len(blocksize_payload)
        debug('Found difference: %d.' % payload_to_expected)
        real_payload_size = (blocksize - payload_offset - payload_to_expected) % 16
        debug('You must use payload of length %d (or + n * %d)' % (real_payload_size, blocksize))

        if payload:
            payload = payload.as_raw()
        else:
            payload = b'X' * real_payload_size

        # find expected value offset
        debug('Using', payload, 'as payload, len:', len(payload))
        #encrypted = Oracle.once(payload, e_oracle_path)
        #decrypted = Oracle.once(encrypted, d_oracle_path)
        e_oracle.run(payload)
        encrypted = e_oracle.matching[0].output
        e_oracle.reset()
        d_oracle.run(encrypted)
        decrypted = d_oracle.matching[0].output
        d_oracle.reset()

        debug('Decrypted message:', decrypted)
        debug('Decrypted chunks:', [decrypted[i:i+blocksize]
                                    for i in range(0, len(decrypted), blocksize)])


        # the fake block must be created in the middle of attacker-controlled
        # payload -> get left and right lengths
        # PKCS#7 pad the fake block
        start_payload_padding = blocksize - payload_offset
        #end_payload_padding = len(payload) - start_payload_padding
        
        fake_block = pkcs7_pad(desired.as_raw(), blocksize)
        payload = (payload[:start_payload_padding]
                   + fake_block
                   + payload[start_payload_padding:])
        debug('Using', payload, 'as final payload, len:', len(payload))

        #encrypted = Oracle.once(payload, e_oracle_path)
        e_oracle.run(payload)
        encrypted = e_oracle.matching[0].output
        e_oracle.reset()

        encrypted_chunks = [encrypted[i:i+blocksize]
                            for i in range(0, len(encrypted), blocksize)]
        # drop the expected chunk, put desired chunk in the place
        # 1, 2 -> 0, 2, 1
        # 2, 5 -> 0, 1, 5, 3, 4, 2
        fake_block_index = payload_offset // blocksize + 1
        #reordered = b''.join(encrypted_chunks[x] for x in (0, 2, 1))
        encrypted_chunks[-1] = encrypted_chunks[fake_block_index]
        del encrypted_chunks[fake_block_index]

        reordered = b''.join(encrypted_chunks)
        #decrypted = Oracle.once(reordered, d_oracle_path)
        d_oracle.run(reordered)
        decrypted = d_oracle.matching[0].output
        d_oracle.reset()

        debug('Decrypted message:', decrypted)
        debug('Decrypted chunks:', [decrypted[i:i+blocksize]
                                    for i in range(0, len(decrypted), blocksize)])
        #return decrypted
        return reordered


def cbc_bitflipping(e_oracle, d_oracle, target_block, desired):
    """
    CBC bitflipping
    (Cryptopals 2.16)

    We can use unneeded chunk to hold specific value than, after XORed
    with next decoded chunk, will create desired payload. In total,
    2 blocks are changed. In CP 16, authorization is bypassed.
    """
    target_block = target_block.as_int()

    # determine blocksize
    blocksize = None
    common_match = 0
    previous_encrypted = b''
    for payload_length in range(8, 129):
        #encrypted = Oracle.once(b'A' * payload_length, e_oracle_path)
        encrypted = e_oracle.oneshot(b'A' * payload_length)

        if previous_encrypted:
            match = len([0 for i in range(len(encrypted)) if encrypted[i] == previous_encrypted[i]])
            if not common_match:
                common_match = match
            if match > common_match:
                blocksize = match - common_match
                """isn't it just an anomaly?"""
                if blocksize % 8 == 0:
                    break
        previous_encrypted = encrypted
    if not blocksize:
        print('Cannot determine blocksize -> probably not CBC.', file=sys.stderr)
    debug('Determined blocksize:', blocksize)

    # Run one E-D cycle
    debug('Trying sample payload.')
    payload = b'thisishalloween'
    debug('Payload:', payload)
    #encrypted = Oracle.once(payload, e_oracle_path)
    encrypted = e_oracle.oneshot(payload)

    original_e_blocks = chunks(encrypted, blocksize)
    debug('Encrypted blocks:', original_e_blocks)

    #decrypted = Oracle.once(encrypted, d_oracle_path)
    decrypted = d_oracle.oneshot(encrypted)
    original_d_blocks = chunks(decrypted, blocksize)
    debug('Decrypted:', decrypted)
    debug('Decrypted blocks:', original_d_blocks)

    # modify (target_block-1) to get correct target_block
    """
        C2      C3
         |    ___|__
        1|    | AES |
         |    ```|```
         |       |2
         `-------X
                 |3
                 P
        3 = 1 ^ 2
        3' = 1' ^ 2
        -----------
        1' = 3' ^ 2
        1' = 3' ^ (1 ^ 3)
        1' = 3' (desired) ^ 1 (previous encrypted block) ^ 3 (string to replace)
    """
    fake_block = xor(xor(desired.as_raw(),
                         original_e_blocks[target_block - 1]),
                     original_d_blocks[target_block])

    new_blocks = (original_e_blocks[0:target_block - 1]
                  + [fake_block]
                  + original_e_blocks[target_block:])
    debug('New blocks:', new_blocks)
    #decrypted = Oracle.once(b''.join(new_blocks), d_oracle_path)
    decrypted = d_oracle.oneshot(b''.join(new_blocks))
    return decrypted


def cbc_padding(ciphertext, oracle, blocksize, iv=None):    
    """
    CBC Padding Oracle Attack

    We can use CBC principles to test faked PKCS#7 padding. This
    leads to plaintext revelation.
    """
    ciphertext = ciphertext.as_raw()
    if iv:
        iv = iv.as_raw()
    # create blocks of blocksize
    blocks = [ciphertext[i:i+blocksize]
              for i in range(0, len(ciphertext), blocksize)]

    if any(len(b) != blocksize for b in blocks):
        log.warn('Not all blocks have correct blocksize.')

    final_plaintexts = []
    # run through blocks in reverse order
    for block_index, block in enumerate(blocks[::-1]):
        block_plaintext = b''
        try:
            previous_block = blocks[::-1][block_index + 1]
            debug('Previous block:',
                  ' '.join('%02x' % c for c in previous_block))
        except:
            previous_block = iv # even None
            debug('Previous block:',
                  (' '.join('%02x' % c for c in previous_block)
                   if iv
                   else 'None'))

        debug('Actual block:  ', ' '.join('%02x' % c for c in block))

        # for each byte in block in reverse order
        for byte_index in range(blocksize-1, -1, -1):
            debug('Dealing with byte #%d (%02x)'
                  % (byte_index, block[byte_index]))

            # prepare payloads for bruteforce
            valid_padding_byte = -1
            #payloads = {}
            payloads = []
            for bf_byte in range(256):
                # prepare fake previous block - start with zeros
                fake_prev = b'\x00' * (blocksize - len(block_plaintext) - 1)
                # add bruteforced byte
                fake_prev += b'%c' % bf_byte

                # then add values so xor with block gives expected padding values
                # skipped on the first run
                for byte_pos, plaintext_byte in enumerate(block_plaintext):
                    fake_prev += b'%c' % (plaintext_byte
                                          ^ (len(block_plaintext) + 1) # expected padding
                                          ^ (previous_block[blocksize-len(block_plaintext)+byte_pos]
                                             if previous_block
                                             else 0))
                # add the block and test it
                #payloads[bf_byte] = fake_prev + block
                payloads.append(fake_prev + block)
            # bruteforce the padding
            '''
            oracle_count = 1 # use this for debug
            oracle_count = 8 # use this for speed
            oracles = [Oracle(oracle_path,
                              {k:v for k,v in payloads.items()
                               if k // (len(payloads)/oracle_count) == i},
                              lambda i,o,e,kw: (r == 0))
                       for i in range(oracle_count)]
            
            for oracle in oracles:
                oracle.start()
            for oracle in oracles:
                oracle.join()
                if oracle.matching:
                    valid_padding_byte = oracle.matching[0].payload_id
            '''
            oracle.run(*payloads, thread_count=1, condition=lambda i,o,kw: bool(o))
            if oracle.matching:
                valid_padding_byte = oracle.matching[0].payload_id
            oracle.reset()
            if valid_padding_byte == -1:
                debug('Failed to find valid padding byte!')
                break

            debug('Found valid padding byte:', valid_padding_byte)
            """compute plaintext byte from padding byte"""
            block_plaintext = (b'%c' % ((len(block_plaintext) + 1) # expected padding
                                        ^ (previous_block[byte_index]
                                           if previous_block
                                           else 0) # byte of previous block
                                        ^ valid_padding_byte) #
                               + block_plaintext)
            debug('New block plaintext:', block_plaintext)
        final_plaintexts.append(block_plaintext)
    #try:
    #    print('Final plaintext:', (b''.join(final_plaintexts[::-1])).decode())
    #except:
    #    print('Final plaintext:', b''.join(final_plaintexts[::-1]))
    return pkcs7_unpad(b''.join(final_plaintexts[::-1]))

def brute_timestamp_seed(rng, value, value_offset, reference_ts):
    """
    After a RNG is seeded, only number of calls is relevant to the new
    values. This function, for given value, tries to decrease current
    timestamp as seed until match.

    Value is processed as bytes, first value_offset bytes from RNG are skipped.
    """
    rngs = {
        'Mersenne32': MersenneTwister32,
        'Mersenne64': MersenneTwister64,
    }
    if rng not in rngs.keys():
        log.err('Unsupported RNG.')
        return None

    if not reference_ts:
        reference_ts = datetime.timestamp(datetime.now())

    # TODO make it killable
    seed = reference_ts
    while True:
        debug('Using seed', seed)
        mt = rngs[rng](seed)
        if value_offset:
            #debug('  Skipping %d bytes.' % value_offset)
            r = mt.get('bytes', value_offset)
        r = mt.get('bytes', len(value.as_raw()))
        debug('  Desired:', value.as_raw())
        debug('  Got:    ', r)
        if r == value.as_raw():
            return seed
        seed -= 1

def clone_rng(rng, states):
    """
    Mersenne Twister (32b) can be cloned if we known 624 successive values. 
    """
    if rng == 'Mersenne32':
        def unshift_left_mask_xor(mt, value, shift, mask):
            result = 0
            for i in range(0, mt.params['w'] // shift + 1):
                part_mask = (mt.params['d'] >> (mt.params['w'] - shift)) << (shift * i)
                part = value & part_mask
                value ^= (part << shift) & mask
                result |= part
            return result
        def unshift_right_xor(mt, value, shift):
            result = 0
            for i in range(mt.params['w'] // shift + 1):
                result ^= value >> (shift * i)
            return result
        def untemper(mt, y):
            value = y
            value = unshift_right_xor(mt, value, mt.params['l'])
            value = unshift_left_mask_xor(mt, value, mt.params['t'], mt.params['c'])
            value = unshift_left_mask_xor(mt, value, mt.params['s'], mt.params['b'])
            value = unshift_right_xor(mt, value, mt.params['u'])
            #debug(y, 'untempered to', value)
            return value

        #print('states:', len(states))
        result = MersenneTwister32(0) # seed is unknown and not important
        result.state = [untemper(result, x) for x in states]
    else:
        log.err('Cloning such RNG is not supported.')
        return None
    return result

def brute_rng_xor(rng, ciphertext, known):
    """
    Using RNG to generate XOR key is cool, but the secret is only seed.
    We can brute it easily if we know portion of plaintext.
    """
    known = known.as_raw()
    rngs = {
        'Mersenne32': MersenneTwister32,
        'Mersenne64': MersenneTwister64,
    }
    if rng not in rngs.keys():
        log.err('Unsupported RNG.')
        return None

    seed = 0
    x = XOR(ciphertext=ciphertext)
    while True:
        if seed % 1024 == 0:
            debug(seed)
        mt = rngs[rng](seed)
        x.params['key'] = mt
        plaintext = x.decrypt().as_raw()
        if known in plaintext:
            return seed
        seed += 1
    return None

# just use 'oracle o plaintext'...
''' 
def ctr_random_access(oracle_path, plaintext):
    """
    Assuming oracle takes our plaintext and includes it in existing
    CTR ciphertext, we can provide ciphertext instead. In CTR, encryption
    and decryption is functionally identical => plaintext will be revealed.
    """
    result = Oracle.once(oracle_path, plaintext)
    return result
'''

def ctr_bitflipping(e_oracle, d_oracle, offset, desired):
    """
    CTR bitflipping

    Similarly to CBC bitflipping, we can use XOR properties to replace
    arbitrary data in CTR ciphertext if we know both ciphertext and
    plaintext. Unlike CBC, offset is not block-aligned and can be arbitrary.
    """
    offset = offset.as_int()
    desired = desired.as_raw()
    # Run one E-D cycle
    debug('Trying sample payload.')
    payload = b'thisishalloween'
    debug('Payload:', payload)
    #encrypted = Oracle.once(payload, e_oracle_path)
    encrypted = e_oracle.oneshot(payload)

    #original_e_blocks = chunks(encrypted, blocksize)
    #debug('Encrypted blocks:', original_e_blocks)
    #decrypted = Oracle.once(encrypted, d_oracle_path)
    decrypted = d_oracle.oneshot(encrypted)
    #original_d_blocks = chunks(decrypted, blocksize)
    debug('Decrypted:', decrypted)
    #debug('Decrypted blocks:', original_d_blocks)
    #target_block = 3 # holding some comment...
    """
         C      CTR
         |    ___|__
        1|    | AES |
         |    ```|```
         |       |2
         `-------X
                 |3
                 P
        3 = 1 ^ 2
        3' = 1' ^ 2
        -----------
        1' = 3' ^ 2
        1' = 3' ^ (1 ^ 3)
        1' = 3' (desired) ^ 1 (real encrypted block) ^ 3 (string to replace)
    """

    keystream = xor(encrypted[offset:offset + len(desired)],
                    decrypted[offset:offset + len(desired)])
    fake_block = xor(desired, keystream)

    fake = encrypted[:offset] + fake_block + encrypted[offset + len(fake_block):]
    #decrypted = Oracle.once(fake, d_oracle_path)
    debug('Bitflipping...')
    decrypted = d_oracle.oneshot(fake)
    return decrypted

def cbc_chosen_ciphertext(oracle, ciphertext):
    blocksize = 16
    ciphertext = ciphertext.as_raw()
    encrypted_chunks = chunks(ciphertext, blocksize)
    if len(encrypted_chunks) < 3:
        log.err('Message is too short.')
    #decrypted = Oracle.once(ciphertext, oracle_path)
    decrypted = oracle.oneshot(ciphertext)
    debug('Decrypted:', decrypted)
    fake = b''.join([encrypted_chunks[0],
                     b'\x00' * blocksize,
                     encrypted_chunks[0]])
    debug('Fake:', fake)
    #decrypted = Oracle.once(fake, oracle_path)
    decrypted = oracle.oneshot(fake)
    decrypted_chunks = chunks(decrypted, blocksize)
    debug('Decrypted:', decrypted_chunks)
    return xor(decrypted_chunks[0], decrypted_chunks[2])


def hash_extension(algorithm, original, original_hash, append, oracle):
    """
    We try to create MAC of new data replacing key with arbitrary characters.
    The hash state will be restored from provided digest -> key is not needed.
    """
    # Create new hashing object
    h = algorithm(data=append)
    # New payload needs the padding automatically added...
    debug('Preparing payloads up to key_length == 256...')
    for key_length in range(256):
        #debug('Key len:', key_length)
        h.restore(original_hash.as_raw())
        forged_data = h.pad(b'A' * key_length + original.as_raw())[key_length:] + append.as_raw()
        #debug('  Forged data:', forged_data)
        
        forged_digest = h.hash(bits_len=((key_length + len(forged_data)) * 8))
        #debug('   Forged digest:', forged_digest)

        #o = Oracle(oracle_path, {0: forged_digest+forged_data}, lambda i,r,o,e,kw: True)
        #o.start()
        #o.join()
        equal = oracle.oneshot(forged_data, forged_digest)
        #if o.matching[0].ret == 0:
        if equal:
            debug('  Oracle approves!', forged_digest)
            return forged_digest
        else:
            #debug('  oracle error:', o.matching[0].error)
            pass
    return ''


def timing_leak(oracle, threshold, slowest, alphabet):
    """
    Often the code is written in such manner that when problem occurs,
    the function is terminated prematurely. With time measuring it may be 
    possible to bruteforce secret values.

    The function prepares the payload by testing all possible byte values,
    then using the one with slowest/fastest response and continuing.

    Payload is sent to oracle. When return code is 0, the attack is 
    considered complete.
    """
    secret = b''
    #debug('Timing leak alphabet:', alphabet)
    while True:
        debug('Actual secret:', secret)
        # try each byte
        payloads = [secret + bytes([i]) for i in alphabet]
        oracle.run(*payloads, thread_count=int(math.sqrt(len(alphabet))))
        finished = [m for m in oracle.matching if m.output == 'success']
        if finished:
            #secret = list(finished[0].payloads.values())[0]
            secret = payloads[finished[0].payload_id]
            debug('Oracle succeeded with', secret)
            return secret
        # pair payloads to results
        paired = [(payloads[match.payload_id], match) for match in oracle.matching]
        # use slowest/fastest payload
        
        timed = sorted(paired, key=lambda x: x[1].time, reverse=slowest)
        best_diff = abs(timed[1][1].time - timed[0][1].time)
        if best_diff >= threshold:
            secret = timed[0][0]
        else:
            debug('  Threshold not met, trying again...')


def compression_leak(oracle, prepended, alphabet):
    """
    
    The function prepares the payload by testing all possible byte values,
    then using the one that is, according to the oracle, compressed best.

    Payload is sent to oracle. When 'success' is returned, the attack is 
    considered complete.
    """
    secret = b''
    #debug('Compression leak alphabet:', alphabet)
    while True:
        debug('Actual secret:', secret)
        # try each byte
        payloads = [prepended.as_raw() + secret + bytes([i]) for i in alphabet]
        oracle.run(*payloads, thread_count=int(math.sqrt(len(alphabet))))
        finished = [m for m in oracle.matching if m.output == 'success'] # TODO won't happend, think of another condition
        if finished:
            #secret = list(finished[0].payloads.values())[0]
            secret = payloads[finished[0].payload_id]
            debug('Oracle succeeded with', secret)
            return secret
        # pair payloads to results
        paired = [(payloads[match.payload_id], match)
                  for match in oracle.matching]
        # use slowest/fastest payload

        timed = sorted(paired, key=lambda x: int(x[1].output))
        # TODO for some reason valid part may have worse padding...
        if True:#if int(timed[0][1].output) < int(timed[1][1].output):
            new_byte = timed[0][0][-1]
            secret += bytes([new_byte])
        else:
            log.warn('No obvious candidate.')
            break
    return secret
        

def rsa_e3_broadcast(modulis, ciphertexts):
    """
    Best explanation: https://www.youtube.com/watch?v=nrgGU2mUum4
    """ # TODO more thorough description
    product = 1
    for m in modulis:
        product *= m.as_int()
    x = 0
    for m, c in zip(modulis, ciphertexts):
        product_part = product // m.as_int()
        inverse = invmod(product_part, m.as_int())
        x += c.as_int() * product_part * inverse
    x = x % product
    result = root(x, len(ciphertexts))
    return result

def rsa_unpadded_recovery(pubkey, oracle):
    """
    Oracle is expected to successfuly decrypt the given ciphertext, but
    only once (imagine some replay protection).

    If the plaintext is not padded before encryption, we can take advantage
    of the modulation to provide completely different ciphertext that
    can be easily transformed into original plaintext.
    """
    ciphertext = pubkey.params['ciphertext'].as_int()
    e = pubkey.params['e'].as_int()
    n = pubkey.params['n'].as_int()

    s = random.randint(2, n - 1)
    fake_ciphertext = Variable((ciphertext * pow(s, e, n)) % n)
    #fake_plaintext = Variable(Oracle.once(fake_ciphertext.as_raw(), oracle_path)).as_int()
    fake_plaintext = Variable(oracle.oneshot(fake_ciphertext.as_raw())).as_int()
    result = Variable((fake_plaintext * invmod(s, n)) % n)
    # TODO test with padded...
    pubkey.params['plaintext'] = result
    return result


def rsa_e3_forge_signature(rsa, hash_algorithm, variant=1):
    """
    When signature verification is implemented incorrectly, you can
    manually craft valid signature (mod N) if the e is small (=3).
    """
    # http://karabut.com/google-ctf-2017-quals-rsa-ctf-challenge-writeup.html

    hash_instance = hash_algorithm(data=rsa.params['plaintext'])
    h = Variable(hash_instance.hash())
    try:
        digest_info = hash_instance.params['digest_info'].as_raw()
    except:
        log.err('Hashing algorithm is not supported (unknown digest_info).')
        return None

    if variant == 1:
        # as in https://github.com/ricpacca/cryptopals
        # simple 0001ff00 + ASN.1 + HASH + 00s, find cube root of it
        # server will cube it and incorrecly check the padding
        block = (b'\x00\x01\xff\x00'
                 + digest_info
                 + h.as_raw()) 
        block = Variable(block + b'\x00' * ((rsa.params['bits'].as_int() + 7) // 8 - len(block))) # TODO how many?
        debug('Block:', block)
        signed = Variable(root(block.as_int(), 3))
        debug('Signed:', signed.as_escaped())
        return signed
    elif variant == 2:
        # TODO anything instead of ffs, no garbage after
        # as in python-rsa https://blog.filippo.io/bleichenbacher-06-signature-forgery-in-python-rsa/
        pass
    else:
        log.err('Unsupported variant.')
        return None


def dsa_private_from_nonce(dsa, k, signature, hash_algorithm):
    n = dsa.params['n'].as_int()
    p = dsa.params['p'].as_int()
    q = dsa.params['q'].as_int()
    g = dsa.params['g'].as_int()
    y = dsa.params['y'].as_int()
    dsa.params['k'] = Variable(k)
    k = dsa.params['k'].as_int()
    signature = signature.as_int()

    r = signature >> n
    s = signature & ((1 << n) - 1)

    hash_instance = hash_algorithm(data=dsa.params['plaintext'])
    h = Variable(hash_instance.hash()).as_int()
    x = (((s * k) - h) * invmod(r, q)) % q
    dsa.params['x'] = Variable(x)
    return x

def dsa_nonce_recovery(dsa1, rs1, dsa2, rs2, hash_algorithm):
    """
    Nonce can be recovered if 2 messages have been signed with
    same private key with same nonce (x, k, p, q, g, n are same)
    """
    n = dsa1.params['n'].as_int()
    q = dsa1.params['q'].as_int()

    hash1 = hash_algorithm(data=dsa1.params['plaintext'])
    hash2 = hash_algorithm(data=dsa2.params['plaintext'])
    m1 = Variable(hash1.hash()).as_int()
    m2 = Variable(hash2.hash()).as_int()
    s1 = rs1 & ((1 << n) - 1)
    s2 = rs2 & ((1 << n) - 1)

    #print('m1', m1)
    #print('m2', m1)
    #print('s1', s1)
    #print('s2', s2)
    k = ((m1 - m2) % q * invmod((s1 - s2) % q, q)) % q
    return k

def dsa_magic_signature(dsa):
    n = dsa.params['n'].as_int()
    p = dsa.params['p'].as_int()
    q = dsa.params['q'].as_int()
    y = dsa.params['y'].as_int()

    z = 1 # can be arbitrary
    r = pow(y, z, p) % q
    s = invmod(r, z) % q
    return (r << n) + s  # concatenated

    
def rsa_parity(oracle, ciphertext, public):
    ciphertext = ciphertext.as_int()
    n = public.params['n'].as_int()
    # encrypt 2 to get multiplier for ciphertext
    public.params['plaintext'] = Variable(2)
    multiplier = public.encrypt().as_int()
    
    lower_bound = 0
    upper_bound = n
    #print('ciphertext', ciphertext)
    #print('multiplier', multiplier)
    
    iter_count = math.ceil(math.log(n, 2))
    for _ in range(iter_count):
        ciphertext = (ciphertext * multiplier) % n
        #oracle = Oracle(oracle_path, {0: Variable(ciphertext).as_raw()}, lambda i,r,o,e,kw: True)
        #oracle.start()
        #oracle.join()
        #lsb = oracle.oneshot(Variable(ciphertext).as_raw())
        lsb = oracle.oneshot(ciphertext)
        #if oracle.matching[0].output == b'1':
        if lsb == b'1':
            lower_bound = (lower_bound + upper_bound) // 2
        else:
            upper_bound = (lower_bound + upper_bound) // 2
        debug(Variable(upper_bound).as_raw())
    return upper_bound


def rsa_padding(oracle, ciphertext, public):
    #public.params['d'] = Variable('file:/tmp/d', constant=True)
    #public.params['n'] = Variable('file:/tmp/n', constant=True)
    #public.params['e'] = Variable(3)

    def ceil(a, b):
        return (a + b - 1) // b
        
    ciphertext = ciphertext.as_int()
    e = public.params['e'].as_int()
    n = public.params['n'].as_int()
    k = ceil(public.params['bits'].as_int(), 8)
    bb = 2 ** (8 * (k - 2))
    c0 = ciphertext

    intervals = [(2*bb, 3*bb-1)]
    # Phase 1: compute m0
    if oracle.oneshot(c0) != b'0':
        debug('Phase 1: Finding valid s')  
        while True:
            s = random.randint(0, n - 1)
            c0 = (ciphertext * pow(s, e, n)) % n
            if oracle.oneshot(c0) == b'0':
                break
    i = 1
    bulk_size = 1000
    while True:
        # Phase 2a: Start search
        if i == 1:
            debug('Phase 2a: Search started')
            # go in bulks
            s = ceil(n, 3 * bb)
            while True:
                ss = range(s, s + bulk_size)
                cs = [(c0 * pow(s, e, n)) % n for s in ss]
                #c = (c0 * pow(s, e, n)) % n
                #if oracle.oneshot(c) == b'0':
                oracle.run(*cs, thread_count=8, condition=lambda i, o, kw: o == b'0')
                if oracle.matching:
                    s = list(ss)[oracle.matching[0].payload_id]
                    c = cs[oracle.matching[0].payload_id]
                    oracle.reset()
                    debug('Phase 2a: Search finished, s = %d.' % s)
                    break
                #s += 1
                s += bulk_size
                oracle.reset()
        
        # Phase 2b: searching in more intervals
        elif len(intervals) > 1:
            debug('Phase 2b: Interval count: %d' % (len(intervals)))
            while True:
                ss = range(s + 1, s + bulk_size + 1)
                cs = [(c0 * pow(s, e, n)) % n for s in ss]
                oracle.run(*cs, thread_count=8,
                           condition=lambda i, o, kw: o == b'0')
                if oracle.matching:
                #if oracle.oneshot(c) == b'0':
                    s = list(ss)[oracle.matching[0].payload_id]
                    c = cs[oracle.matching[0].payload_id]
                    oracle.reset()
                    debug('Phase 2b: Search finished, s = %d.' % s)
                    break
                s += bulk_size
                oracle.reset()
        
        # Phase 2c: searching in one interval
        elif len(intervals) == 1:
            a, b = intervals[0]
            debug('Phase 2c: 1 interval, distance %d' % (hamming(gray(Variable(a).as_raw()), gray(Variable(b).as_raw()))))
            if a == b:
                return b'\x00' + int_to_bytes(a)
            r = ceil(2*(b*s - 2*bb), n)
            s = ceil(2 * bb + r * n, b)
            
            while True:
                c = (c0 * pow(s, e, n)) % n
                if oracle.oneshot(c) == b'0':
                    break
                s += 1
                if s > (3 * bb + r * n) // a:
                    r += 1
                    s = ceil((2 * bb + r * n), b)
        
        # Phase 3: Narrowing the set of solutions
        intervals_new = []
        for a, b in intervals:
            min_r = ceil(a * s - 3 * bb + 1, n)
            max_r = (b * s - 2 * bb) // n
            
            for r in range(min_r, max_r + 1):
                l = max(a, ceil(2 * bb + r * n, s))
                u = min(b, (3 * bb - 1 + r * n) // s)
                if l > u:
                    raise Exception('RSA Error: L > U')
                # add new interval
                overlap_found = False
                for j, (x, y) in enumerate(intervals_new):
                    if not (y < l or x > u):
                        overlap_found = True
                        x_new = min(l, x)
                        y_new = max(u, y)
                        intervals_new[j] = (x_new, y_new)
                if not overlap_found:
                    intervals_new.append((l, u))
                
        if not intervals_new:
            raise Exception('RSA Error: No new intervals')
        intervals = intervals_new
        i += 1


def cbc_mac_length_extension(valid_message, valid_mac, append, iv):
    # https://github.com/ashutosh1206/Crypton/tree/master/Message-Authentication-Code/Attack-Length-Extension-CBC-MAC
    valid_message = valid_message.as_raw()
    valid_mac = valid_mac.as_raw()
    append = append.as_raw()
    iv = iv.as_raw()
    forged = (pkcs7_pad(valid_message) +
              xor(xor(valid_mac, iv), append[:16]) +
              append[16:])
    return forged


#####
