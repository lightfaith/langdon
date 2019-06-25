#!/usr/bin/python3
"""
Sophisticated attacks are here
"""
import pdb
import traceback

from source.log import *
from source.functions import *
from source.classes import *

def fixed_nonce(texts, language):
    """
    If CTR mode is used with fixed nonce for multiple cases, it can be
    broken as XOR.
    """
    #print('num of texts:', len(texts)) #TODO del
    min_length = min([len(l) for l in texts])
    aligned_lines = [l[:min_length] for l in texts]
    #print('aligned to', min_length) # TODO del
    transposed_lines = [b''.join(b'%c' % l[i]
                                for l in aligned_lines)
                       for i in range(min_length)]
    xor_key = b''
    #print('transposed count:', len(transposed_lines))
    for line in transposed_lines:
        #print('transposed len', len(line))
        xors = list(bruteforce(line,
                               [b'%c' % c for c in range(256)],
                               lambda a, b: xor(a, b)))
        best = sorted(xors, key=lambda x: get_frequency_error(x, language))
        #for i in range(3):
        #    print(get_frequency_error(best[i], language))
        xor_key += b'%c' % (xors.index(best[0]))
    #print(xor_key)
    log.info('Revealed XOR value:', Variable(xor_key))
    result = XORAlgorithm(key=Variable(xor_key),
                          ciphertext=Variable(texts[0]),
                          plaintext=Variable(xor(texts[0], xor_key)))
    return result


def break_xor(data, language, keysize=None):
    result = None
    # get normalized hamming for keysizes, smallest should be correct
    distances = {}
    keysizes = [keysize] if keysize else range(2, min(40, len(data)))
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

    # use 2 best distances and try to get characters based on best frequency
    #for keysize, distance in best[:2]:
    for keysize, distance in best[:1]:
        key = b''
        debug('Trying keysize %d (distance %.3f)' % (keysize, distance))
        for offset in range(keysize):
            transposed = data[offset::keysize]
            xors = list(bruteforce(transposed,
                                   [b'%c' % c for c in range(256)],
                                   lambda a, b: xor(a, b)))
            best = sorted(xors, key=lambda x: get_frequency_error(x, language))
            #for i in range(3):
            #    print(get_frequency_error(best[i], language))
            key += b'%c' % (xors.index(best[0]))
            debug('Adding 0x%02x to key.' % key[-1])
            #for i in range(3):
            #    print(get_frequency_error(best[i], language))
        if not result:
            result = XORAlgorithm(key=Variable(key),
                                  ciphertext=Variable(data),
                                  plaintext=Variable(xor(data, key)))
        #print('Key for keysize %d:' % keysize, key)
        #print('Deciphered message:')
        #prynt(xor(data, key))
    return result


def ecb_chosen_plaintext(oracle_path):
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
        oracle = Oracle(oracle_path, {0: prepend}, lambda i,r,o,e,kw: True)
        oracle.start()
        oracle.join()
        ciphertext = oracle.matching[0].output
        patterns = find_repeating_patterns(ciphertext)
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
                oracle = Oracle(oracle_path,
                                {0: reference_payload},
                                lambda i,r,o,e,kw: True)
                oracle.start()
                oracle.join()
                reference_index = block_counter * blocksize
                #print('reference index:', reference_index)
                reference = oracle.matching[0].output[reference_index:reference_index+blocksize]
                if not reference:
                    # end of ciphertext
                    debug('No reference, this is the end.')
                    done = True
                    break
                #debug('Reference:', reference)
                # try all bytes instead of first text byte
                payloads = {byte_index: (start_padding
                                         + b'A' * offset
                                         + plaintext
                                         + b'%c' % byte_index)
                            for byte_index in range(256)}
                oracle_count = 8
                #oracle_count = 1 # TODO del
                #workload = (len(payloads) // oracle_count
                #            + (1 if len(payloads) % oracle_count != 0 else 0))
                datasets = [{k:v for k,v in list(payloads.items())[i::oracle_count]}
                            for i in range(oracle_count)]
                oracles = [Oracle(oracle_path,
                                  #{k:v for k,v in 
                                  # list(payloads.items())[i*workload:(i+1)*workload]},
                                  datasets[i],
                                  (lambda i,r,o,e,kw:
                                   (o[kw['reference_index']:kw['reference_index']
                                    + kw['blocksize']] == kw['reference'])),
                                  reference=reference,
                                  reference_index=reference_index,
                                  blocksize=blocksize)
                           for i in range(oracle_count)]
                #debug(oracles)
                new_byte_found = False
                for oracle in oracles:
                    oracle.start()
                for oracle in oracles:
                    oracle.join()
                    if oracle.matching:
                        if new_byte_found:
                            #another matching byte? we are decrypting
                            #static block!
                            #repair the damage and move on
                            plaintext = plaintext[:-1]
                            new_byte_found = False
                            break
                        plaintext += b'%c' % oracle.matching[0].payload_id
                        new_byte_found = True
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


def ecb_injection(e_oracle_path, d_oracle_path, expected, desired, payload=None):
    """
    ECB injection
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
    encrypted = Oracle.once(blocksize_payload, e_oracle_path)
    patterns = find_repeating_patterns(encrypted)
    if not patterns:
        log.err('No patterns present -> probably not ECB.')
    else:
        blocksize = patterns[0][1] - patterns[0][0]
        debug('Determined blocksize:', blocksize)
        
        decrypted = Oracle.once(encrypted, d_oracle_path)
        # determine payload offset
        debug('Determining payload offset...')
        payload_offset = decrypted.index(blocksize_payload)
        debug('Payload offset:', payload_offset)
    
        debug('Determining size of data between payload and expected...')
        # find length of data between the 'A' payload and the expected value
        payload_to_expected = decrypted.index(expected) - payload_offset - len(blocksize_payload)
        debug('Found difference: %d.' % payload_to_expected)
        real_payload_size = (blocksize - payload_offset - payload_to_expected) % 16
        debug('You must use payload of length %d (or + n * %d)' % (real_payload_size, blocksize))

        if not payload:
            payload = b'X' * real_payload_size

        # find expected value offset
        debug('Using', payload, 'as payload, len:', len(payload))
        encrypted = Oracle.once(payload, e_oracle_path)
        decrypted = Oracle.once(encrypted, d_oracle_path)
        debug('Decrypted message:', decrypted)
        debug('Decrypted chunks:', [decrypted[i:i+blocksize]
                                    for i in range(0, len(decrypted), blocksize)])


        # the fake block must be created in the middle of attacker-controlled
        # payload -> get left and right lengths
        # PKCS#7 pad the fake block
        start_payload_padding = blocksize - payload_offset
        end_payload_padding = len(payload) - start_payload_padding
        
        fake_block = pkcs7_pad(desired, blocksize)
        payload = (payload[:start_payload_padding]
                   + fake_block
                   + payload[start_payload_padding:])
        debug('Using', payload, 'as final payload, len:', len(payload))

        encrypted = Oracle.once(payload, e_oracle_path)
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
        decrypted = Oracle.once(reordered, d_oracle_path)
        debug('Decrypted message:', decrypted)
        debug('Decrypted chunks:', [decrypted[i:i+blocksize]
                                    for i in range(0, len(decrypted), blocksize)])
        return decrypted


def cbc_bitflipping(e_oracle_path, d_oracle_path, target_block, desired):
    """
    CBC bitflipping
    (Cryptopals 2.16)

    We can use unneeded chunk to hold specific value than, after XORed
    with next decoded chunk, will create desired payload. In total,
    2 blocks are destroyed. In CP 16, authorization is bypassed.
    """
    # determine blocksize
    blocksize = None
    common_match = 0
    previous_encrypted = b''
    for payload_length in range(8, 129):
        encrypted = Oracle.once(b'A' * payload_length, e_oracle_path)
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
    encrypted = Oracle.once(payload, e_oracle_path)
    original_e_blocks = chunks(encrypted, blocksize)
    debug('Encrypted blocks:', original_e_blocks)

    decrypted = Oracle.once(encrypted, d_oracle_path)
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
    fake_block = xor(xor(desired,
                         original_e_blocks[target_block - 1]),
                     original_d_blocks[target_block])

    new_blocks = (original_e_blocks[0:target_block - 1]
                  + [fake_block]
                  + original_e_blocks[target_block:])
    debug('New blocks:', new_blocks)
    decrypted = Oracle.once(b''.join(new_blocks), d_oracle_path)
    return decrypted


def cbc_padding(ciphertext, oracle_path, blocksize, iv=None):    
    """
    CBC Padding Oracle Attack

    We can use CBC principles to test faked PKCS#7 padding. This
    leads to plaintext revelation.
    """
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
                  ' '.join('%02x' % c for c in previous_block))

        debug('Actual block:  ', ' '.join('%02x' % c for c in block))

        # for each byte in block in reverse order
        for byte_index in range(blocksize-1, -1, -1):
            debug('Dealing with byte #%d (%02x)'
                  % (byte_index, block[byte_index]))

            # prepare payloads for bruteforce
            valid_padding_byte = -1
            payloads = {}
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
                payloads[bf_byte] = fake_prev + block
            # bruteforce the padding
            oracle_count = 1 # use this for debug
            oracle_count = 8 # use this for speed
            oracles = [Oracle(oracle_path,
                              {k:v for k,v in payloads.items()
                                   if (k // (len(payloads)/oracle_count) == i)},
                              lambda i,r,o,e,kw: (r == 0))
                       for i in range(oracle_count)]
            for oracle in oracles:
                oracle.start()
            for oracle in oracles:
                oracle.join()
                if oracle.matching:
                    valid_padding_byte = oracle.matching[0].payload_id

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
    return b''.join(final_plaintexts[::-1])
 
#####
