#!/usr/bin/python3
"""
Sophisticated attacks are here
"""
import pdb
import traceback

from source.log import *
from source.functions import *
from source.classes import *


def break_xor(data, language):
    result = None
    # get normalized hamming for keysizes, smallest should be correct
    distances = {}
    for keysize in range(2, min(40, len(data))):
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
    (Cryptopals 2.12)
    
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
            break # TODO del
            #prynt(plaintext, end='')
        return plaintext


def ecb_injection(e_oracle_path, d_oracle_path):
    """
    ECB injection

    With control of portion of the plaintext, we can create fake blocks
    that we can feed into decryption routine, in this case resulting in
    authorization bypass.
    """
    # TODO not automated
    """find blocksize"""
    payload = b'A' * 129
    encrypted = Oracle.once(payload, e_oracle_path)
    patterns = find_repeating_patterns(encrypted)
    if not patterns:
        log.err('No patterns present -> probably not ECB.')
    else:
        blocksize = patterns[0][1] - patterns[0][0]
        debug('Determined blocksize:', blocksize)

        """find role=user offset"""
        payload = b'ninja@cia.gov'
        debug('Using', payload, 'as payload, len:', len(payload))
        encrypted = Oracle.once(payload, e_oracle_path)
        decrypted = Oracle.once(encrypted, d_oracle_path)
        debug('Decrypted message:', decrypted)
        debug('Decrypted chunks:', [decrypted[i:i+blocksize]
                                    for i in range(0, len(decrypted), blocksize)])

        payload_offset = decrypted.index(payload)
        debug('Payload offset:', payload_offset)
        role_to_payload_offset = (decrypted.index(b'user')
                                  - payload_offset
                                  - len(payload))
        debug('Role offset from the end of the payload:', role_to_payload_offset)

        start_payload_padding = blocksize - payload_offset
        end_payload_padding = len(payload) - start_payload_padding
        debug('Payload must have', start_payload_padding + end_payload_padding, 'bytes.')
        """in this case, the payload is OK"""
        payload = b'ninja@cia.gov'
        fake_block = pkcs7_pad(b'admin', blocksize)
        payload = (payload[:start_payload_padding]
                   + fake_block
                   + payload[start_payload_padding:])
        debug('Using', payload, 'as payload, len:', len(payload))

        encrypted = Oracle.once(payload, e_oracle_path)
        encrypted_chunks = [encrypted[i:i+blocksize]
                            for i in range(0, len(encrypted), blocksize)]
        reordered = b''.join(encrypted_chunks[x] for x in (0, 2, 1))
        decrypted = Oracle.once(reordered, d_oracle_path)
        debug('Decrypted message:', decrypted)
        debug('Decrypted chunks:', [decrypted[i:i+blocksize]
                                    for i in range(0, len(decrypted), blocksize)])
        return decrypted

#####
