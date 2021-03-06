#!/usr/bin/python3
from source.functions import *
from source.classes import *


def test_binary():
    assert binary(b'A\xff') == b'0100000111111111'
    assert unbinary(b'0100000111111111') == b'A\xff'
    assert unbinary(b'100000111111111') == b'A\xff'
    assert unbinary(b'0b100000111111111') == b'A\xff'
    assert unbinary(b'0b100000111111111\n') == b'A\xff'


def test_hexadecimal():
    assert hexadecimal(b'A\xff') == b'41ff'
    assert unhexadecimal(b'41ff') == b'A\xff'
    assert unhexadecimal(b'0x41ff') == b'A\xff'
    assert unhexadecimal(b'0x41ff\n') == b'A\xff'


def test_gray():
    assert gray(b'\x01\x00') == b'\x01\x80'
    assert gray(b'\x059') == b'\x07\xa5'
    assert gray(b'\x07[\xcd\x15') == b'\x04\xf6+\x9f'
    assert ungray(b'\x01\x80') == b'\x01\x00'
    assert ungray(b'\x07\xa5') == b'\x059'
    assert ungray(b'\x04\xf6+\x9f') == b'\x07[\xcd\x15'


def test_rev():
    v = Variable(b'A\xff')
    assert Variable.get_reversed(v).value == Variable(b'\xffA').value
    assert Variable.get_reversed(v, 8).value == Variable(b'\xffA').value
    assert Variable.get_reversed(v, 1).value == Variable(
        '1111111110000010').value


def test_statistics():
    assert entropy(b'Hello World!') == 0.37775690110927507
    assert coincidence(b'ABAaA') == 0.6
    assert int(coincidence(
        b'To be, or not to be, that is the question') * 1000) == 96


def test_bitwise():
    assert xor(b'Hello World!', b'ICE') == b"\x01&)%,e\x1e,7%'d"
    assert xor(b'Hello World!', b'\x00') == b'Hello World!'
    assert xor(b'Hello World!',
               b'Hello World!') == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    assert xor(
        Variable(0x1c0111001f010100061a024b53535009181c).as_raw(),
        Variable(b"hit the bull's eye").as_raw()) == b"the kid don't play"

    assert xor(
        b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
        b'ICE') == Variable(0x0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f).as_raw()
    assert bitwise_not(b'\x41\xff') == b'\xbe\x00'
    assert bitwise_and(b'Hello World!', b'ICE') == b'HADHC\x00AC@H@\x01'
    assert bitwise_or(b'Hello World!', b'ICE') == b'Igmmoe_owmge'


def test_variable():
    v = Variable(b'YELLOW SUBMARINE')
    # output support
    assert v.as_binary() == '01011001010001010100110001001100010011110101011100100000010100110101010101000010010011010100000101010010010010010100111001000101'
    assert v.as_int() == 118661107617121289380992810610737106501
    assert v.as_hex() == '0x59454c4c4f57205355424d4152494e45'
    assert v.as_raw() == b'YELLOW SUBMARINE'
    assert v.as_base64() == 'WUVMTE9XIFNVQk1BUklORQ=='
    # input support
    assert Variable('YELLOW SUBMARINE',
                    constant=True).as_raw() == b'YELLOW SUBMARINE'
    assert Variable("'YELLOW SUBMARINE'",
                    constant=True).as_raw() == b'YELLOW SUBMARINE'
    assert Variable('"YELLOW SUBMARINE"',
                    constant=True).as_raw() == b'YELLOW SUBMARINE'
    assert Variable('YELLOW SUBM\x41RINE',
                    constant=True).as_raw() == b'YELLOW SUBMARINE'
    assert Variable('base64:WUVMTE9XIFNVQk1BUklORQ==',
                    constant=True).as_raw() == b'YELLOW SUBMARINE'
    assert Variable(
        '118661107617121289380992810610737106501').as_raw() == b'YELLOW SUBMARINE'
    assert Variable(
        118661107617121289380992810610737106501).as_raw() == b'YELLOW SUBMARINE'
    assert Variable(
        0x59454c4c4f57205355424d4152494e45).as_raw() == b'YELLOW SUBMARINE'
    assert Variable(
        '0x59454c4c4f57205355424d4152494e45').as_raw() == b'YELLOW SUBMARINE'
    assert Variable(
        '59454c4c4f57205355424d4152494e45').as_raw() == b'YELLOW SUBMARINE'
    assert Variable(0b01011001010001010100110001001100010011110101011100100000010100110101010101000010010011010100000101010010010010010100111001000101).as_raw(
    ) == b'YELLOW SUBMARINE'
    assert Variable('0b01011001010001010100110001001100010011110101011100100000010100110101010101000010010011010100000101010010010010010100111001000101').as_raw(
    ) == b'YELLOW SUBMARINE'
    # TODO 'image:'


def test_hamming():
    assert hamming(b'this is a test', b'wokka wokka!!!') == 37


if __name__ == '__main__':
    try:
        print('Run from VS Code.')
    except SystemExit:
        pass
