#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import binascii


test_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(test_dir, '../src')
sys.path.append(src_dir)

from cryptotool import *


def test_b58():
    print('-' * 10)
    print('test B58')
    test_cases = [
        {'value': b'\x00\x00', 'result': '11'},
        {'value': b'\x00\x01', 'result': '12'},
        {'value': b'\x39', 'result': 'z'},
        {'value': b'\x3a', 'result': '21'},
        {'value': binascii.unhexlify('00faff0a22892a12628ab869c4dad29e4db30e9e1c1c518cf7'), 'result': '1Pt9TRJKeAW61aR1ELQpUZKdMaYXzkCTrn'},
        {'value': binascii.unhexlify('d0f4508033c5f56be1104146bd2a33c3e393ee755afe3a56960c81f11a9c2737'), 'result': 'F4fshQ6TdtySEi34wVpfK15w4GMHR6b9QjhQoCNkcPvN'},
     ]

    for test in test_cases:

        result = B58().pack(test['value'])
        if result != test['result']:
            print(
                'Error pack b58',
                'value:', test['value'].hex(),
                'got b58:', result,
                'expected b58:', test['result'])
        value = B58().unpack(test['result'])
        if value != test['value']:
            print(
                'Error unpack b58',
                'value:', test['value'].hex(),
                'got b58:', value.hex(),
                'expected b58:', test['value'].hex())


def test_sha256():
    print('-' * 10)
    print('test SHA256')
    test_cases = [
        {'value': b'', 'result': binascii.unhexlify('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')},
        {'value': b'1', 'result': binascii.unhexlify('6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b')},
        {'value': b'qwew', 'result': binascii.unhexlify('a79ea83b27091b326e6bcdf58429a0230ecb95fc9261d0e5b994a4fb7fbe3873')},
    ]

    for test in test_cases:
        result = sha256(test['value'])
        if result != test['result']:
            print(
                'Error hashing',
                'value:', test['value'],
                'got hash:', result.hex(),
                'expected hash:', test['result'].hex())


def test_aes():
    print('-' * 10)
    print('test AES')

    message = 'erthheherhe4563g45$%^#$G45b4b3b63456b'.encode('utf8')

    aes_gen = AES()
    key = aes_gen.get_key()
    aes_export = AES(key)

    secret_1 = aes_gen.encode(message)
    secret_2 = aes_export.encode(message)

    message_decrypt_1 = aes_gen.decode(secret_1)
    message_decrypt_2 = aes_gen.decode(secret_1)
    message_decrypt_3 = aes_export.decode(secret_1)
    message_decrypt_4 = aes_export.decode(secret_1)

    if not (message == message_decrypt_1 == message_decrypt_2 == message_decrypt_3 == message_decrypt_4):
        print('Error decode AES')

    aes_wrong = AES()
    message_decrypt_wrong = aes_wrong.decode(secret_1)

    if message == message_decrypt_wrong:
        print('Error decode AES with wrong key')


def test_ecdsa():
    print('-' * 10)
    print('test ECDSA')

    message_1 = 'qwerty123'.encode('utf8')
    message_2 = 'ytrewq321'.encode('utf8')

    ecdsa_gen = ECDSA()

    priv_key_1 = ecdsa_gen.get_priv_key()
    pub_key_1 = ecdsa_gen.get_pub_key()

    ecdsa_priv_export = ECDSA(priv_key=priv_key_1)
    ecdsa_pub_export = ECDSA(pub_key=pub_key_1)

    sign_1_1 = ecdsa_gen.sign(message_1)
    sign_1_2 = ecdsa_priv_export.sign(message_1)

    if not ecdsa_gen.check_signature(message_1, sign_1_1) is True:
        print('Error ECDSA check_signature')
    if not ecdsa_gen.check_signature(message_1, sign_1_2) is True:
        print('Error ECDSA check_signature')

    if not ecdsa_priv_export.check_signature(message_1, sign_1_1) is True:
        print('Error ECDSA check_signature')
    if not ecdsa_priv_export.check_signature(message_1, sign_1_2) is True:
        print('Error ECDSA check_signature')

    if not ecdsa_pub_export.check_signature(message_1, sign_1_1) is True:
        print('Error ECDSA check_signature')
    if not ecdsa_pub_export.check_signature(message_1, sign_1_2) is True:
        print('Error ECDSA check_signature')

    if not ecdsa_gen.check_signature(message_2, sign_1_1) is False:
        print('Error ECDSA check_signature set pub_key/wrong message')
    if not ecdsa_gen.check_signature(message_2, sign_1_2) is False:
        print('Error ECDSA check_signature set pub_key/wrong sign')
    if not ecdsa_gen.check_signature(message_1, b'\x00' * len(sign_1_1)) is False:
        print('Error ECDSA check_signature set pub_key/wrong message')

    if not ecdsa_priv_export.check_signature(message_2, sign_1_1) is False:
        print('Error ECDSA check_signature set pub_key/wrong message')
    if not ecdsa_priv_export.check_signature(message_2, sign_1_2) is False:
        print('Error ECDSA check_signature set pub_key/wrong sign')
    if not ecdsa_priv_export.check_signature(message_1, b'\x00' * len(sign_1_1)) is False:
        print('Error ECDSA check_signature set pub_key/wrong message')

    if not ecdsa_pub_export.check_signature(message_2, sign_1_1) is False:
        print('Error ECDSA check_signature set pub_key/wrong message')
    if not ecdsa_pub_export.check_signature(message_2, sign_1_2) is False:
        print('Error ECDSA check_signature set pub_key/wrong sign')
    if not ecdsa_pub_export.check_signature(message_1, b'\x00' * len(sign_1_1)) is False:
        print('Error ECDSA check_signature set pub_key/wrong message')

    wrong_pub_key = binascii.unhexlify('4017ba920ba91aa94e4c4b850b5e4f558842be6c6cbdd5155afd35a70b6c1a0960bdea3b92135208075c4ec42e81309ed20ff52ee4c395cb6181ec065b6042fa')
    ecdsa_wrong_pub_export = ECDSA(pub_key=wrong_pub_key)

    if not ecdsa_wrong_pub_export.check_signature(message_1, sign_1_1) is False:
        print('Error ECDSA check_signature set pub_key/wrong message')
    if not ecdsa_wrong_pub_export.check_signature(message_1, sign_1_2) is False:
        print('Error ECDSA check_signature set pub_key/wrong sign')
    if not ecdsa_wrong_pub_export.check_signature(message_2, sign_1_1) is False:
        print('Error ECDSA check_signature set pub_key/wrong sign')
    if not ecdsa_wrong_pub_export.check_signature(message_2, sign_1_2) is False:
        print('Error ECDSA check_signature set pub_key/wrong sign')


def test_elgamal():
    print('-' * 10)
    print('test ELGAMAL')

    message = '12345qwerty'.encode('utf8')
    elgamal_gen = ELGAMAL(key_size=256)
    priv_key = elgamal_gen.get_priv_key()
    pub_key = elgamal_gen.get_pub_key()
    elgamal_priv_key_export = ELGAMAL(priv_key=priv_key)
    elgamal_pub_key_export = ELGAMAL(pub_key=pub_key)
    secret_1 = elgamal_gen.encrypt(message)
    secret_2 = elgamal_priv_key_export.encrypt(message)
    secret_3 = elgamal_pub_key_export.encrypt(message)
    
    message_decrypt_1 = elgamal_gen.decrypt(secret_1)
    message_decrypt_2 = elgamal_gen.decrypt(secret_2)
    message_decrypt_3 = elgamal_gen.decrypt(secret_3)
    message_decrypt_4 = elgamal_priv_key_export.decrypt(secret_1)
    message_decrypt_5 = elgamal_priv_key_export.decrypt(secret_2)
    message_decrypt_6 = elgamal_priv_key_export.decrypt(secret_3)

    if (message == message_decrypt_1 == message_decrypt_2 == message_decrypt_3 == message_decrypt_4 == message_decrypt_5 == message_decrypt_6) is False:
        print('Error ELGAMAL decrypt message')

    elgamal_gen_wrong = ELGAMAL(key_size=256)
    if (elgamal_gen_wrong.decrypt(secret_1) == message):
        print('Error ELGAMAL decrypt message, negative test')


def test_rsa():
    print('-' * 10)
    print('test RSA')

    message = '12345qwerty'.encode('utf8')
    rsa_gen = RSA(key_size=2048)
    priv_key = rsa_gen.get_priv_key()
    pub_key = rsa_gen.get_pub_key()
    rsa_priv_key_export = RSA(priv_key=priv_key)
    rsa_pub_key_export = RSA(pub_key=pub_key)
    secret_1 = rsa_gen.encrypt(message)
    secret_2 = rsa_priv_key_export.encrypt(message)
    secret_3 = rsa_pub_key_export.encrypt(message)
    
    message_decrypt_1 = rsa_gen.decrypt(secret_1)
    message_decrypt_2 = rsa_gen.decrypt(secret_2)
    message_decrypt_3 = rsa_gen.decrypt(secret_3)
    message_decrypt_4 = rsa_priv_key_export.decrypt(secret_1)
    message_decrypt_5 = rsa_priv_key_export.decrypt(secret_2)
    message_decrypt_6 = rsa_priv_key_export.decrypt(secret_3)

    if (message == message_decrypt_1 == message_decrypt_2 == message_decrypt_3 == message_decrypt_4 == message_decrypt_5 == message_decrypt_6) is False:
        print('Error RSA decrypt message')

    rsa_gen_wrong = RSA(key_size=2048)
    if (rsa_gen_wrong.decrypt(secret_1) == message):
        print('Error RSA decrypt message, negative test')


def test_ecdh():
    print('-' * 10)
    print('test ECDH')
    alis_gen = ECDH()
    alis_gen_priv_key = alis_gen.get_priv_key()
    alis_import = ECDH(alis_gen_priv_key)

    if alis_gen.get_pub_key() != alis_import.get_pub_key():
        print('Error ECDH export-import private key, negative test')

    bob_gen = ECDH()
    bob_shared_key = bob_gen.get_shared_key(alis_gen.get_pub_key())
    alis_shared_key = alis_gen.get_shared_key(bob_gen.get_pub_key())
    if bob_shared_key != alis_shared_key:
        print('Error ECDH shared key, negative test')


if __name__ == "__main__":
    print('test start')
    # test_b58()
    # test_sha256()
    # test_aes()
    # test_ecdsa()
    test_elgamal()
    # test_rsa()
    # test_ecdh()
    print('-' * 10)
    print('test end')
