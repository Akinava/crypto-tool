# -*- coding: utf-8 -*-
import hashlib
from Crypto.Cipher import AES as CipherAES
from Crypto import Random
from Crypto.Random import random
from Crypto.PublicKey import ElGamal as CryptoElGamal
from Crypto.PublicKey import RSA as CryptoRSA
from Crypto.Math._IntegerGMP import IntegerGMP
from Crypto.Util.number import GCD
from Crypto.Util.asn1 import DerSequence
import ecdsa
from tinyec import registry
from tinyec.ec import Point


registry.EC_CURVE_REGISTRY['secp256k1'] = {
    "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    "a": 0x0000000000000000000000000000000000000000000000000000000000000000,
    "b": 0x0000000000000000000000000000000000000000000000000000000000000007,
    "g": (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
          0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    "h": 0x1,
}


def sha256(data):
    m = hashlib.sha256()
    m.update(data)
    return m.digest()


class B58:
    __b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    def pack(self, data):
        base58 = ''
        int_data = int.from_bytes(data, byteorder='big', signed=False)
        while int_data > 0:
            base58 = B58.__b58chars[int_data % len(B58.__b58chars)] + base58
            int_data = int_data // len(B58.__b58chars)
        for i in range(len(data)):
            if data[i: i+1] == b'\x00': base58 = '1' + base58
            else: break
        return base58

    def unpack(self, base58):
        int_data = 0
        for i in range(-1, -len(base58) - 1, -1):
            int_data += B58.__b58chars.index(base58[i]) * len(B58.__b58chars) ** (-i - 1)
        data = int_data.to_bytes((int_data.bit_length() + 7) // 8, byteorder='big', signed=False)
        for i in range(len(base58)):
            if base58[i] == '1': data = b'\x00' + data
            else: break
        return data


class AES:
    bs = 16
    key_size = 32

    def __init__(self, key=b''):
        if key == b'':
            self.gen_key()
        else:
            self.set_key(key)

    def gen_key(self):
        self.key = Random.get_random_bytes(AES.key_size)

    def get_key(self):
        return self.key

    def set_key(self, key):
        self.key = key

    def encode(self, message):
        cipher = CipherAES.new(self.key, CipherAES.MODE_EAX)
        ciphertext = cipher.encrypt(message)
        return cipher.nonce + ciphertext

    def decode(self, secret):
        nonce, ciphertext = secret[:self.bs], secret[self.bs:]
        cipher = CipherAES.new(self.key, CipherAES.MODE_EAX, nonce)
        return cipher.decrypt(ciphertext) 


class ECDSA:
    def __init__(self, priv_key=b'', pub_key=b''):
        self.sk = priv_key
        self.vk = pub_key
        if priv_key == b'' and pub_key == b'':
            self.gen_priv_key()
            self.gen_pub_key()
        elif priv_key != b'':
            self.set_priv_key(priv_key)
            self.gen_pub_key()
        elif self.vk != b'':
            self.set_pub_key(pub_key)

    def get_priv_key(self):
        return self.priv_key.to_string()

    def get_pub_key(self):
        return self.pub_key.to_string()

    def set_priv_key(self, priv_key):
        self.priv_key = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)

    def set_pub_key(self, pub_key):
        self.pub_key = ecdsa.VerifyingKey.from_string(pub_key, curve=ecdsa.SECP256k1)

    def gen_priv_key(self):
        self.priv_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

    def gen_pub_key(self):
        self.pub_key = self.priv_key.get_verifying_key()

    def sign(self, message):
        return self.priv_key.sign(message, hashfunc=hashlib.sha256)

    def check_signature(self, message, signature):
        try:
            self.pub_key.verify(signature, message, hashfunc=hashlib.sha256)
            return True
        except ecdsa.keys.BadSignatureError:
            return False


class ELGAMAL:
    def __init__(self, priv_key=b'', pub_key=b'', key_size=2048):
        self.set_key_size(key_size)
        if priv_key != b'':
            self.set_priv_key(priv_key)
            return
        if pub_key != b'':
            self.set_pub_key(pub_key)
            return
        self.gen_key()

    def set_key_size(self, key_size):
        self.key_size = key_size

    def get_priv_key(self):
        return self.get_pub_key() + \
            self.key.x.to_bytes(self.key_size//8)

    def get_pub_key(self):
        return self.key.p.to_bytes(self.key_size//8) + \
            self.key.g.to_bytes(self.key_size//8) + \
            self.key.y.to_bytes(self.key_size//8)

    def set_pub_key(self, key):
        self.set_key_size(len(key)//3*8)
        self.set_key(key)

    def set_priv_key(self, key):
        self.set_key_size(len(key)//4*8)
        self.set_key(key)

    def set_key(self, key):
        key_data = []
        for part in range(8*len(key)//self.key_size):
            key_part = key[self.key_size//8 * part: self.key_size//8 * (part + 1)]
            key_part_int = IntegerGMP.from_bytes(key_part)
            key_data.append(key_part_int)
        self.key = CryptoElGamal.construct(key_data)

    def gen_key(self):
        self.key = CryptoElGamal.generate(self.key_size, Random.new().read)

    def encrypt(self, message):
        if len(message) > self.key_size//8:
            raise Exception('Error: message length {} more then {}'.format(len(message), self.key_size//8))
        message_int = int.from_bytes(message, byteorder='big', signed=False)
        while 1:
            k = random.StrongRandom().randint(1, int(self.key.p)-1)
            if GCD(k, int(self.key.p)-1) == 1: break
        a, b = self.key._encrypt(message_int, k)
        return a.to_bytes(self.key_size//8, byteorder='big', signed=False) + \
               b.to_bytes(self.key_size//8, byteorder='big', signed=False)

    def decrypt(self, secret):
        secret_data = []
        for part in range(2):
            secret_part = secret[self.key_size//8 * part: self.key_size//8 * (part + 1)]
            secret_part_int = int.from_bytes(secret_part, byteorder='big', signed=False)
            secret_data.append(secret_part_int)
        message_int = self.key._decrypt(tuple(secret_data))
        return message_int.to_bytes((message_int.bit_length()+7)//8, byteorder='big', signed=False)


class RSA:
    def __init__(self, priv_key=b'', pub_key=b'', key_size=2048):
        self.key_size = key_size
        if priv_key != b'':
            self.set_priv_key(priv_key)
            return
        if pub_key != b'':
            self.set_pub_key(pub_key)
            return
        self.gen_key()

    def gen_key(self):
        self.key = CryptoRSA.generate(self.key_size)

    def get_priv_key(self):
        return self.key.export_key(format='DER')

    def get_pub_key(self):
        return CryptoRSA._create_subject_public_key_info(
                CryptoRSA.oid,
                DerSequence([
                    self.key.n,
                    self.key.e]))

    def set_pub_key(self, key):
        self.key = CryptoRSA.import_key(key)

    def set_priv_key(self, key):
        self.key = CryptoRSA.import_key(key)

    def encrypt(self, message):
        message_int = int.from_bytes(message, byteorder='big', signed=False)
        secret_int = self.key._encrypt(message_int)
        return secret_int.to_bytes((secret_int.bit_length()+7)//8, byteorder='big', signed=False)

    def decrypt(self, secret):
        secret_int = int.from_bytes(secret, byteorder='big', signed=False)
        message_int = self.key._decrypt(secret_int)
        return message_int.to_bytes()


class ECDH:
    curve = registry.get_curve('secp256k1')
    key_size = 256//8

    def __init__(self, priv_key=b''):
        if priv_key != b'':
            self.set_priv_key(priv_key)
        else:
            self.gen_key()
        self.__gen_pub_key()

    def gen_key(self):
        self.priv_key = random.StrongRandom().randint(0, self.curve.field.n)

    def get_priv_key(self):
        return self.priv_key.to_bytes(self.key_size, byteorder='big', signed=False)

    def get_pub_key(self):
        hex_x = self.pub_key.x.to_bytes(self.key_size, byteorder='big', signed=False)
        hex_y = self.pub_key.y.to_bytes(self.key_size, byteorder='big', signed=False)
        return hex_x + hex_y

    def get_shared_key(self, neighbor_pub_key):
        self.__set_neighbor_pub_key(neighbor_pub_key)
        self.__calc_shared_key()
        return self.__pack_shared_key()

    def __pack_shared_key(self):
        shared_key_int = self.shared_key.x ^ self.shared_key.y
        return shared_key_int.to_bytes(self.key_size, byteorder='big', signed=False)

    def __calc_shared_key(self):
        self.shared_key = self.priv_key * self.neighbor_pub_key

    def __set_neighbor_pub_key(self, neighbor_pub_key):
        hex_x = neighbor_pub_key[: self.key_size]
        hex_y = neighbor_pub_key[self.key_size: ]
        x = int.from_bytes(hex_x, byteorder='big', signed=False)
        y = int.from_bytes(hex_y, byteorder='big', signed=False)
        self.neighbor_pub_key = Point(self.curve, x, y)

    def __gen_pub_key(self):
        self.pub_key = self.priv_key * self.curve.g

    def set_priv_key(self, key):
        self.priv_key = int.from_bytes(key, byteorder='big', signed=False)
