from email.encoders import encode_base64
from auth_manager import AuthManager
from encryption_manager import EncryptionManager
from master_password_manager import MasterPasswordManager
from storage_manager import StorageManager
from evaluation_password import EvaluationPassword
from password_generator import PasswordGenerator
from report_manager import ReportManager
from session_manager import SessionManager
from config_manager import ConfigManager
from main import MainMenu
import numpy as np
from email.header import Header, decode_header
import struct
import quopri
import brotli
import zstandard as zstd
import lz4.frame
import bz2
import lzma
import heapq
import secrets
import os
import json
import csv
import gzip
import zlib
import base64
import binascii
import codecs
import random
import string
import hashlib
import hmac
import logging
import datetime
import smtplib
import time
import requests
from collections import defaultdict, Counter
import uu
import io
import sys
import base64

from colorama import init, Fore, Style
init(autoreset=True)

# Correction des imports Crypto (remplacer Cryptography par Crypto)
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

from passlib.context import CryptContext
import snappy


import hashlib
import base64
import hmac
from typing import Optional, Union, Any

try:
    import blake3  # pip install blake3
except ImportError:
    blake3 = None

try:
    import bcrypt  # pip install bcrypt
except ImportError:
    bcrypt = None

try:
    from argon2 import PasswordHasher  # pip install argon2-cffi
    ph = PasswordHasher()
except ImportError:
    ph = None



base91_alphabet = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '!', '#', '$',
	'%', '&', '(', ')', '*', '+', ',', '.', '/', ':', ';', '<', '=',
	'>', '?', '@', '[', ']', '^', '_', '`', '{', '|', '}', '~', '"']

decode_table = dict((v,k) for k,v in enumerate(base91_alphabet))
PY2 = sys.version_info[0] == 2
kShortened = 0b111  # last two-byte char encodes <= 7 bits
kIllegals = [chr(0), chr(10), chr(13), chr(34), chr(38), chr(92)]
kIllegalsSet = {chr(0), chr(10), chr(13), chr(34), chr(38), chr(92)}


class HashUtility:
    """
    Classe utilitaire pour hachage sécurisé, intégrité des données et dérivation de clés.

    Algorithmes supportés :
      - SHA-2 : sha224, sha256, sha384, sha512, sha512_224, sha512_256
      - SHA-3 : sha3_224, sha3_256, sha3_384, sha3_512, shake_128, shake_256
      - BLAKE2 : blake2b, blake2s
      - BLAKE3 : via bibliothèque externe
      - KDFs : Argon2, bcrypt, PBKDF2
      - HMAC : vérification de l'intégrité avec clé secrète
    """

    @staticmethod
    def hash_string(
        data: Union[str, bytes],
        algorithm: str = "sha256",
        salt: Optional[Union[str, bytes]] = None,
        encoding: str = "hex",
        **kwargs: Any
    ) -> str:
        data_bytes = data.encode('utf-8') if isinstance(data, str) else data

        if salt is not None:
            salt_bytes = salt.encode('utf-8') if isinstance(salt, str) else salt
            data_bytes = salt_bytes + data_bytes

        alg = algorithm.lower().replace('-', '_')

        if alg == 'blake3':
            if blake3 is None:
                raise ValueError("BLAKE3 non installé. `pip install blake3`.")
            hasher = blake3.blake3()
            hasher.update(data_bytes)
            raw = hasher.digest()
        elif alg in ('shake_128', 'shake_256'):
            output_len = kwargs.get('output_length', 32)
            hasher = getattr(hashlib, alg)()
            hasher.update(data_bytes)
            raw = hasher.digest(output_len)
        elif alg in ('blake2b', 'blake2s'):
            digest_size = kwargs.get('digest_size')
            hasher = getattr(hashlib, alg)(digest_size=digest_size) if digest_size else getattr(hashlib, alg)()
            hasher.update(data_bytes)
            raw = hasher.digest()
        else:
            try:
                hasher = hashlib.new(alg)
            except (ValueError, TypeError):
                raise ValueError(f"Algorithme non supporté: {algorithm}")
            hasher.update(data_bytes)
            raw = hasher.digest()

        if encoding == 'hex':
            return raw.hex()
        elif encoding == 'base64':
            return base64.b64encode(raw).decode('ascii')
        else:
            raise ValueError("Encodage inconnu. Utiliser 'hex' ou 'base64'.")

    @staticmethod
    def hash_file(
        file_path: str,
        algorithm: str = "sha256",
        salt: Optional[Union[str, bytes]] = None,
        encoding: str = "hex",
        text_mode: bool = False,
        file_encoding: str = "utf-8",
        **kwargs: Any
    ) -> str:
        alg = algorithm.lower().replace('-', '_')

        if alg == 'blake3':
            if blake3 is None:
                raise ValueError("BLAKE3 non installé. `pip install blake3`.")
            hasher = blake3.blake3()
        elif alg in ('shake_128', 'shake_256'):
            hasher = getattr(hashlib, alg)()
        elif alg in ('blake2b', 'blake2s'):
            digest_size = kwargs.get('digest_size')
            hasher = getattr(hashlib, alg)(digest_size=digest_size) if digest_size else getattr(hashlib, alg)()
        else:
            try:
                hasher = hashlib.new(alg)
            except (ValueError, TypeError):
                raise ValueError(f"Algorithme non supporté: {algorithm}")

        if salt is not None:
            salt_bytes = salt.encode('utf-8') if isinstance(salt, str) else salt
            hasher.update(salt_bytes)

        mode = 'r' if text_mode else 'rb'
        with open(file_path, mode, encoding=file_encoding if text_mode else None) as f:
            for chunk in iter(lambda: f.read(8192), '' if text_mode else b''):
                chunk_bytes = chunk.encode(file_encoding) if text_mode else chunk
                hasher.update(chunk_bytes)

        raw = hasher.digest(kwargs.get('output_length', 32)) if alg in ('shake_128', 'shake_256') else hasher.digest()

        if encoding == 'hex':
            return raw.hex()
        elif encoding == 'base64':
            return base64.b64encode(raw).decode('ascii')
        else:
            raise ValueError("Encodage inconnu. Utiliser 'hex' ou 'base64'.")

    @staticmethod
    def compare_hashes(hash1: str, hash2: str, encoding: str = "hex") -> bool:
        try:
            if encoding == 'hex':
                b1 = bytes.fromhex(hash1)
                b2 = bytes.fromhex(hash2)
            elif encoding == 'base64':
                b1 = base64.b64decode(hash1)
                b2 = base64.b64decode(hash2)
            else:
                return False
        except Exception:
            return False

        return hmac.compare_digest(b1, b2)

    @staticmethod
    def hmac_hash(data: Union[str, bytes], key: Union[str, bytes], algorithm: str = "sha256") -> str:
        key_bytes = key.encode() if isinstance(key, str) else key
        data_bytes = data.encode() if isinstance(data, str) else data
        try:
            digestmod = getattr(hashlib, algorithm)
        except AttributeError:
            raise ValueError(f"Algorithme HMAC non supporté: {algorithm}")
        return hmac.new(key_bytes, data_bytes, digestmod).hexdigest()

    @staticmethod
    def hash_password_bcrypt(password: str) -> str:
        if bcrypt is None:
            raise ImportError("bcrypt non installé. `pip install bcrypt`.")
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    @staticmethod
    def verify_password_bcrypt(password: str, hashed: str) -> bool:
        if bcrypt is None:
            raise ImportError("bcrypt non installé.")
        return bcrypt.checkpw(password.encode(), hashed.encode())

    @staticmethod
    def hash_password_argon2(password: str) -> str:
        if ph is None:
            raise ImportError("argon2-cffi non installé. `pip install argon2-cffi`.")
        return ph.hash(password)

    @staticmethod
    def verify_password_argon2(password: str, hashed: str) -> bool:
        if ph is None:
            raise ImportError("argon2-cffi non installé.")
        try:
            ph.verify(hashed, password)
            return True
        except Exception:
            return False


def base91_decode(encoded_str):
    ''' Decode Base91 string to a bytearray '''
    v = -1
    b = 0
    n = 0
    out = bytearray()
    for strletter in encoded_str:
        if not strletter in decode_table:
            continue
        c = decode_table[strletter]
        if(v < 0):
            v = c
        else:
            v += c*91
            b |= v << n
            n += 13 if (v & 8191)>88 else 14
            while True:
                out += struct.pack('B', b&255)
                b >>= 8
                n -= 8
                if not n>7:
                    break
            v = -1
    if v+1:
        out += struct.pack('B', (b | v << n) & 255 )
    return out

def base91_encode(bindata):
    ''' Encode a bytearray to a Base91 string '''
    b = 0
    n = 0
    out = ''
    for count in range(len(bindata)):
        byte = bindata[count:count+1]
        b |= struct.unpack('B', byte)[0] << n
        n += 8
        if n>13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            out += base91_alphabet[v % 91] + base91_alphabet[v // 91]
    if n:
        out += base91_alphabet[b % 91]
        if n>7 or b>90:
            out += base91_alphabet[b // 91]
    return out

def base122_encode(rawData, warnings=True):
    if PY2 and warnings:
        raise NotImplementedError(
            "This hasn't been tested on Python2 yet! Turn this warning off by passing warnings=False."
        )
    if isinstance(rawData, str):
        rawData = bytearray(rawData, "UTF-8")
    else:
        raise TypeError("rawData must be a string!")
    # null, newline, carriage return, double quote, ampersand, backslash
    curIndex = curBit = 0
    outData = bytearray()

    def get7(rawDataLen):
        nonlocal curIndex, curBit, rawData
        if curIndex >= rawDataLen:
            return False, 0
        firstPart = (
            (((0b11111110 % 0x100000000) >> curBit) & rawData[curIndex]) << curBit
        ) >> 1
        curBit += 7
        if curBit < 8:
            return True, firstPart
        curBit -= 8
        curIndex += 1
        if curIndex >= rawDataLen:
            return True, firstPart
        secondPart = (
            (((0xFF00 % 0x100000000) >> curBit) & rawData[curIndex]) & 0xFF
        ) >> (8 - curBit)
        return True, firstPart | secondPart

    # for loops don't work because they cut off a variable amount of end letters for some reason, but they'd speed it up immensely
    while True:
        retBits, bits = get7(len(rawData))
        if not retBits:
            break
        if bits in kIllegalsSet:
            illegalIndex = kIllegals.index(bits)
        else:
            outData.append(bits)
            continue
        retNext, nextBits = get7(len(rawData))
        b1 = 0b11000010
        b2 = 0b10000000
        if not retNext:
            b1 |= (0b111 & kShortened) << 2
            nextBits = bits
        else:
            b1 |= (0b111 & illegalIndex) << 2
        firstBit = 1 if (nextBits & 0b01000000) > 0 else 0
        b1 |= firstBit
        b2 |= nextBits & 0b00111111
        outData += [b1, b2]
    return outData


def base122_decode(strData, warnings=True):
    if PY2 and warnings:
        raise NotImplementedError(
            "This hasn't been tested on Python2 yet! Turn this warning off by passing warnings=False."
        )
    # null, newline, carriage return, double quote, ampersand, backslash
    decoded = []
    curByte = bitOfByte = 0

    # this could test for every letter in the for loop, but I took it out for performance
    if not isinstance(strData[0], int):
        raise TypeError("You can only decode an encoded string!")

    def push7(byte):
        nonlocal curByte, bitOfByte, decoded
        byte <<= 1
        curByte |= (byte % 0x100000000) >> bitOfByte
        bitOfByte += 7
        if bitOfByte >= 8:
            decoded += [curByte]
            bitOfByte -= 8
            curByte = (byte << (7 - bitOfByte)) & 255
        return

    for i in range(len(strData)):
        if strData[i] > 127:
            illegalIndex = ((strData[i] % 0x100000000) >> 8) & 7
            if illegalIndex != kShortened:
                push7(kIllegals[illegalIndex])
            push7(strData[i] & 127)
        else:
            push7(strData[i])
    return bytearray(decoded).decode("utf-8")


def ascii85_encode(data: str) -> str:
    return base64.a85encode(data.encode()).decode()


def ascii85_decode(data: str) -> str:
    return base64.a85decode(data).decode()


def base45_encode(data: str) -> str:
    b45_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
    b = data.encode('utf-8')
    result = ""
    i = 0

    while i < len(b):
        if i+1 < len(b):
            x = (b[i] << 8) + b[i+1]
            result += b45_chars[x % 45] + b45_chars[(x // 45) % 45] + b45_chars[x // (45*45)]
            i += 2

        else:
            x = b[i]
            result += b45_chars[x % 45] + b45_chars[x // 45]
            i += 1
    return result


def base45_decode(data: str) -> str:
    b45_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
    result = bytearray()
    i = 0

    while i < len(data):

        if i+2 < len(data):
            x = b45_chars.index(data[i]) + b45_chars.index(data[i+1]) * \
                45 + b45_chars.index(data[i+2]) * 45 * 45
            result.append(x >> 8)
            result.append(x & 0xFF)
            i += 3

        else:
            x = b45_chars.index(data[i]) + b45_chars.index(data[i+1]) * 45
            result.append(x)
            i += 2
    return result.decode('utf-8', errors='replace')


def base58_encode(data: str) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    b = data.encode('utf-8')
    num = int.from_bytes(b, 'big')
    result = ""

    while num > 0:
        num, rem = divmod(num, 58)
        result = alphabet[rem] + result
    n_pad = len(b) - len(b.lstrip(b'\0'))
    return alphabet[0] * n_pad + result


def base58_decode(data: str) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = 0

    for char in data:
        num = num * 58 + alphabet.index(char)
    b = num.to_bytes((num.bit_length() + 7) // 8, 'big')
    n_pad = len(data) - len(data.lstrip(alphabet[0]))
    return (b'\0' * n_pad + b).decode('utf-8', errors='replace')


def base62_encode(data: str) -> str:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    b = data.encode('utf-8')
    num = int.from_bytes(b, 'big')
    result = ""

    while num:
        num, rem = divmod(num, 62)
        result = alphabet[rem] + result
    n_pad = len(b) - len(b.lstrip(b'\0'))
    return alphabet[0] * n_pad + result


def base62_decode(data: str) -> str:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    num = 0

    for char in data:
        num = num * 62 + alphabet.index(char)
    b = num.to_bytes((num.bit_length() + 7) // 8, 'big')
    n_pad = len(data) - len(data.lstrip(alphabet[0]))
    return (b'\0' * n_pad + b).decode('utf-8', errors='replace')


def base65536_encode(data: str) -> str:
    b = data.encode('utf-8')
    result = ""

    for i in range(0, len(b), 2):

        if i+1 < len(b):
            val = b[i] << 8 | b[i+1]

        else:
            val = b[i]
        result += chr(val)
    return result


def base65536_decode(data: str) -> str:
    b = bytearray()

    for c in data:
        val = ord(c)

        if val > 255:
            b.append(val >> 8)
            b.append(val & 0xFF)

        else:
            b.append(val)
    return bytes(b).decode('utf-8', errors='replace')


# Encodages Cryptographiques
def rot5_encode(data: str) -> str:
    result = ''

    for c in data:

        if c.isdigit():
            result += chr((ord(c) - ord('0') + 5) % 10 + ord('0'))

        else:
            result += c
    return result


def rot5_decode(data: str) -> str:
    return rot5_encode(data)


def rot18_encode(data: str) -> str:
    result = ''

    for c in data:

        if c.isalpha():
            result += codecs.encode(c, 'rot_13')

        elif c.isdigit():
            result += rot5_encode(c)

        else:
            result += c
    return result


def rot18_decode(data: str) -> str:
    return rot18_encode(data)


def rot47_encode(data: str) -> str:
    result = ''

    for c in data:

        if 33 <= ord(c) <= 126:
            result += chr(33 + ((ord(c) - 33 + 47) % 94))

        else:
            result += c
    return result


def rot47_decode(data: str) -> str:
    return rot47_encode(data)


def vigenere_encode(data: str, key: str = "KEY") -> str:
    key = key.upper()
    result = ""

    for i, c in enumerate(data):

        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            shift = ord(key[i % len(key)]) - ord('A')
            result += chr((ord(c) - base + shift) % 26 + base)

        else:
            result += c
    return result


def vigenere_decode(data: str, key: str = "KEY") -> str:
    key = key.upper()
    result = ""

    for i, c in enumerate(data):

        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            shift = ord(key[i % len(key)]) - ord('A')
            result += chr((ord(c) - base - shift) % 26 + base)

        else:
            result += c
    return result


def atbash_encode(data: str) -> str:
    result = ""

    for c in data:

        if c.isalpha():

            if c.isupper():
                result += chr(90 - (ord(c) - 65))

            else:
                result += chr(122 - (ord(c) - 97))

        else:
            result += c
    return result


def atbash_decode(data: str) -> str:
    return atbash_decode(data)


def modinv(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("Aucun inverse modulaire trouvé.")


def affine_encode(data: str, a: int = 5, b: int = 8) -> str:
    result = ""

    for c in data:

        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result += chr(((a * (ord(c) - base) + b) % 26) + base)

        else:
            result += c
    return result


def affine_decode(data: str, a: int = 5, b: int = 8) -> str:
    result = ""
    inv_a = modinv(a, 26)

    for c in data:

        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result += chr((inv_a * ((ord(c) - base) - b)) % 26 + base)

        else:
            result += c
    return result


def rail_fence_encode(data: str, num_rails: int = 3) -> str:

    if num_rails <= 1:
        return data
    rails = [''] * num_rails
    rail = 0
    direction = 1

    for c in data:
        rails[rail] += c
        rail += direction

        if rail == 0 or rail == num_rails - 1:
            direction *= -1
    return ''.join(rails)


def rail_fence_decode(data: str, num_rails: int = 3) -> str:

    if num_rails <= 1:
        return data
    pattern = list(range(num_rails)) + list(range(num_rails - 2, 0, -1))
    rail_len = [0] * num_rails

    for i in range(len(data)):
        rail_len[pattern[i % len(pattern)]] += 1
    rails = []
    index = 0

    for r in rail_len:
        rails.append(data[index:index+r])
        index += r
    result = []
    rail_indices = [0] * num_rails

    for i in range(len(data)):
        rail = pattern[i % len(pattern)]
        result.append(rails[rail][rail_indices[rail]])
        rail_indices[rail] += 1
    return ''.join(result)


def bifid_encode(data: str, key: str = "ABCDEFGHIKLMNOPQRSTUVWXYZ") -> str:
    data = data.upper().replace("J", "I")
    square = [key[i*5:(i+1)*5] for i in range(5)]
    pos = {square[i][j]: (i+1, j+1) for i in range(5) for j in range(5)}
    rows, cols = [], []

    for c in data:

        if c in pos:
            r, c_val = pos[c]
            rows.append(str(r))
            cols.append(str(c_val))
    merged = ''.join(rows + cols)
    result = ""

    for i in range(0, len(merged), 2):
        r = int(merged[i]) - 1
        c_val = int(merged[i+1]) - 1
        result += square[r][c_val]
    return result


def bifid_decode(data: str, key: str = "ABCDEFGHIKLMNOPQRSTUVWXYZ") -> str:
    data = data.upper().replace("J", "I")
    square = [key[i*5:(i+1)*5] for i in range(5)]
    pos = {square[i][j]: (i+1, j+1) for i in range(5) for j in range(5)}
    nums = []

    for c in data:

        if c in pos:
            r, c_val = pos[c]
            nums.append(str(r))
            nums.append(str(c_val))
    half = len(nums) // 2
    result = ""

    for i in range(half):
        r = int(nums[i]) - 1
        c_val = int(nums[i+half]) - 1
        result += square[r][c_val]
    return result


def generate_playfair_square(key: str) -> list:
    key = "".join(dict.fromkeys(key.upper().replace("J", "I")))
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    square = list(key)

    for c in alphabet:

        if c not in square:
            square.append(c)
    return [square[i*5:(i+1)*5] for i in range(5)]


def playfair_encode(data: str, key: str = "PLAYFAIREXAMPLE") -> str:
    square = generate_playfair_square(key)

    def pos(letter):

        for i, row in enumerate(square):

            if letter in row:
                return i, row.index(letter)
    data = data.upper().replace("J", "I")
    digrams = []
    i = 0

    while i < len(data):
        a = data[i]
        b = data[i+1] if i+1 < len(data) else 'X'

        if a == b:
            digrams.append(a + 'X')
            i += 1

        else:
            digrams.append(a + b)
            i += 2
    result = ""

    for d in digrams:
        r1, c1 = pos(d[0])
        r2, c2 = pos(d[1])

        if r1 == r2:
            result += square[r1][(c1+1) % 5] + square[r2][(c2+1) % 5]

        elif c1 == c2:
            result += square[(r1+1) % 5][c1] + square[(r2+1) % 5][c2]

        else:
            result += square[r1][c2] + square[r2][c1]
    return result


def playfair_decode(data: str, key: str = "PLAYFAIREXAMPLE") -> str:
    square = generate_playfair_square(key)

    def pos(letter):

        for i, row in enumerate(square):

            if letter in row:
                return i, row.index(letter)
    digrams = [data[i:i+2] for i in range(0, len(data), 2)]
    result = ""

    for d in digrams:
        r1, c1 = pos(d[0])
        r2, c2 = pos(d[1])

        if r1 == r2:
            result += square[r1][(c1-1) % 5] + square[r2][(c2-1) % 5]

        elif c1 == c2:
            result += square[(r1-1) % 5][c1] + square[(r2-1) % 5][c2]

        else:
            result += square[r1][c2] + square[r2][c1]
    return result


def hill_encode(data: str, key_matrix: list = [[3, 3], [2, 5]]) -> str:
    data = data.upper().replace(" ", "")

    if len(data) % 2 != 0:
        data += "X"
    result = ""

    for i in range(0, len(data), 2):
        pair = [ord(data[i]) - 65, ord(data[i+1]) - 65]
        encoded = np.dot(key_matrix, pair) % 26
        result += chr(int(encoded[0]) + 65) + chr(int(encoded[1]) + 65)
    return result


def hill_decode(data: str, key_matrix: list = [[3, 3], [2, 5]]) -> str:
    data = data.upper().replace(" ", "")
    det = (key_matrix[0][0]*key_matrix[1][1] - key_matrix[0][1]*key_matrix[1][0]) % 26
    inv_det = modinv(det, 26)
    inv_matrix = [[key_matrix[1][1]*inv_det % 26, (-key_matrix[0][1]*inv_det) % 26],
                  [(-key_matrix[1][0]*inv_det) % 26, key_matrix[0][0]*inv_det % 26]]
    result = ""

    for i in range(0, len(data), 2):
        pair = [ord(data[i]) - 65, ord(data[i+1]) - 65]
        decoded = np.dot(inv_matrix, pair) % 26
        result += chr(int(decoded[0]) + 65) + chr(int(decoded[1]) + 65)
    return result


# Encodages Binaires/Compression
def base128_encode(data: str) -> str:
    b = data.encode('utf-8')
    num = int.from_bytes(b, 'big')
    alphabet = ''.join(chr(i) for i in range(128))
    result = ""

    while num:
        num, rem = divmod(num, 128)
        result = alphabet[rem] + result
    n_pad = len(b) - len(b.lstrip(b'\0'))
    return alphabet[0] * n_pad + result


def base128_decode(data: str) -> str:
    alphabet = ''.join(chr(i) for i in range(128))
    num = 0
    for char in data:
        num = num * 128 + alphabet.index(char)
    b = num.to_bytes((num.bit_length() + 7) // 8, 'big')
    n_pad = len(data) - len(data.lstrip(alphabet[0]))
    return (b'\0' * n_pad + b).decode('utf-8', errors='replace')


def base256_encode(data: str) -> str:
    # Représentation littérale en Base256 (affichage hexadécimal)
    return data.encode('utf-8').hex()


def base256_decode(data: str) -> str:
    return bytes.fromhex(data).decode('utf-8', errors='replace')


def lzma_encode(data: str) -> str:
    return lzma.compress(data.encode()).hex()


def lzma_decode(data: str) -> str:
    return lzma.decompress(bytes.fromhex(data)).decode()


def bzip2_encode(data: str) -> str:
    return bz2.compress(data.encode()).hex()


def bzip2_decode(data: str) -> str:
    return bz2.decompress(bytes.fromhex(data)).decode()


def snappy_encode(data: str) -> str:
    return snappy.compress(data.encode()).hex()


def snappy_decode(data: str) -> str:
    return snappy.decompress(bytes.fromhex(data)).decode()


def lz4_encode(data: str) -> str:
    return lz4.frame.compress(data.encode()).hex()


def lz4_decode(data: str) -> str:
    return lz4.frame.decompress(bytes.fromhex(data)).decode()


def zstandard_encode(data: str) -> str:
    cctx = zstd.ZstdCompressor()
    return cctx.compress(data.encode()).hex()


def zstandard_decode(data: str) -> str:
    dctx = zstd.ZstdDecompressor()
    return dctx.decompress(bytes.fromhex(data)).decode()


def brotli_encode(data: str) -> str:
    return brotli.compress(data.encode()).hex()


def brotli_decode(data: str) -> str:
    return brotli.decompress(bytes.fromhex(data)).decode()


def arithmetic_encode(data: str) -> str:
    freq = Counter(data)
    total = sum(freq.values())
    probabilities = {}
    low = {}
    cumulative = 0.0

    for char in sorted(freq):
        probabilities[char] = freq[char] / total
        low[char] = cumulative
        cumulative += probabilities[char]
    high = {char: low[char] + probabilities[char] for char in freq}
    low_val = 0.0
    high_val = 1.0

    for char in data:
        range_val = high_val - low_val
        high_val = low_val + range_val * high[char]
        low_val = low_val + range_val * low[char]
    code = (low_val + high_val) / 2
    model = {"probabilities": probabilities, "low": low, "high": high, "length": len(data)}
    return json.dumps({"code": code, "model": model})


def arithmetic_decode(encoded: str) -> str:
    obj = json.loads(encoded)
    code = obj["code"]
    model = obj["model"]
    probabilities = model["probabilities"]
    low = model["low"]
    high = model["high"]
    length = model["length"]
    result = ""

    for _ in range(length):

        for char in sorted(probabilities):

            if low[char] <= code < high[char]:
                result += char
                range_val = high[char] - low[char]
                code = (code - low[char]) / range_val
                break
    return result


# def huffman_adaptive_encode(data: str) -> str:
    # Utilisation de la méthode Huffman statique déjà définie
#    return EncryptionManager().huffman_encode(data)


# def huffman_adaptive_decode(data: str) -> str:
#    return EncryptionManager().huffman_decode(data)


# Encodages Spécialisés
def uuencode_encode(data: str) -> str:
    inp = io.StringIO(data)
    out = io.StringIO()
    uu.encode(inp, out, "dummy", mode=644)
    return out.getvalue()


def uuencode_decode(data: str) -> str:
    inp = io.StringIO(data)
    out = io.StringIO()
    uu.decode(inp, out)
    return out.getvalue()


def xxencode_encode(data: str) -> str:
    # Utilisation de base64 comme alternative pour XXencode
    return base64.b64encode(data.encode()).decode()


def xxencode_decode(data: str) -> str:
    return base64.b64decode(data).decode()


def binhex_encode(data: str) -> str:
    return data.encode('utf-8').hex()


def binhex_decode(data: str) -> str:
    return bytes.fromhex(data).decode('utf-8', errors='replace')


def quoted_printable_encode(data: str) -> str:
    return quopri.encodestring(data.encode()).decode()


def quoted_printable_decode(data: str) -> str:
    return quopri.decodestring(data.encode()).decode()


def utf7_encode(data: str) -> str:
    return data.encode('utf-7').decode('utf-7')


def utf7_decode(data: str) -> str:
    return data.encode('utf-7').decode('utf-7')


def utf16_encode(data: str) -> str:
    return data.encode('utf-16').hex()


def utf16_decode(data: str) -> str:
    return bytes.fromhex(data).decode('utf-16', errors='replace')


def utf32_encode(data: str) -> str:
    return data.encode('utf-32').hex()


def utf32_decode(data: str) -> str:
    return bytes.fromhex(data).decode('utf-32', errors='replace')


def escape_sequence_encode(data: str) -> str:
    return data.encode('unicode_escape').decode('ascii')


def escape_sequence_decode(data: str) -> str:
    return bytes(data, "utf-8").decode("unicode_escape")


def mime_header_encode(data: str) -> str:
    return str(Header(data, 'utf-8'))


def mime_header_decode(data: str) -> str:
    decoded, charset = decode_header(data)[0]
    return decoded.decode(charset) if charset else decoded


# Encodages obscurs/historiques
def base32hex_encode(data: str) -> str:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
    b = data.encode('utf-8')
    num = int.from_bytes(b, 'big')
    result = ""

    while num:
        num, rem = divmod(num, 32)
        result = alphabet[rem] + result
    return result if result else alphabet[0]


def base32hex_decode(data: str) -> str:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
    num = 0

    for char in data:
        num = num * 32 + alphabet.index(char)
    b = num.to_bytes((num.bit_length() + 7) // 8, 'big')
    return b.decode('utf-8', errors='replace')


def base36_encode(data: str) -> str:
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    b = data.encode('utf-8')
    num = int.from_bytes(b, 'big')
    result = ""

    while num:
        num, rem = divmod(num, 36)
        result = alphabet[rem] + result
    return result if result else alphabet[0]


def base36_decode(data: str) -> str:
    num = int(data, 36)
    b = num.to_bytes((num.bit_length() + 7) // 8, 'big')
    return b.decode('utf-8', errors='replace')


def base64url_encode(data: str) -> str:
    encoded = base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")
    return encoded


def base64url_decode(data: str) -> str:
    padding = 4 - (len(data) % 4)
    data += "=" * padding
    return base64.urlsafe_b64decode(data).decode()


def base92_encode(data: str) -> str:
    b = data.encode('utf-8')
    num = int.from_bytes(b, 'big')
    alphabet = ''.join(chr(i) for i in range(33, 33+92))
    result = ""

    while num:
        num, rem = divmod(num, 92)
        result = alphabet[rem] + result
    n_pad = len(b) - len(b.lstrip(b'\0'))
    return alphabet[0] * n_pad + result


def base92_decode(data: str) -> str:
    alphabet = ''.join(chr(i) for i in range(33, 33+92))
    num = 0

    for c in data:
        num = num * 92 + alphabet.index(c)
    b = num.to_bytes((num.bit_length() + 7) // 8, 'big')
    n_pad = len(data) - len(data.lstrip(alphabet[0]))
    return (b'\0' * n_pad + b).decode('utf-8', errors='replace')


def a1z26_encode(data: str) -> str:
    return ' '.join(str(ord(c.lower()) - 96) for c in data if c.isalpha())


def a1z26_decode(data: str) -> str:
    return ''.join(chr(int(num) + 96) for num in data.split() if num.isdigit())


def tap_code_encode(data: str) -> str:
    data = data.upper().replace(" ", "")
    square = [
        ['A', 'B', 'C', 'D', 'E'],
        ['F', 'G', 'H', 'I', 'J'],
        ['L', 'M', 'N', 'O', 'P'],
        ['Q', 'R', 'S', 'T', 'U'],
        ['V', 'W', 'X', 'Y', 'Z']
    ]
    mapping = {square[i][j]: (i+1, j+1) for i in range(5) for j in range(5)}
    result = []

    for c in data:

        if c == 'K':
            c = 'C'

        if c in mapping:
            result.append(f"{mapping[c][0]},{mapping[c][1]}")
    return ' '.join(result)


def tap_code_decode(data: str) -> str:
    square = [
        ['A', 'B', 'C', 'D', 'E'],
        ['F', 'G', 'H', 'I', 'J'],
        ['L', 'M', 'N', 'O', 'P'],
        ['Q', 'R', 'S', 'T', 'U'],
        ['V', 'W', 'X', 'Y', 'Z']
    ]
    result = ""

    for pair in data.split():
        i, j = map(int, pair.split(','))
        result += square[i-1][j-1]
    return result


def pigpen_cipher_encode(data: str) -> str:
    # Une implémentation simple utilisant une substitution symbolique
    mapping = {c: f"[{c}]" for c in data}
    return ''.join(mapping.get(c, c) for c in data)


def pigpen_cipher_decode(data: str) -> str:
    import re
    return re.sub(r'\[([^\]]+)\]', r'\1', data)


def braille_encode(data: str) -> str:
    return ''.join(chr(0x2800 + (ord(c) % 256)) for c in data)


def braille_decode(data: str) -> str:
    return ''.join(chr((ord(c) - 0x2800) % 256) for c in data)


def semaphore_encode(data: str) -> str:
    return ' '.join(f"<{c}>" for c in data)


def semaphore_decode(data: str) -> str:
    return data.replace("<", "").replace(">", "")


def dna_encode(data: str) -> str:
    mapping = {'0': 'A', '1': 'T', '2': 'C', '3': 'G'}
    result = ""

    for c in data:

        for digit in format(ord(c), '03d'):
            result += mapping[digit]
    return result


def dna_decode(data: str) -> str:
    rev_mapping = {'A': '0', 'T': '1', 'C': '2', 'G': '3'}
    digits = "".join(rev_mapping[c] for c in data)
    result = ""

    for i in range(0, len(digits), 3):
        result += chr(int(digits[i:i+3]))
    return result


# ----------------- Mise à jour des dictionnaires dans EncryptionManager -----------------
class EncryptionManager():
    

    def __init__(self):
        self.conf = ConfigManager()        
        self.passgen = PasswordGenerator()
        self.session = SessionManager()
        self.report = ReportManager()
        self.eval = EvaluationPassword()
        self.storage = StorageManager()
        self.enc = EncryptionManager()
        self.auth = AuthManager()
        self.main = MainMenu()
        self.master_password = None
        self.password_history = []
        self.secure_directory = self.storage.load_secure_directory()
        self.derived_master_key = None
        self.pwd_context = CryptContext(schemes=["bcrypt", "argon2", "pbkdf2_sha256"], deprecated="auto")
        self.master_manager = MasterPasswordManager(self.conf.secure_directory)
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            filename=os.path.join(os.path.dirname(os.path.abspath(__file__)), "password_manager.log"),
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
            )
        
    def generic_encode(self, data: str, encoding: str) -> str:

        funcs = {
            "base64": lambda d: base64.b64encode(d.encode()).decode(),
            "hex": lambda d: binascii.hexlify(d.encode()).decode(),
            "utf-8": lambda d: d,
            "ascii": lambda d: d.encode('ascii').decode('ascii'),
            "url": lambda d: __import__('urllib.parse').quote(d),
            "base32": lambda d: base64.b32encode(d.encode()).decode(),
            "base16": lambda d: base64.b16encode(d.encode()).decode(),
            "rot13": lambda d: codecs.encode(d, 'rot_13'),
            "base85": lambda d: base64.b85encode(d.encode()).decode(),
            "zlib": lambda d: binascii.hexlify(zlib.compress(d.encode())).decode(),
            "gzip": lambda d: binascii.hexlify(gzip.compress(d.encode())).decode(),
            "brotli": lambda d: brotli.compress(d.encode()).hex(),
            "punycode": lambda d: d.encode('punycode').decode('ascii'),
            "z85": lambda d: base64.a85encode(d.encode()).decode(),
            #"rle": self.rle_encode,
            #"delta": self.delta_encode,
            #"huffman": self.huffman_encode,
            "base91": base91_encode,
            "base122": base122_encode,
            "ascii85": ascii85_encode,
            "base45": base45_encode,
            "base58": base58_encode,
            "base62": base62_encode,
            "base65536": base65536_encode,
#           "ebcdic": ebcdic_encode,
#           "morse": morse_encode,
#           "baudot": baudot_encode,
            "rot5": rot5_encode,
            "rot18": rot18_encode,
            "rot47": rot47_encode,
            "vigenere": lambda d: vigenere_encode(d, key="KEY"),
            "atbash": atbash_encode,
            "affine": affine_encode,
            "rail_fence": lambda d: rail_fence_encode(d, num_rails=3),
            "bifid": lambda d: bifid_encode(d, key="ABCDEFGHIKLMNOPQRSTUVWXYZ"),
            "playfair": lambda d: playfair_encode(d, key="PLAYFAIREXAMPLE"),
            "hill": lambda d: hill_encode(d, key_matrix=[[3, 3], [2, 5]]),
            "base128": base128_encode,
            "base256": base256_encode,
            "lzma": lzma_encode,
            "bzip2": bzip2_encode,
            "snappy": snappy_encode,
            "lz4": lz4_encode,
            "zstandard": zstandard_encode,
            "arithmetic": arithmetic_encode,
#           "huffman_adaptive": huffman_adaptive_encode,
            "uuencode": uuencode_encode,
            "xxencode": xxencode_encode,
            "binhex": binhex_encode,
            "quoted_printable": quoted_printable_encode,
            "utf7": utf7_encode,
            "utf16": utf16_encode,
            "utf32": utf32_encode,
            "escape": escape_sequence_encode,
            "mime_header": mime_header_encode,
            "base32hex": base32hex_encode,
            "base36": base36_encode,
            "base64url": base64url_encode,
            "base92": base92_encode,
            "a1z26": a1z26_encode,
            "tap_code": tap_code_encode,
            "pigpen": pigpen_cipher_encode,
            "braille": braille_encode,
            "semaphore": semaphore_encode,
            "dna": dna_encode
        }

        data = str(input('Entrez la chaine de caractères à encoder: '))
        dict_encodages = {}

        for i, name in zip(range(len(funcs)), funcs.keys()):
            dict_encodages[i] = name

        print('Voici la liste des encodeurs disponibles: ')

        for i, name in zip(range(len(funcs)), funcs.keys()):
            print(f"/n{i} - {name}")
        choice = input(
            "Choisissez un encodeur parmi les options suivantes (écrivez le nombre correspondant):")
        encoding = dict_encodages[choice]

        try:
            return funcs[encoding](data)

        except KeyError:
            raise ValueError("Type d'encodage non supporté.")

        except Exception as e:
            return f"Erreur lors de l'encodage : {e}"

    def generic_decode(self, data: str, decoding: str) -> str:
        funcs = {
            "base64": lambda d: base64.b64decode(d).decode(),
            "hex": lambda d: binascii.unhexlify(d).decode(),
            "utf-8": lambda d: d,
            "ascii": lambda d: d,
            "url": lambda d: __import__('urllib.parse').unquote(d),
            "base32": lambda d: base64.b32decode(d).decode(),
            "base16": lambda d: base64.b16decode(d).decode(),
            "rot13": lambda d: codecs.decode(d, 'rot_13'),
            "base85": lambda d: base64.b85decode(d).decode(),
            "zlib": lambda d: zlib.decompress(binascii.unhexlify(d)).decode(),
            "gzip": lambda d: gzip.decompress(binascii.unhexlify(d)).decode(),
            "brotli": lambda d: brotli.decompress(bytes.fromhex(d)).decode(),
            "punycode": lambda d: d.encode('ascii').decode('punycode'),
            "z85": lambda d: base64.a85decode(d).decode(),
#           "rle": self.rle_decode,
#           "delta": self.delta_decode,
#           "huffman": self.huffman_decode,
            "base91": base91_decode,
            "base122": base122_decode,
            "ascii85": ascii85_decode,
            "base45": base45_decode,
            "base58": base58_decode,
            "base62": base62_decode,
            "base65536": base65536_decode,
#           "ebcdic": ebcdic_decode,
#           "morse": morse_decode,
#           "baudot": baudot_decode,
            "rot5": rot5_decode,
            "rot18": rot18_decode,
            "rot47": rot47_decode,
            "vigenere": lambda d: vigenere_decode(d, key="KEY"),
            "atbash": atbash_decode,
            "affine": affine_decode,
            "rail_fence": lambda d: rail_fence_decode(d, num_rails=3),
            "bifid": lambda d: bifid_decode(d, key="ABCDEFGHIKLMNOPQRSTUVWXYZ"),
            "playfair": lambda d: playfair_decode(d, key="PLAYFAIREXAMPLE"),
            "hill": lambda d: hill_decode(d, key_matrix=[[3, 3], [2, 5]]),
            "base128": base128_decode,
            "base256": base256_decode,
            "lzma": lzma_decode,
            "bzip2": bzip2_decode,
            "snappy": snappy_decode,
            "lz4": lz4_decode,
            "zstandard": zstandard_decode,
            "arithmetic": arithmetic_decode,
#           "huffman_adaptive": huffman_adaptive_decode,
            "uuencode": uuencode_decode,
            "xxencode": xxencode_decode,
            "binhex": binhex_decode,
            "quoted_printable": quoted_printable_decode,
            "utf7": utf7_decode,
            "utf16": utf16_decode,
            "utf32": utf32_decode,
            "escape": escape_sequence_decode,
            "mime_header": mime_header_decode,
            "base32hex": base32hex_decode,
            "base36": base36_decode,
            "base64url": base64url_decode,
            "base92": base92_decode,
            "a1z26": a1z26_decode,
            "tap_code": tap_code_decode,
            "pigpen": pigpen_cipher_decode,
            "braille": braille_decode,
            "semaphore": semaphore_decode,
            "dna": dna_decode
        }
        data = str(input('Entrez la chaine de caractères à décoder: '))
        dict_decodings = {}

        for i, name in zip(range(len(funcs)), funcs.keys()):
            dict_decodings[i] = name

        print('Voici la liste des décodeurs disponibles: ')

        for i, name in zip(range(len(funcs)), funcs.keys()):
            print(f"/n{i} - {name}")
        choice = input(
            "Choisissez un décodeur parmi les options suivantes (écrivez le nombre correspondant):")
        decoding = dict_decodings[choice]

        try:
            return funcs[decoding](data)

        except KeyError:
            raise ValueError("Type de décodage non supporté.")

        except Exception as e:
            return f"Erreur lors du décodage : {e}"



    def hash_password(self, password):
        """
        Hache un mot de passe en utilisant passlib pour le stockage sécurisé.

        Parameters:
        password (str): Mot de passe en clair.

        Returns:
        str: Mot de passe haché.
        """
        return self.pwd_context.hash(password)

    
    def encode_with_hmac(self, data, key):
        """
        Encode une chaîne de caractères avec HMAC et une clé secrète.

        Parameters:
        data (str): La chaîne de caractères à encoder.
        key (str): La clé secrète.

        Returns:
        str: La chaîne encodée avec HMAC.
        """
        encoded_hmac = hmac.new(key.encode('utf-8'), data.encode('utf-8'), hashlib.sha256).hexdigest()
        return encoded_hmac



    def encrypt_password(self, password, key):
        """
        Chiffre un mot de passe en utilisant AES-GCM avec une clé donnée.

        Parameters:
        password (str): Mot de passe en clair.
        key (bytes): Clé AES (16, 24 ou 32 octets).

        Returns:
        tuple: Mot de passe chiffré, nonce et tag d'authentification.

        Raises:
        Exception: Si une erreur survient lors du chiffrement.
        """
        try:
            cipher = AES.new(key, AES.MODE_GCM)
            encrypted_password, tag = cipher.encrypt_and_digest(password.encode('utf-8'))
            return encrypted_password, cipher.nonce, tag
        except Exception as e:
            print(f"Erreur lors du chiffrement : {e}")
            raise

    def derive_key_from_master_password(self, master_password, salt, key_length=16):
        """
        Génère une clé AES à partir d'un mot de passe maître en utilisant PBKDF2.
        Si master_password est None, demande via MasterPasswordManager.
        """
        if master_password is None:
            master_password = self.master_manager.verify_master_password()
            if not master_password:
                raise ValueError("Authentification échouée pour la dérivation de clé.")
        return PBKDF2(master_password, salt, dkLen=key_length, count=100000, hmac_hash_module=SHA256)


    def decrypt_password(self, encrypted_password, key, nonce, tag):
        """
        Déchiffre un mot de passe AES-GCM.

        Parameters:
        encrypted_password (bytes): Mot de passe chiffré.
        key (bytes): Clé AES utilisée pour le chiffrement.
        nonce (bytes): Nonce utilisé pour le chiffrement.
        tag (bytes): Tag d'authentification.

        Returns:
        str: Mot de passe déchiffré.

        Raises:
        ValueError: Si l'authentification échoue ou si les données sont corrompues.
        Exception: Pour toute autre erreur lors du déchiffrement.
        """
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decrypted_password = cipher.decrypt_and_verify(encrypted_password, tag)
            return decrypted_password.decode('utf-8')
        except ValueError:
            print("Échec de l'authentification ou des données corrompues.")
            raise
        except Exception as e:
            print(f"Erreur lors du déchiffrement : {e}")
            raise
