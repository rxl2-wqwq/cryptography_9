from math import gcd
from sympy import Matrix
from collections.abc import Sequence
from .utils import _to_num, _to_chr, clean_alpha


def _inverse_key(key):
    matrix = Matrix(key)

    if matrix.rows != matrix.cols or matrix.rows == 0:
        raise ValueError("key harus matriks persegi")

    if gcd(int(matrix.det()), 26) != 1:
        raise ValueError("determinan key harus relatif prima dengan 26")

    return matrix.inv_mod(26)


def hill_encrypt(text, key):
    text = clean_alpha(text)
    size = len(key)

    if not size:
        raise ValueError("key tidak boleh kosong")

    text += "X" * (-len(text) % size)
    result = []

    for start in range(0, len(text), size):
        block = Matrix([_to_num(ch) for ch in text[start : start + size]])
        encrypted = Matrix(key) * block
        result.extend(_to_chr(int(value) % 26) for value in encrypted)

    return "".join(result)


def hill_decrypt(text, key):
    text = clean_alpha(text)
    size = len(key)

    if not size or len(text) % size:
        raise ValueError("panjang ciphertext harus kelipatan ukuran key")

    inverse = _inverse_key(key)
    result = []

    for start in range(0, len(text), size):
        block = Matrix([_to_num(ch) for ch in text[start : start + size]])
        decrypted = inverse * block
        result.extend(_to_chr(int(value) % 26) for value in decrypted)

    return "".join(result).rstrip("X")
