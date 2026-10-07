import math
from .utils import _to_num, _to_chr, clean_alpha


def affine_encrypt(text, m, b):
    if math.gcd(m, 26) != 1:
        raise ValueError("m harus coprime 26")
    return "".join(_to_chr(m * _to_num(c) + b) for c in clean_alpha(text))


def affine_decrypt(text, m, b):
    inv = pow(m, -1, 26)
    return "".join(_to_chr(inv * (_to_num(c) - b)) for c in clean_alpha(text))
