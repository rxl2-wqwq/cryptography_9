import math
from .utils import _to_num, _to_chr, clean_alnum


def _digit_multiplier(m):
    """Use m where it is invertible mod 10; otherwise fall back to 1."""
    return m % 10 if math.gcd(m, 10) == 1 else 1


def affine_encrypt(text, m, b):
    if math.gcd(m, 26) != 1:
        raise ValueError("m harus coprime 26")
    digit_m = _digit_multiplier(m)
    return "".join(
        _to_chr(m * _to_num(c) + b) if c.isalpha() else str((digit_m * int(c) + b) % 10)
        for c in clean_alnum(text)
    )


def affine_decrypt(text, m, b):
    inv = pow(m, -1, 26)
    digit_inverse = pow(_digit_multiplier(m), -1, 10)
    return "".join(
        _to_chr(inv * (_to_num(c) - b)) if c.isalpha() else str(digit_inverse * (int(c) - b) % 10)
        for c in clean_alnum(text)
    )
