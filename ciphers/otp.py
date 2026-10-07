import secrets

from .utils import ALPHABET, _to_num, _to_chr, clean_alpha, clean_alnum, shift_digit


def otp_generate_key(length):
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


def otp_encrypt(text, key):
    text = clean_alnum(text)
    key = clean_alpha(key)

    if len(key) < len(text):
        raise ValueError("key OTP lebih pendek dari plaintext")

    return "".join(
        _to_chr(_to_num(ch) + _to_num(key[i])) if ch.isalpha() else shift_digit(ch, _to_num(key[i]))
        for i, ch in enumerate(text)
    )


def otp_decrypt(ciphertext, key):
    ciphertext = clean_alnum(ciphertext)
    key = clean_alpha(key)

    if len(key) < len(ciphertext):
        raise ValueError("key OTP lebih pendek dari ciphertext")

    return "".join(
        _to_chr(_to_num(ch) - _to_num(key[i])) if ch.isalpha() else shift_digit(ch, -_to_num(key[i]))
        for i, ch in enumerate(ciphertext)
    )
