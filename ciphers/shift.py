from .utils import _to_num, _to_chr, clean_alnum, shift_digit


def shift_encrypt(text, k):
    hasil = ""
    for ch in clean_alnum(text):
        hasil += _to_chr(_to_num(ch) + k) if ch.isalpha() else shift_digit(ch, k)
    return hasil


def shift_decrypt(text, k):
    return shift_encrypt(text, -k)
