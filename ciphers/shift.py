from .utils import _to_num, _to_chr, clean_alpha


def shift_encrypt(text, k):
    hasil = ""
    for ch in clean_alpha(text):
        hasil += _to_chr(_to_num(ch) + k)
    return hasil


def shift_decrypt(text, k):
    return shift_encrypt(text, -k)
