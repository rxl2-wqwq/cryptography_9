from .utils import _to_num, _to_chr, clean_alpha, clean_alnum, shift_digit


def vigenere_encrypt(text, key):
    key = clean_alpha(key)
    if not key:
        raise ValueError("key tidak boleh kosong")

    text = clean_alnum(text)
    return "".join(
        _to_chr(_to_num(ch) + _to_num(key[i % len(key)]))
        if ch.isalpha()
        else shift_digit(ch, _to_num(key[i % len(key)]))
        for i, ch in enumerate(text)
    )


def vigenere_decrypt(text, key):
    key = clean_alpha(key)
    if not key:
        raise ValueError("key tidak boleh kosong")

    text = clean_alnum(text)
    return "".join(
        _to_chr(_to_num(ch) - _to_num(key[i % len(key)]))
        if ch.isalpha()
        else shift_digit(ch, -_to_num(key[i % len(key)]))
        for i, ch in enumerate(text)
    )
