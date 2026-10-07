from .utils import _to_num, _to_chr, clean_alpha


def vigenere_encrypt(text, key):
    key = clean_alpha(key)
    if not key:
        raise ValueError("key tidak boleh kosong")

    text = clean_alpha(text)
    return "".join(
        _to_chr(_to_num(ch) + _to_num(key[i % len(key)])) for i, ch in enumerate(text)
    )


def vigenere_decrypt(text, key):
    key = clean_alpha(key)
    if not key:
        raise ValueError("key tidak boleh kosong")

    text = clean_alpha(text)
    return "".join(
        _to_chr(_to_num(ch) - _to_num(key[i % len(key)])) for i, ch in enumerate(text)
    )
