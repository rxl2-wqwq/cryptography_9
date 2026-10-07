from .utils import ALPHABET, clean_alpha


def substitution_encrypt(text, key):
    key = key.upper()
    assert len(key) == 26 and set(key) == set(ALPHABET), "key 26 huruf unik"
    tbl = str.maketrans(ALPHABET, key)
    return clean_alpha(text).translate(tbl)


def substitution_decrypt(text, key):
    key = key.upper()
    tbl = str.maketrans(key, ALPHABET)
    return clean_alpha(text).translate(tbl)
