from .utils import ALPHABET, DIGITS, clean_alnum


def _validate_key(key):
    normalized = key.upper()
    if len(normalized) != 26 or set(normalized) != set(ALPHABET):
        raise ValueError("Kunci Substitution harus berisi tepat 26 huruf unik A-Z")
    return normalized


def _digit_table(key):
    """Derive a reversible digit substitution from the 26-letter key."""
    ordered_digits = "".join(
        digit for _, digit in sorted((key[index], str(index)) for index in range(10))
    )
    return str.maketrans(DIGITS, ordered_digits), str.maketrans(ordered_digits, DIGITS)


def substitution_encrypt(text, key):
    key = _validate_key(key)
    letters = str.maketrans(ALPHABET, key)
    digits, _ = _digit_table(key)
    return clean_alnum(text).translate(letters).translate(digits)


def substitution_decrypt(text, key):
    key = _validate_key(key)
    letters = str.maketrans(key, ALPHABET)
    _, digits = _digit_table(key)
    return clean_alnum(text).translate(letters).translate(digits)
