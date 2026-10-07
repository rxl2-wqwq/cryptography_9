from .utils import clean_alpha


def _validate_key(key):
    key = tuple(key)
    if not key or set(key) != set(range(1, len(key) + 1)):
        raise ValueError("key harus urutan angka 1 sampai panjang key, tanpa duplikat")
    return key


def permutation_encrypt(text, key):
    key = _validate_key(key)
    text = clean_alpha(text)
    width = len(key)

    # Tiap irisan adalah satu kolom pada susunan baris-per-baris.
    return "".join(text[col - 1 :: width] for col in key)


def permutation_decrypt(ciphertext, key):
    key = _validate_key(key)
    ciphertext = clean_alpha(ciphertext)
    width = len(key)

    # Kolom awal bisa satu huruf lebih panjang jika baris terakhir tidak penuh.
    full_rows, extra = divmod(len(ciphertext), width)
    lengths = [full_rows + (col < extra) for col in range(width)]

    columns = [""] * width
    pos = 0
    for col in key:
        length = lengths[col - 1]
        columns[col - 1] = ciphertext[pos : pos + length]
        pos += length

    return "".join(
        columns[col][row]
        for row in range(full_rows + (extra > 0))
        for col in range(width)
        if row < lengths[col]
    )
