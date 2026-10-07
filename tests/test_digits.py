import pytest

from ciphers import (
    affine_decrypt,
    affine_encrypt,
    hill_decrypt,
    hill_encrypt,
    otp_decrypt,
    otp_encrypt,
    permutation_decrypt,
    permutation_encrypt,
    shift_decrypt,
    shift_encrypt,
    substitution_decrypt,
    substitution_encrypt,
    vigenere_decrypt,
    vigenere_encrypt,
)


@pytest.mark.parametrize(
    ("encrypt", "decrypt", "key"),
    [
        (shift_encrypt, shift_decrypt, 3),
        (substitution_encrypt, substitution_decrypt, "QWERTYUIOPASDFGHJKLZXCVBNM"),
        (lambda text, key: affine_encrypt(text, *key), lambda text, key: affine_decrypt(text, *key), (5, 1)),
        (vigenere_encrypt, vigenere_decrypt, "CIPHER"),
        (lambda text, key: hill_encrypt(text, key), lambda text, key: hill_decrypt(text, key), [[3, 3], [2, 5]]),
        (permutation_encrypt, permutation_decrypt, [3, 1, 2]),
        (otp_encrypt, otp_decrypt, "CIPHERKEYCIPHERKEYCIPHERKEY"),
    ],
)
def test_text_ciphers_encrypt_and_decrypt_digits(encrypt, decrypt, key):
    plaintext = "AYO MALING AYAM 3 PAGI"

    ciphertext = encrypt(plaintext, key)

    assert any(char.isdigit() for char in ciphertext)
    assert decrypt(ciphertext, key) == "AYOMALINGAYAM3PAGI"
