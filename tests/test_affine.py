import pytest

from ciphers import affine_encrypt, affine_decrypt


def test_affine_encrypt_decrypt():
    ciphertext = affine_encrypt("kripto", 7, 10)

    assert ciphertext == "CZOLNE"
    assert affine_decrypt(ciphertext, 7, 10) == "KRIPTO"


def test_affine_rejects_invalid_multiplier():
    with pytest.raises(ValueError):
        affine_encrypt("kripto", 2, 10)
