from ciphers import substitution_encrypt, substitution_decrypt
import pytest


def test_substitution_encrypt_decrypt():
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    ciphertext = substitution_encrypt("kripto", key)

    assert ciphertext == "AKOHZG"
    assert substitution_decrypt(ciphertext, key) == "KRIPTO"


@pytest.mark.parametrize("invalid_key", ["ABC", "A" * 26])
def test_substitution_rejects_invalid_key_for_both_operations(invalid_key):
    with pytest.raises(ValueError, match="26 huruf unik"):
        substitution_encrypt("KRIPTO", invalid_key)

    with pytest.raises(ValueError, match="26 huruf unik"):
        substitution_decrypt("AKOHZG", invalid_key)
