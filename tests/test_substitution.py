from ciphers import substitution_encrypt, substitution_decrypt


def test_substitution_encrypt_decrypt():
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    ciphertext = substitution_encrypt("kripto", key)

    assert ciphertext == "AKOHZG"
    assert substitution_decrypt(ciphertext, key) == "KRIPTO"
