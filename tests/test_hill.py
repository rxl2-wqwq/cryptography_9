from ciphers import hill_encrypt, hill_decrypt


def test_hill_cipher():
    key = [
        [17, 17, 5],
        [21, 18, 21],
        [2, 2, 19],
    ]

    ciphertext = hill_encrypt("paymoremoney", key)

    assert ciphertext == "LNSHDLEWMTRW"
    assert hill_decrypt(ciphertext, key) == "PAYMOREMONEY"
