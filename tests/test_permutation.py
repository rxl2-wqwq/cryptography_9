from ciphers import permutation_encrypt, permutation_decrypt


def test_columnar_example():
    plaintext = "sistem dan teknologi informasi itb"
    key = [1, 2, 3, 4, 5, 6]

    ciphertext = permutation_encrypt(plaintext, key)

    assert ciphertext == "SDNIAIAONSSNLFITTOOIEEGRTMKIMB"
    assert permutation_decrypt(ciphertext, key) == "SISTEMDANTEKNOLOGIINFORMASIITB"


def test_uneven_length_roundtrip():
    plaintext = "contohteks"
    key = [3, 1, 2]

    ciphertext = permutation_encrypt(plaintext, key)

    assert permutation_decrypt(ciphertext, key) == "CONTOHTEKS"
