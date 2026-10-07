from ciphers import vigenere_encrypt, vigenere_decrypt


def test_encrypt_decrypt():
    plaintext = "thiscryptosystemisnotsecure"
    key = "CIPHER"
    ciphertext = vigenere_encrypt(plaintext, key)

    assert ciphertext == "VPXZGIAXIVWPUBTTMJPWIZITWZT"
    assert vigenere_decrypt(ciphertext, key) == "THISCRYPTOSYSTEMISNOTSECURE"
