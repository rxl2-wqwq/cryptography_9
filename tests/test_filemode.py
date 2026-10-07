import pytest

from filemode import decrypt_file, encrypt_file


@pytest.mark.parametrize(
    ("cipher", "key"),
    [
        ("shift", "29"),
        ("substitution", "QWERTYUIOPASDFGHJKLZXCVBNM"),
        ("affine", "7,10"),
        ("vigenere", "binary-key"),
        ("hill", "[[3,3],[2,5]]"),
        ("permutation", "3,1,2"),
        ("otp", bytes(range(256)) * 2),
    ],
)
def test_binary_file_round_trip(cipher, key):
    original = bytes(range(256)) + b"\x00\xffdatabase\x00image-data"

    encrypted = encrypt_file(original, cipher, key, "contoh.database.sql")
    decrypted, filename = decrypt_file(encrypted, cipher, key)

    assert decrypted == original
    assert filename == "contoh.database.sql"
