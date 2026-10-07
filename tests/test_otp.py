from ciphers import otp_encrypt, otp_decrypt, otp_generate_key


def test_otp_roundtrip():
    text = "HELLO"
    key = "XMCKL"
    ciphertext = otp_encrypt(text, key)

    assert otp_decrypt(ciphertext, key) == text


def test_generated_key_length():
    assert len(otp_generate_key(100)) == 100
