from ciphers import shift_encrypt, shift_decrypt


def test_shift_encrypt_decrypt():
    ciphertext = shift_encrypt("awasi asterix dan temannya obelix", 3)

    assert ciphertext == "DZDVL" + "DVWHULA" + "GDQ" + "WHPDQQBD" + "REHOLA"
    assert shift_decrypt(ciphertext, 3) == "AWASIASTERIXDANTEMANNYAOBELIX"
