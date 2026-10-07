from ast import literal_eval

from flask import Flask, render_template, request

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
from ciphers.utils import group5

app = Flask(__name__)


def parse_affine_key(key):
    try:
        return tuple(map(int, key.split(",")))
    except ValueError as exc:
        raise ValueError("Kunci Affine harus seperti: 7,10") from exc


def parse_permutation_key(key):
    try:
        return [int(value.strip()) for value in key.split(",")]
    except ValueError as exc:
        raise ValueError("Kunci Permutation harus seperti: 3,1,2") from exc


def parse_hill_key(key):
    try:
        matrix = literal_eval(key)
    except (SyntaxError, ValueError) as exc:
        raise ValueError(
            "Kunci Hill harus seperti: [[17,17,5],[21,18,21],[2,2,19]]"
        ) from exc

    if not isinstance(matrix, list):
        raise ValueError("Kunci Hill harus berupa matriks")
    return matrix


def process_text(cipher, mode, text, key):
    if not text:
        raise ValueError("Masukkan teks")

    operations = {
        "shift": (
            lambda: shift_encrypt(text, int(key)),
            lambda: shift_decrypt(text, int(key)),
            "Shift Cipher",
        ),
        "substitution": (
            lambda: substitution_encrypt(text, key),
            lambda: substitution_decrypt(text, key),
            "Substitution Cipher",
        ),
        "affine": (
            lambda: affine_encrypt(text, *parse_affine_key(key)),
            lambda: affine_decrypt(text, *parse_affine_key(key)),
            "Affine Cipher",
        ),
        "vigenere": (
            lambda: vigenere_encrypt(text, key),
            lambda: vigenere_decrypt(text, key),
            "Vigenère Cipher",
        ),
        "hill": (
            lambda: hill_encrypt(text, parse_hill_key(key)),
            lambda: hill_decrypt(text, parse_hill_key(key)),
            "Hill Cipher",
        ),
        "permutation": (
            lambda: permutation_encrypt(text, parse_permutation_key(key)),
            lambda: permutation_decrypt(text, parse_permutation_key(key)),
            "Permutation Cipher",
        ),
        "otp": (
            lambda: otp_encrypt(text, key),
            lambda: otp_decrypt(text, key),
            "One-Time Pad",
        ),
    }

    try:
        encrypt, decrypt, name = operations[cipher]
    except KeyError as exc:
        raise ValueError("Algoritma tidak dikenali") from exc

    return (encrypt if mode == "encrypt" else decrypt)(), name


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    cipher_name = None

    if request.method == "POST":
        try:
            if request.form.get("input_mode", "text") == "file":
                raise ValueError("Mode file belum tersedia")

            result, cipher_name = process_text(
                request.form.get("cipher", "shift"),
                request.form.get("mode", "encrypt"),
                request.form.get("text", ""),
                request.form.get("key", ""),
            )

            if request.form.get("output_format") == "group5":
                result = group5(result)
        except (TypeError, ValueError) as exc:
            error = str(exc)

    return render_template(
        "index.html",
        result=result,
        error=error,
        cipher_name=cipher_name,
    )


if __name__ == "__main__":
    app.run(debug=True)
