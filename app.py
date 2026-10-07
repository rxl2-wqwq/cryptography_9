"""Web interface for the Cryptography 9 cipher exercises."""

from __future__ import annotations

from flask import Flask, render_template, request

from ciphers import shift_decrypt, shift_encrypt, vigenere_decrypt, vigenere_encrypt
from ciphers.utils import ALPHABET, clean_alpha


app = Flask(__name__)


def atbash(text: str) -> str:
    """Encrypt or decrypt text with Atbash (both operations are identical)."""
    return clean_alpha(text).translate(str.maketrans(ALPHABET, ALPHABET[::-1]))


def rail_fence_encrypt(text: str, rails: int) -> str:
    text = clean_alpha(text)
    rows = ["" for _ in range(rails)]
    row, direction = 0, 1

    for char in text:
        rows[row] += char
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction

    return "".join(rows)


def rail_fence_decrypt(ciphertext: str, rails: int) -> str:
    ciphertext = clean_alpha(ciphertext)
    if not ciphertext:
        return ""

    pattern: list[int] = []
    row, direction = 0, 1
    for _ in ciphertext:
        pattern.append(row)
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction

    counts = [pattern.count(rail) for rail in range(rails)]
    rows: list[list[str]] = []
    cursor = 0
    for count in counts:
        rows.append(list(ciphertext[cursor : cursor + count]))
        cursor += count

    return "".join(rows[rail].pop(0) for rail in pattern)


def get_input_text() -> str:
    """Return the submitted text, preferring an uploaded UTF-8 text file."""
    uploaded = request.files.get("file")
    if uploaded and uploaded.filename:
        try:
            return uploaded.read().decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("file harus berupa teks UTF-8") from exc
    return request.form.get("text", "")


def process_cipher(cipher: str, mode: str, text: str, key: str) -> tuple[str, str]:
    """Run the cipher selected by the form and return result plus display name."""
    if not clean_alpha(text):
        raise ValueError("masukkan teks yang berisi huruf A-Z")

    encrypting = mode == "encrypt"

    if cipher == "caesar":
        try:
            shift = int(key)
        except ValueError as exc:
            raise ValueError("kunci Caesar harus berupa angka") from exc
        operation = shift_encrypt if encrypting else shift_decrypt
        return operation(text, shift), "Caesar"

    if cipher == "vigenere":
        operation = vigenere_encrypt if encrypting else vigenere_decrypt
        return operation(text, key), "Vigenère"

    if cipher == "atbash":
        return atbash(text), "Atbash"

    if cipher == "railfence":
        try:
            rails = int(key)
        except ValueError as exc:
            raise ValueError("kunci Rail Fence harus berupa angka") from exc
        if rails < 2:
            raise ValueError("kunci Rail Fence minimal 2")
        operation = rail_fence_encrypt if encrypting else rail_fence_decrypt
        return operation(text, rails), "Rail Fence"

    raise ValueError("algoritma tidak dikenali")


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    cipher_name = None

    if request.method == "POST":
        try:
            text = get_input_text()
            result, cipher_name = process_cipher(
                request.form.get("cipher", "caesar"),
                request.form.get("mode", "encrypt"),
                text,
                request.form.get("key", ""),
            )
        except ValueError as exc:
            error = str(exc)

    return render_template(
        "index.html", result=result, error=error, cipher_name=cipher_name
    )


if __name__ == "__main__":
    app.run(debug=True)
