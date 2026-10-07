"""Byte-oriented file encryption for the seven classical ciphers.

The metadata header is prepended to the original bytes and encrypted together
with them.  Therefore an encrypted file does not expose its original name,
extension, or file signature before it is decrypted.
"""

from __future__ import annotations

from ast import literal_eval
from hashlib import sha256
from math import gcd
from pathlib import PurePath, PureWindowsPath
from struct import Struct
from typing import Sequence

from sympy import Matrix


MAGIC = b"CFGF"
VERSION = 1
HEADER = Struct(">4sBBHQ")
MAX_FILENAME_BYTES = 1024

CIPHER_IDS = {
    "shift": 1,
    "substitution": 2,
    "affine": 3,
    "vigenere": 4,
    "hill": 5,
    "permutation": 6,
    "otp": 7,
}


class FileModeError(ValueError):
    """Raised when a binary-file cipher request is invalid."""


def _cipher_id(cipher: str) -> int:
    try:
        return CIPHER_IDS[cipher]
    except KeyError as exc:
        raise FileModeError("Cipher file tidak dikenali") from exc


def _key_bytes(key: str | bytes | bytearray) -> bytes:
    if isinstance(key, str):
        value = key.encode("utf-8")
    elif isinstance(key, (bytes, bytearray)):
        value = bytes(key)
    else:
        raise FileModeError("Kunci file harus berupa teks atau bytes")
    if not value:
        raise FileModeError("Kunci tidak boleh kosong")
    return value


def _parse_affine_key(key: str | Sequence[int]) -> tuple[int, int]:
    if isinstance(key, str):
        try:
            values = tuple(int(part.strip()) for part in key.split(","))
        except ValueError as exc:
            raise FileModeError("Kunci Affine harus seperti: 7,10") from exc
    else:
        values = tuple(key)
    if len(values) != 2:
        raise FileModeError("Kunci Affine harus berisi m,b")
    m, b = values
    if gcd(m, 256) != 1:
        raise FileModeError("Untuk file, m Affine harus relatif prima dengan 256")
    return m % 256, b % 256


def _parse_permutation_key(key: str | Sequence[int]) -> tuple[int, ...]:
    if isinstance(key, str):
        try:
            values = tuple(int(part.strip()) for part in key.split(","))
        except ValueError as exc:
            raise FileModeError("Kunci Permutation harus seperti: 3,1,2") from exc
    else:
        values = tuple(key)
    if not values or set(values) != set(range(1, len(values) + 1)):
        raise FileModeError("Kunci Permutation harus urutan angka tanpa duplikat")
    return values


def _parse_hill_key(key: str | Sequence[Sequence[int]]) -> list[list[int]]:
    if isinstance(key, str):
        try:
            key = literal_eval(key)
        except (SyntaxError, ValueError) as exc:
            raise FileModeError("Kunci Hill harus berupa matriks, contoh [[3,3],[2,5]]") from exc
    try:
        matrix = Matrix(key)
    except (TypeError, ValueError) as exc:
        raise FileModeError("Kunci Hill harus berupa matriks angka") from exc
    if matrix.rows == 0 or matrix.rows != matrix.cols:
        raise FileModeError("Kunci Hill harus matriks persegi")
    determinant = int(matrix.det())
    if gcd(determinant, 256) != 1:
        raise FileModeError("Determinan Hill untuk file harus relatif prima dengan 256")
    return [[int(matrix[row, col]) % 256 for col in range(matrix.cols)] for row in range(matrix.rows)]


def _hill_inverse(matrix_values: list[list[int]]) -> list[list[int]]:
    matrix = Matrix(matrix_values)
    inverse = matrix.adjugate() * pow(int(matrix.det()), -1, 256)
    return [[int(inverse[row, col]) % 256 for col in range(matrix.cols)] for row in range(matrix.rows)]


def _substitution_table(key: str | bytes | bytearray) -> tuple[bytes, bytes]:
    if not isinstance(key, str):
        raise FileModeError("Kunci Substitution file harus 26 huruf unik")
    normalized = key.upper()
    if len(normalized) != 26 or set(normalized) != set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        raise FileModeError("Kunci Substitution harus 26 huruf unik")
    order = sorted(range(256), key=lambda value: sha256(normalized.encode() + bytes([value])).digest())
    encrypt = bytes(order)
    decrypt = bytearray(256)
    for source, target in enumerate(encrypt):
        decrypt[target] = source
    return encrypt, bytes(decrypt)


def _transform_hill(data: bytes, matrix: list[list[int]], decrypt: bool) -> bytes:
    if decrypt:
        matrix = _hill_inverse(matrix)
    block_size = len(matrix)
    if not decrypt:
        data += b"\x00" * (-len(data) % block_size)
    elif len(data) % block_size:
        raise FileModeError("Ciphertext Hill file tidak valid")

    output = bytearray()
    for start in range(0, len(data), block_size):
        block = data[start : start + block_size]
        output.extend(
            sum(matrix[row][col] * block[col] for col in range(block_size)) % 256
            for row in range(block_size)
        )
    return bytes(output)


def _transform_permutation(data: bytes, key: tuple[int, ...], decrypt: bool) -> bytes:
    output = bytearray()
    width = len(key)
    for start in range(0, len(data), width):
        block = data[start : start + width]
        positions = [position for position in key if position <= len(block)]
        if decrypt:
            restored = bytearray(len(block))
            for index, position in enumerate(positions):
                restored[position - 1] = block[index]
            output.extend(restored)
        else:
            output.extend(block[position - 1] for position in positions)
    return bytes(output)


def _transform(data: bytes, cipher: str, key, decrypt: bool = False) -> bytes:
    _cipher_id(cipher)
    if cipher == "shift":
        try:
            shift = int(key) % 256
        except (TypeError, ValueError) as exc:
            raise FileModeError("Kunci Shift harus berupa angka") from exc
        direction = -shift if decrypt else shift
        return bytes((value + direction) % 256 for value in data)

    if cipher == "substitution":
        encrypt, inverse = _substitution_table(key)
        return data.translate(inverse if decrypt else encrypt)

    if cipher == "affine":
        m, b = _parse_affine_key(key)
        if decrypt:
            inverse = pow(m, -1, 256)
            return bytes(inverse * (value - b) % 256 for value in data)
        return bytes((m * value + b) % 256 for value in data)

    if cipher == "vigenere":
        key_bytes = _key_bytes(key)
        direction = -1 if decrypt else 1
        return bytes((value + direction * key_bytes[index % len(key_bytes)]) % 256 for index, value in enumerate(data))

    if cipher == "hill":
        return _transform_hill(data, _parse_hill_key(key), decrypt)

    if cipher == "permutation":
        return _transform_permutation(data, _parse_permutation_key(key), decrypt)

    key_bytes = _key_bytes(key)
    if len(key_bytes) < len(data):
        raise FileModeError("File kunci OTP lebih pendek dari data yang dienkripsi")
    direction = -1 if decrypt else 1
    return bytes((value + direction * key_bytes[index]) % 256 for index, value in enumerate(data))


def _safe_filename(filename: str) -> str:
    clean_name = PurePath(PureWindowsPath(filename).name).name.replace("\x00", "")
    if not clean_name:
        raise FileModeError("Nama file asli tidak valid")
    encoded = clean_name.encode("utf-8")
    if len(encoded) > MAX_FILENAME_BYTES:
        raise FileModeError("Nama file terlalu panjang")
    return clean_name


def encrypt_file(data: bytes, cipher: str, key, orig_filename: str) -> bytes:
    """Encrypt arbitrary bytes and embed the original filename in encrypted data."""
    if not isinstance(data, bytes):
        raise FileModeError("Isi file harus bytes")
    filename = _safe_filename(orig_filename)
    name_bytes = filename.encode("utf-8")
    header = HEADER.pack(MAGIC, VERSION, _cipher_id(cipher), len(name_bytes), len(data))
    return _transform(header + name_bytes + data, cipher, key)


def decrypt_file(data: bytes, cipher: str, key) -> tuple[bytes, str]:
    """Decrypt a .dat file and return its original bytes and filename."""
    if not isinstance(data, bytes) or not data:
        raise FileModeError("File .dat kosong atau tidak valid")
    plaintext = _transform(data, cipher, key, decrypt=True)
    if len(plaintext) < HEADER.size:
        raise FileModeError("File .dat tidak valid atau kunci/cipher salah")
    magic, version, cipher_id, filename_length, original_size = HEADER.unpack(plaintext[: HEADER.size])
    if magic != MAGIC or version != VERSION or cipher_id != _cipher_id(cipher):
        raise FileModeError("File .dat tidak cocok dengan cipher atau kunci yang dipilih")
    payload_start = HEADER.size + filename_length
    payload_end = payload_start + original_size
    if filename_length > MAX_FILENAME_BYTES or payload_end > len(plaintext):
        raise FileModeError("Metadata file .dat tidak valid")
    try:
        filename = _safe_filename(plaintext[HEADER.size:payload_start].decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise FileModeError("Nama file dalam metadata tidak valid") from exc
    return plaintext[payload_start:payload_end], filename
