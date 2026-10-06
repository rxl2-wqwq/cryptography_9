ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _to_num(ch):
    return ord(ch) - ord("A")


def _to_chr(n):
    return chr(n % 26 + ord("A"))


def clean_alpha(text):
    return "".join(ch for ch in text.upper() if ch in ALPHABET)


def group5(ct):
    return " ".join(ct[i : i + 5] for i in range(0, len(ct), 5))
