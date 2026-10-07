ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"


def _to_num(ch):
    return ord(ch) - ord("A")


def _to_chr(n):
    return chr(n % 26 + ord("A"))


def clean_alpha(text):
    return "".join(ch for ch in text.upper() if ch in ALPHABET)


def clean_alnum(text):
    """Normalize text while retaining letters and decimal digits only."""
    return "".join(ch for ch in text.upper() if ch in ALPHABET or ch in DIGITS)


def shift_digit(ch, amount):
    return DIGITS[(int(ch) + amount) % len(DIGITS)]


def group5(ct):
    return " ".join(ct[i : i + 5] for i in range(0, len(ct), 5))
