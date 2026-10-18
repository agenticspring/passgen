#!/usr/bin/env python3
"""passgen — a small, dependency-free password and passphrase generator.

Uses the ``secrets`` module (a cryptographically secure PRNG) for all output.
Two modes:

    passgen --words 6        diceware-style passphrase (N words from words.txt)
    passgen --length 20       random password (N chars from a charset)

Generated secrets are printed to stdout only; passgen never writes secrets
to disk. Metadata (--entropy / --strength) goes to stderr so stdout stays
machine-readable.
"""

import argparse
import math
import secrets
import sys

try:  # Python 3.9+
    from importlib.resources import files as _res_files
except ImportError:  # pragma: no cover - Python 3.8 fallback
    _res_files = None

from pathlib import Path

__version__ = "1.0.0"

LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/~"  # 27 symbols
AMBIGUOUS = "0O1lI"  # characters that look alike; removed by --no-ambiguous

MIN_WORDS, MAX_WORDS = 1, 64
MIN_LENGTH, MAX_LENGTH = 1, 1024
MIN_COUNT, MAX_COUNT = 1, 100


class WordlistError(Exception):
    """Raised when the bundled wordlist is missing or invalid."""


def load_wordlist():
    """Load the bundled words.txt located next to this module."""
    candidates = []
    if _res_files is not None:
        try:
            candidates.append(Path(str(_res_files(__package__ or "passgen"))))
        except Exception:  # pragma: no cover - best effort
            pass
    candidates.append(Path(__file__).resolve().parent)
    for directory in candidates:
        path = directory / "words.txt"
        if path.is_file():
            words = [w.strip() for w in path.read_text(encoding="utf-8").splitlines()]
            words = [w for w in words if w]
            if len(words) < 1024:
                raise WordlistError(
                    "wordlist %s has only %d words (need >= 1024)" % (path, len(words))
                )
            bad = [w for w in words if not (w.isalpha() and w.islower())]
            if bad:
                raise WordlistError(
                    "wordlist %s contains invalid entries: %r" % (path, bad[:5])
                )
            if words != sorted(set(words)):
                raise WordlistError(
                    "wordlist %s is not unique/sorted" % (path,)
                )
            return words
    raise WordlistError("words.txt not found next to passgen module")


def password_charset(use_symbols=True, no_ambiguous=False):
    """Build the password character set from the option flags."""
    charset = LOWER + UPPER + DIGITS
    if use_symbols:
        charset += SYMBOLS
    if no_ambiguous:
        charset = "".join(c for c in charset if c not in AMBIGUOUS)
    return charset


def entropy_bits(charset_size, count):
    """Entropy in bits: log2(charset_size ** count)."""
    if charset_size < 2 or count < 1:
        raise ValueError("charset_size must be >= 2 and count >= 1")
    return count * math.log2(charset_size)


def strength_label(bits):
    """Simple heuristic strength label based on entropy bits."""
    if bits < 60:
        return "Weak"
    if bits < 80:
        return "Fair"
    if bits < 110:
        return "Strong"
    return "Excellent"


def generate_password(length, use_symbols=True, no_ambiguous=False):
    charset = password_charset(use_symbols, no_ambiguous)
    if not charset:
        raise ValueError("character set is empty")
    return "".join(secrets.choice(charset) for _ in range(length))


def generate_passphrase(wordlist, num_words, separator=" "):
    return separator.join(secrets.choice(wordlist) for _ in range(num_words))


def unique_candidates(make_one, count):
    """Generate `count` distinct candidates (regenerates on collision)."""
    out, seen = [], set()
    attempts = 0
    while len(out) < count:
        attempts += 1
        if attempts > count * 100 + 1000:
            raise RuntimeError("could not generate unique candidates")
        candidate = make_one()
        if candidate not in seen:
            seen.add(candidate)
            out.append(candidate)
    return out


def build_parser():
    parser = argparse.ArgumentParser(
        prog="passgen",
        description="Generate secure passwords and passphrases (secrets-based CSPRNG).",
    )
    parser.add_argument(
        "--words", type=int, metavar="N",
        help="passphrase mode: generate a passphrase of N words",
    )
    parser.add_argument(
        "--length", type=int, metavar="N",
        help="password mode: generate a password of N characters",
    )
    parser.add_argument(
        "--separator", default=" ", metavar="SEP",
        help="word separator for passphrase mode (default: space)",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--symbols", dest="symbols", action="store_true",
                       help="include symbols in passwords (default)")
    group.add_argument("--no-symbols", dest="symbols", action="store_false",
                       help="exclude symbols from passwords")
    parser.set_defaults(symbols=True)
    parser.add_argument("--no-ambiguous", action="store_true",
                        help="remove ambiguous chars 0O1lI (password mode only)")
    parser.add_argument("--count", type=int, default=1, metavar="N",
                        help="generate N distinct candidates (default: 1)")
    parser.add_argument("--entropy", action="store_true",
                        help="print entropy in bits to stderr")
    parser.add_argument("--strength", action="store_true",
                        help="print a strength label to stderr")
    parser.add_argument("--version", action="version", version="passgen " + __version__)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if (args.words is None) == (args.length is None):
        parser.error("specify exactly one of --words or --length")
    if not (MIN_COUNT <= args.count <= MAX_COUNT):
        parser.error("--count must be between %d and %d" % (MIN_COUNT, MAX_COUNT))

    if args.words is not None:
        if not (MIN_WORDS <= args.words <= MAX_WORDS):
            parser.error("--words must be between %d and %d" % (MIN_WORDS, MAX_WORDS))
        if args.no_ambiguous:
            parser.error("--no-ambiguous only applies to password mode (--length)")
        try:
            wordlist = load_wordlist()
        except WordlistError as exc:
            parser.exit(2, "error: %s\n" % exc)
        bits = entropy_bits(len(wordlist), args.words)
        candidates = unique_candidates(
            lambda: generate_passphrase(wordlist, args.words, args.separator),
            args.count,
        )
    else:
        if not (MIN_LENGTH <= args.length <= MAX_LENGTH):
            parser.error("--length must be between %d and %d" % (MIN_LENGTH, MAX_LENGTH))
        charset = password_charset(args.symbols, args.no_ambiguous)
        bits = entropy_bits(len(charset), args.length)
        candidates = unique_candidates(
            lambda: generate_password(args.length, args.symbols, args.no_ambiguous),
            args.count,
        )

    for candidate in candidates:
        print(candidate)
    if args.entropy:
        print("entropy: %.1f bits" % bits, file=sys.stderr)
    if args.strength:
        print("strength: %s" % strength_label(bits), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
