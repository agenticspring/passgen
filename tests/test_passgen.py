"""Unit tests for passgen. Run: python -m unittest discover -s tests -v"""

import io
import math
import re
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import passgen


class TestEntropyMath(unittest.TestCase):
    def test_password_entropy_formula(self):
        charset = passgen.password_charset(True, False)
        expected = 20 * math.log2(len(charset))
        self.assertAlmostEqual(passgen.entropy_bits(len(charset), 20), expected, places=9)

    def test_passphrase_entropy_formula(self):
        words = passgen.load_wordlist()
        expected = 6 * math.log2(len(words))
        self.assertAlmostEqual(passgen.entropy_bits(len(words), 6), expected, places=9)

    def test_entropy_sanity_values(self):
        # full charset must be at least 90 chars wide; check a plausible bit value
        n = len(passgen.password_charset(True, False))
        # 26 lower + 26 upper + 10 digits + 27 symbols = 89
        self.assertEqual(n, 26 + 26 + 10 + len(passgen.SYMBOLS))
        self.assertGreaterEqual(n, 85)
        bits = passgen.entropy_bits(n, 20)
        self.assertAlmostEqual(bits, 20 * math.log2(n), places=9)

    def test_entropy_rejects_bad_input(self):
        with self.assertRaises(ValueError):
            passgen.entropy_bits(1, 20)
        with self.assertRaises(ValueError):
            passgen.entropy_bits(94, 0)


class TestWordlist(unittest.TestCase):
    def test_wordlist_integrity(self):
        words = passgen.load_wordlist()
        self.assertGreaterEqual(len(words), 1024)
        self.assertEqual(len(set(words)), len(words), "wordlist must be unique")
        for w in words:
            self.assertTrue(w.isalpha() and w.islower(), "bad word: %r" % w)
        self.assertEqual(words, sorted(words), "wordlist must be sorted alphabetically")

    def test_wordlist_loads_relative_to_module(self):
        # no hardcoded absolute paths: the file must sit next to the module
        module_dir = Path(passgen.__file__).resolve().parent
        self.assertTrue((module_dir / "words.txt").is_file())


class TestPasswordFormat(unittest.TestCase):
    def test_length(self):
        for _ in range(20):
            pw = passgen.generate_password(16)
            self.assertEqual(len(pw), 16)

    def test_default_charset(self):
        charset = set(passgen.password_charset(True, False))
        self.assertIn("a", charset)
        self.assertIn("Z", charset)
        self.assertIn("7", charset)
        self.assertIn("!", charset)
        for _ in range(20):
            pw = passgen.generate_password(24)
            self.assertTrue(all(c in charset for c in pw))

    def test_no_symbols(self):
        charset = set(passgen.password_charset(False, False))
        self.assertNotIn("!", charset)
        for _ in range(20):
            pw = passgen.generate_password(24, use_symbols=False)
            self.assertTrue(all(c in charset for c in pw))

    def test_no_ambiguous_removed(self):
        charset = set(passgen.password_charset(True, True))
        for ch in passgen.AMBIGUOUS:
            self.assertNotIn(ch, charset)
        for _ in range(50):
            pw = passgen.generate_password(32, no_ambiguous=True)
            self.assertTrue(all(c not in passgen.AMBIGUOUS for c in pw))


class TestPassphraseFormat(unittest.TestCase):
    def test_word_count_and_membership(self):
        words = set(passgen.load_wordlist())
        for _ in range(20):
            phrase = passgen.generate_passphrase(passgen.load_wordlist(), 6)
            parts = phrase.split(" ")
            self.assertEqual(len(parts), 6)
            self.assertTrue(all(p in words for p in parts))

    def test_custom_separator(self):
        phrase = passgen.generate_passphrase(passgen.load_wordlist(), 4, separator="-")
        self.assertEqual(len(phrase.split("-")), 4)


class TestDeterminismWithMock(unittest.TestCase):
    def test_mocked_choice_is_deterministic(self):
        # Honest determinism check: patch secrets.choice, not the real RNG.
        seq = iter("abcdef")
        with mock.patch.object(passgen.secrets, "choice", side_effect=lambda c: next(seq)):
            self.assertEqual(passgen.generate_password(6), "abcdef")

    def test_uses_secrets_not_random(self):
        import inspect
        src = inspect.getsource(passgen)
        self.assertIn("secrets", src)
        self.assertNotRegex(src, r"(?<![\w.])random\.")


class TestNonRepetition(unittest.TestCase):
    def test_two_consecutive_runs_differ(self):
        # Real CSPRNG; collision probability for 32-char full-charset
        # passwords is ~2^-209, so a difference is a meaningful check.
        a = passgen.generate_password(32)
        b = passgen.generate_password(32)
        self.assertNotEqual(a, b)


class TestCLI(unittest.TestCase):
    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        code = None
        with redirect_stdout(out), redirect_stderr(err):
            try:
                code = passgen.main(argv)
            except SystemExit as e:
                code = e.code
        return code, out.getvalue(), err.getvalue()

    def test_password_stdout_only(self):
        code, out, err = self.run_main(["--length", "20"])
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip().splitlines()), 1)
        self.assertEqual(len(out.strip()), 20)
        self.assertEqual(err, "")

    def test_count_produces_n_unique_lines(self):
        code, out, err = self.run_main(["--length", "24", "--count", "5"])
        self.assertEqual(code, 0)
        lines = out.strip().splitlines()
        self.assertEqual(len(lines), 5)
        self.assertEqual(len(set(lines)), 5)

    def test_entropy_and_strength_go_to_stderr(self):
        code, out, err = self.run_main(
            ["--length", "20", "--entropy", "--strength"])
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip().splitlines()), 1)
        m = re.search(r"entropy: ([0-9.]+) bits", err)
        self.assertIsNotNone(m, "entropy line missing in stderr: %r" % err)
        bits = float(m.group(1))
        charset = passgen.password_charset(True, False)
        self.assertAlmostEqual(bits, 20 * math.log2(len(charset)), places=1)
        self.assertIn("strength:", err)

    def test_passphrase_cli(self):
        code, out, err = self.run_main(["--words", "6", "--entropy"])
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip().split(" ")), 6)
        m = re.search(r"entropy: ([0-9.]+) bits", err)
        words = passgen.load_wordlist()
        self.assertAlmostEqual(float(m.group(1)), 6 * math.log2(len(words)), places=1)

    def test_bad_args_exit_2(self):
        for argv in (["--length", "0"], ["--length", "-5"], ["--words", "0"],
                     ["--words", "-1"], ["--count", "0"], ["--count", "101"],
                     ["--words", "6", "--length", "20"], [],
                     ["--words", "6", "--no-ambiguous"]):
            code, out, err = self.run_main(argv)
            self.assertEqual(code, 2, "expected exit 2 for %r (got %r)" % (argv, code))

    def test_strength_labels(self):
        self.assertEqual(passgen.strength_label(30), "Weak")
        self.assertEqual(passgen.strength_label(59.9), "Weak")
        self.assertEqual(passgen.strength_label(60), "Fair")
        self.assertEqual(passgen.strength_label(79.9), "Fair")
        self.assertEqual(passgen.strength_label(80), "Strong")
        self.assertEqual(passgen.strength_label(109.9), "Strong")
        self.assertEqual(passgen.strength_label(110), "Excellent")


if __name__ == "__main__":
    unittest.main()
