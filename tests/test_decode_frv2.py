"""Format, integrity, resource limits, and frozen-source regression checks."""

import gzip
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.decode_frv2 import CARRIER, DecodeError, decode, sha256


ROOT = Path(__file__).resolve().parents[1]


def encode_packet(packet):
    selectors = "".join(chr(0xFE00 + b) if b < 16 else chr(0xE0100 + b - 16)
                        for b in packet)
    return (CARRIER + selectors + "\n").encode("utf-8")


def benign_source(plaintext=b"Hello, research!\n"):
    return encode_packet(b"FRV2" + gzip.compress(plaintext, mtime=0))


class DecoderTests(unittest.TestCase):
    def test_frozen_source(self):
        result = decode((ROOT / "🫐.txt").read_bytes())
        self.assertEqual(result.manifest["source"]["sha256"],
                         "55479d8bf662dcf26c89c3e9b0409e635d5721b3fe5afc5b8d8224ac10464d58")
        self.assertEqual(sha256(result.plaintext),
                         "6d7d8ff8c039a47981128433019361d2fde387b381174d956d2667d5032f455b")
        self.assertEqual(len(result.packet), 10704)
        self.assertEqual(len(result.gzip), 10700)
        self.assertEqual(len(result.plaintext), 27351)
        self.assertEqual(result.manifest["decoded"]["lines"], 140)

    def test_benign_roundtrip_with_and_without_final_lf(self):
        source = benign_source("Hello, research! 🫐\n".encode())
        for candidate in (source, source[:-1]):
            self.assertEqual(decode(candidate).plaintext, "Hello, research! 🫐\n".encode())

    def test_carrier_selector_is_not_data(self):
        source = benign_source()
        for candidate in (source.replace(CARRIER.encode(), "🫐".encode(), 1),
                          source.replace(CARRIER.encode(), (CARRIER + "\ufe0f").encode(), 1)):
            with self.assertRaises(DecodeError):
                decode(candidate)

    def test_unexpected_text_and_utf8_rejected(self):
        for candidate in (b"\xff", benign_source() + b"visible", benign_source() + b"\n",
                          (CARRIER + "\u200b").encode()):
            with self.assertRaises(DecodeError):
                decode(candidate)

    def test_wrong_envelope_and_non_gzip_rejected(self):
        for packet in (b"FRV1" + gzip.compress(b"hello"), b"FRV2" + b"plain text"):
            with self.assertRaises(DecodeError):
                decode(encode_packet(packet))

    def test_truncated_and_corrupt_gzip_rejected(self):
        compressed = gzip.compress(b"hello", mtime=0)
        corrupt = bytearray(compressed)
        corrupt[-8] ^= 1
        for data in (compressed[:-1], bytes(corrupt)):
            with self.assertRaises(DecodeError):
                decode(encode_packet(b"FRV2" + data))

    def test_extra_data_and_multiple_members_rejected(self):
        compressed = gzip.compress(b"hello", mtime=0)
        for suffix in (b"extra", gzip.compress(b"other", mtime=0)):
            with self.assertRaises(DecodeError):
                decode(encode_packet(b"FRV2" + compressed + suffix))

    def test_output_cap_and_exact_boundary(self):
        source = benign_source(b"A" * 20000)
        with self.assertRaisesRegex(DecodeError, "output exceeds"):
            decode(source, max_output=19999)
        self.assertEqual(len(decode(source, max_output=20000).plaintext), 20000)

    def test_input_cap_and_nonpositive_limits(self):
        source = benign_source()
        with self.assertRaisesRegex(DecodeError, "input exceeds"):
            decode(source, max_input=len(source) - 1)
        self.assertEqual(decode(source, max_input=len(source)).plaintext, b"Hello, research!\n")
        for limits in ({"max_input": 0}, {"max_output": 0}, {"max_output": -1}):
            with self.assertRaises(DecodeError):
                decode(source, **limits)

    def test_invalid_decoded_utf8(self):
        with self.assertRaisesRegex(DecodeError, "decoded content"):
            decode(benign_source(b"\xff"))

    def test_cli_artifacts_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "evidence"
            command = [sys.executable, str(ROOT / "scripts/decode_frv2.py"),
                       str(ROOT / "🫐.txt"), "--out", str(out)]
            process = subprocess.run(command, capture_output=True, check=True)
            manifest = json.loads(process.stdout)
            self.assertEqual(sha256((out / "decoded.txt").read_bytes()),
                             manifest["decoded"]["sha256"])
            self.assertEqual(json.loads((out / "manifest.json").read_text()), manifest)
            self.assertNotIn(b"!L1B3RT4S", process.stdout)
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)


if __name__ == "__main__":
    unittest.main()
