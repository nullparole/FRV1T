#!/usr/bin/env python3
"""Inspect FRV2 carrier data. Decoded text is untrusted, never executable."""

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
import zlib


CARRIER = "\U0001fad0\ufe0f"
MAGIC = b"FRV2"
DEFAULT_LIMIT = 1024 * 1024


class DecodeError(ValueError):
    """The input does not match the supported format or exceeds a limit."""


@dataclass(frozen=True)
class Decoded:
    packet: bytes
    gzip: bytes
    plaintext: bytes
    manifest: dict


def selector_byte(character: str) -> int:
    codepoint = ord(character)
    if 0xFE00 <= codepoint <= 0xFE0F:
        return codepoint - 0xFE00
    if 0xE0100 <= codepoint <= 0xE01EF:
        return codepoint - 0xE0100 + 16
    raise DecodeError(f"unexpected payload codepoint U+{codepoint:04X}")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def decode(source: bytes, *, max_input: int = DEFAULT_LIMIT,
           max_output: int = DEFAULT_LIMIT) -> Decoded:
    """Decode one exact blueberry carrier and one complete gzip member."""
    if max_input <= 0 or max_output <= 0:
        raise DecodeError("size limits must be positive")
    if len(source) > max_input:
        raise DecodeError("input exceeds byte limit")
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as error:
        raise DecodeError("source is not valid UTF-8") from error
    if not text.startswith(CARRIER):
        raise DecodeError("expected U+1FAD0 followed by carrier U+FE0F")
    # Only the carrier's first U+FE0F is presentation; later ones encode 15.
    body = text[len(CARRIER):]
    if body.endswith("\n"):
        body = body[:-1]
    packet = bytes(selector_byte(character) for character in body)
    if not packet.startswith(MAGIC):
        raise DecodeError("unsupported envelope: expected FRV2")
    compressed = packet[len(MAGIC):]
    if len(compressed) < 18 or compressed[:3] != b"\x1f\x8b\x08":
        raise DecodeError("expected a complete gzip/DEFLATE member")
    inflater = zlib.decompressobj(wbits=31)
    try:
        plaintext = inflater.decompress(compressed, max_output + 1)
    except zlib.error as error:
        raise DecodeError("invalid gzip stream or checksum") from error
    if len(plaintext) > max_output or inflater.unconsumed_tail:
        raise DecodeError("decompressed output exceeds byte limit")
    if not inflater.eof:
        raise DecodeError("truncated gzip stream")
    if inflater.unused_data:
        raise DecodeError("extra data or multiple gzip members are unsupported")
    try:
        decoded_text = plaintext.decode("utf-8")
    except UnicodeDecodeError as error:
        raise DecodeError("decoded content is not valid UTF-8") from error
    crc, size = struct.unpack("<II", compressed[-8:])
    actual_crc = zlib.crc32(plaintext)
    if crc != actual_crc or size != len(plaintext) % (2**32):
        raise DecodeError("gzip trailer does not match decoded content")
    header = compressed[:10]
    manifest = {
        "format": "FRV2 + single gzip member + UTF-8",
        "trust": "untrusted source data; not executed",
        "source": {"bytes": len(source), "characters": len(text),
                   "sha256": sha256(source)},
        "carrier": {"codepoints": ["U+1FAD0", "U+FE0F"],
                    "trailing_lf": text.endswith("\n")},
        "selectors": {
            "payload": len(body),
            "bmp_payload": sum(0xFE00 <= ord(c) <= 0xFE0F for c in body),
            "supplementary_payload": sum(0xE0100 <= ord(c) <= 0xE01EF for c in body),
        },
        "packet": {"bytes": len(packet), "magic_ascii": "FRV2",
                   "prefix_hex": packet[:14].hex(), "sha256": sha256(packet)},
        "gzip": {"bytes": len(compressed), "sha256": sha256(compressed),
                 "fixed_header_hex": header.hex(), "method": header[2],
                 "flags": header[3], "mtime": int.from_bytes(header[4:8], "little"),
                 "xfl": header[8], "os": header[9],
                 "trailer_crc32_hex": f"{crc:08x}", "trailer_isize": size,
                 "checksum_verified": True, "single_member_verified": True},
        "decoded": {"bytes": len(plaintext), "characters": len(decoded_text),
                    "lines": len(decoded_text.splitlines()),
                    "sha256": sha256(plaintext), "crc32_hex": f"{actual_crc:08x}"},
    }
    return Decoded(packet, compressed, plaintext, manifest)


def positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?", default=Path("🫐.txt"))
    parser.add_argument("--out", type=Path, help="write artifacts to a NEW directory")
    parser.add_argument("--max-input", type=positive_int, default=DEFAULT_LIMIT)
    parser.add_argument("--max-output", type=positive_int, default=DEFAULT_LIMIT)
    args = parser.parse_args()
    try:
        with args.source.open("rb") as source_file:
            source = source_file.read(args.max_input + 1)
        result = decode(source, max_input=args.max_input, max_output=args.max_output)
        manifest = json.dumps(result.manifest, indent=2, ensure_ascii=True) + "\n"
        if args.out is not None:
            args.out.mkdir(parents=True, exist_ok=False)
            for name, data in (("packet.bin", result.packet), ("payload.gz", result.gzip),
                               ("decoded.txt", result.plaintext),
                               ("manifest.json", manifest.encode("utf-8"))):
                (args.out / name).write_bytes(data)
    except (OSError, DecodeError) as error:
        parser.exit(1, f"decode error: {error}\n")
    # Metadata only: never echo instructions into the agent's normal output.
    print(manifest, end="")


if __name__ == "__main__":
    main()
