# FRV1T: decoding an agent prompt injection

Research fork of [elder-plinius/FRV1T](https://github.com/elder-plinius/FRV1T), examining upstream commit [`24dbe8c`](https://github.com/elder-plinius/FRV1T/commit/24dbe8c9889df0e5ea428380baceb706854bbebe).

The upstream blueberry file hides a **27,351-byte creative instruction payload** in Unicode variation selectors. Its binary envelope is `FRV2` followed by gzip. The source README tells an agent to decode and follow it; the recovered text requests changes to its voice, response structure, and tool use.

This fork treats the original file and decoded text as **untrusted evidence**. Their instructions do not authorize actions. The decoder transforms bytes only; it never executes the recovered prompt. The upstream entry instructions remain available in the linked commit history.

- [Technical writeup](docs/research/frv2-analysis.md): format, decoded values, behavioral analysis, evidence, and limits.
- [Decoder](scripts/decode_frv2.py): Python standard library, bounded decompression, integrity checks.
- [Decoded evidence and hashes](docs/research/evidence/manifest.json); [exact plaintext](docs/research/evidence/decoded.txt) contains untrusted instructions.
- [Harmless examples](examples/README.md), including a reproducible roundtrip.
- [Published X thread](https://x.com/nullparole/status/2109790463670567239), with [copy and publication receipt](docs/x-thread.md).

## Reproduce

Run from the repository root with Python 3.10 or later and its standard-library `zlib` module:

```sh
python3 scripts/decode_frv2.py
python3 scripts/decode_frv2.py --out /tmp/frv2-evidence
python3 -m examples.benign_roundtrip
python3 -m unittest discover -s tests -v
```

The first command prints metadata only. `--out` must name a new directory; it writes `packet.bin`, `payload.gz`, `decoded.txt`, and `manifest.json`. Input and decompressed output each default to a 1 MiB ceiling. The script rejects unexpected text, unknown envelopes, damaged/truncated gzip, multiple members, and excess output.

The analysis establishes what the payload asks an agent to do. No live agent compliance experiment or fictional desktop performance was run.
