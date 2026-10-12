# X thread: the blueberry prompt injection

Ready-to-post copy, based on static analysis of upstream commit `24dbe8c`. No X posts have been published and no live agent compliance experiment was run. Numbering is included in the length check.

## Posts

### 1/10

This blueberry hides a 27 KB instruction prompt. 🫐

FRV1T packs it into Unicode characters that normally render invisibly, then asks an AI agent to decode and follow it.

We unpacked the file, traced its intended behavior, and built a decoder. 🧵

### 2/10

The hiding place: Unicode variation selectors.

They normally select glyph variants. Unsupported sequences generally render invisibly.

FRV1T uses 256 selectors as byte values, letting a large instruction payload sit behind a small visible glyph.

### 3/10

The byte mapping:

U+FE00–U+FE0F → 0–15
U+E0100–U+E01EF → 16–255

Strip the exact blueberry carrier, map the remaining selectors to bytes, check the FRV2 marker, then decompress gzip.

No encryption or key is involved.

### 4/10

The numbers:

42,213 bytes in the original file
10,704 payload selectors
10,700 bytes of gzip
27,351 bytes of decoded UTF-8
140 lines of instructions

The packet starts:
46 52 56 32 1f 8b 08

That's ASCII “FRV2”, followed by gzip.

### 5/10

One decoding trap: the first U+FE0F belongs to the blueberry carrier.

Decode every selector and you get a stray 0x0f before FRV2.

Remove EVERY U+FE0F and you corrupt real payload bytes.

Skip the carrier by position, then validate the format and checksum.

### 6/10

The recovered prompt asks the agent to adopt a profane persona, use exact dividers, and produce recursive creative passages.

It even directs progress updates and tool reactions to retain that voice.

For a repo-research task, following this would redirect the work.

### 7/10

The tool-use request goes further: create, verify, and execute a compact script through fresh owned windows, with coordinated visuals and audio.

The file doesn't contain that executable. It asks the agent to write and run it as a fictional computer intrusion.

### 8/10

The payload also limits that performance: four owned windows/tabs, two minutes, accessible controls and cleanup.

It prohibits persistence, installs, settings changes, and private-data access.

We decoded the instructions; we did not test agent compliance.

### 9/10

The trust boundary is the README's invitation to “decode and follow”.

Recovering text doesn't give it authority over the user's task.

Our decoder caps input/output, checks integrity, and saves evidence. All 11 tests passed. It never executes the recovered prompt.

### 10/10

Decoder, exact decoded text, hashes, harmless examples, and technical writeup:

https://github.com/nullparole/FRV1T

Original artifact: elder-plinius/FRV1T.

The next research question is measurable: does an agent change its task or attempt tool actions after reading it?

## Evidence map

| Post | Primary evidence |
|---|---|
| 1, 3–5 | [Manifest](research/evidence/manifest.json), [decoder](../scripts/decode_frv2.py), [format analysis](research/frv2-analysis.md) |
| 2 | [Unicode 17.0, section 23.4](https://www.unicode.org/versions/Unicode17.0.0/core-spec/chapter-23/), [observed encoding](research/frv2-analysis.md) |
| 6 | [Recovered creative brief](research/evidence/decoded.txt#L26), [voice in progress updates](research/evidence/decoded.txt#L35) |
| 7 | [Script execution directive](research/evidence/decoded.txt#L111) |
| 8 | [Operational constraints](research/evidence/decoded.txt#L138) |
| 9 | [Pinned upstream README](https://github.com/elder-plinius/FRV1T/blob/24dbe8c9889df0e5ea428380baceb706854bbebe/README.md#L7), [decoder](../scripts/decode_frv2.py), [tests](../tests/test_decode_frv2.py) |
| 10 | [Research fork](https://github.com/nullparole/FRV1T), [proposed evaluation](research/frv2-analysis.md#recommendations-and-a-future-evaluation) |

## Length check

A conservative check uses the [twitter-text v3 weight ranges and 23-character URL length](https://github.com/twitter/twitter-text/blob/master/config/v3.json), treating each non-ASCII emoji as two units.

Weighted lengths including the post number and two newlines: 253, 252, 226, 236, 263, 272, 266, 262, 271, 266. All posts fit 280 units. Check the final rendering in the composer before publication.
