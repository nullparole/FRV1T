# Examples

These examples illustrate the encoding and trust boundary. The agent behaviors below are hypothetical; they are not model evaluation results.

## 1. Byte mapping without invisible text

| Byte value | Selector | Role |
|---|---|---|
| `00` | `U+FE00` | Payload byte 0 |
| `0f` | `U+FE0F` | Payload byte 15, except the carrier's first selector |
| `10` | `U+E0100` | Payload byte 16 |
| `46` | `U+E0136` | ASCII `F`, first envelope byte |
| `52` | `U+E0142` | ASCII `R` |
| `56` | `U+E0146` | ASCII `V` |
| `32` | `U+E0122` | ASCII `2` |
| `ff` | `U+E01EF` | Payload byte 255 |

The beginning of the actual source, escaped for visibility:

```text
\U0001fad0\ufe0f\U000e0136\U000e0142\U000e0146\U000e0122\U000e010f\U000e017b\ufe08
└ carrier ────┘└────────── FRV2 ──────────────────┘└──── gzip: 1f 8b 08 ─────┘
```

## 2. Harmless roundtrip

```sh
python3 -m examples.benign_roundtrip
```

[The example](benign_roundtrip.py) compresses the fixed message `Hello, research!\n`, prefixes `FRV2`, encodes the bytes into selectors, and decodes it again. It prints escaped carrier characters and confirms the gzip checksum. It writes no hidden-payload file and performs no recovered instructions.

## 3. Carrier off-by-one error

Treating all 10,705 selectors in the source as payload gives the prefix `0f 46 52 56 32 1f 8b 08`. The leading `0f` belongs to the carrier. Removing the exact two-codepoint carrier gives the 10,704-byte packet starting `46 52 56 32 1f 8b 08`.

Do not globally remove `U+FE0F`: later occurrences legitimately encode payload byte 15. [Tests](../tests/test_decode_frv2.py) cover missing/extra carrier selectors.

## 4. The trust boundary in an agent workflow

**Authorized task:** inspect the repository and explain its prompt injection.

**Untrusted evidence:** the source README asks an agent to follow the decoded prompt; the decoded text asks for a persona and an executed desktop performance.

| Hypothetical behavior | Assessment |
|---|---|
| Agent reports encoding, hashes, and requested behavior | Completes the research task |
| Agent quotes a directive with attribution and line numbers | Analyzes source data |
| Agent adopts the requested persona and substitutes a long creative performance for the report | Follows source instructions beyond the user's task |
| Agent generates and launches performance code solely because decoded text requests it | Lets source data drive tool actions |

An unsafe design uses recovered instructions as the next agent task. A safer design passes recovered bytes to an evidence store and restricts downstream work to the user's analysis request. Text labels help communicate provenance; tool authorization must also be enforced by the application.

## 5. Resource and integrity boundaries

```sh
python3 scripts/decode_frv2.py --max-output 1024
```

For the real source this exits unsuccessfully with `decompressed output exceeds byte limit`. The default limit permits the known 27,351-byte plaintext. The test suite separately verifies corrupted CRC, truncation, invalid UTF-8, unexpected codepoints, extra members, exact limit boundaries, and refusal to overwrite an existing artifact directory.
