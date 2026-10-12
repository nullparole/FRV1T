# X thread draft: the blueberry prompt injection

Draft for later publication. No posts have been published. Claims describe static analysis of upstream commit `24dbe8c`; no model attack-success rate was measured. The fork link targets the research branch.

## Posts

### 1/10

A text file that looks like a blueberry hides a 27 KB prompt for an AI agent.

I decoded FRV1T: Unicode variation selectors → bytes → FRV2 → gzip → instructions.

The interesting part is how a repo asks an agent to turn recovered data into its next task. 🧵

### 2/10

The README supplies the handoff: retrieve the blueberry file, decode it, and follow the creative prompt. It also claims authorization.

For an agent assigned to research the repo, those words are evidence to analyze. Following them would change the task.

### 3/10

The file is 42,213 bytes and 10,707 Unicode scalars.

After a blueberry and its presentation selector come 10,704 payload selectors. Map U+FE00–FE0F to 0–15 and U+E0100–E01EF to 16–255.

The recovered bytes start with ASCII FRV2, then a gzip header.

### 4/10

Small decoding trap: the first U+FE0F belongs to the carrier.

Decode every selector and you get an extra 0x0f before FRV2. Remove every U+FE0F and you corrupt real payload bytes.

Skip the exact carrier, then validate the envelope and checksum.

### 5/10

The gzip member expands to 27,351 bytes of UTF-8: 140 lines.

The prompt asks for a profane persona, exact dividers, recursive creative passages, invented state traces, and eventually a host-specific fictional computer intrusion with visuals and audio.

### 6/10

The tool-use step is explicit: create and verify a compact script, then execute it through fresh owned windows.

There is no embedded executable to run here. The payload asks the agent to write the code itself, after a long creative performance.

### 7/10

The prompt bounds the performance and prohibits persistence, installs, settings changes, private-data access, and unrelated-app control.

Our analysis shows intended task redirection. It does not demonstrate malware, data theft, or a successful compromise.

### 8/10

The decoder uses Python's standard library, caps input and output, validates the carrier and FRV2 marker, and rejects damaged gzip or extra members.

It prints metadata and can save the exact evidence. It never performs the recovered instructions.

### 9/10

We added harmless examples, boundary tests, hashes, the full decoded text, and a cited technical writeup.

No live model compliance test was run. Keep decoded repository content in the evidence channel; enforce the user's task at tool boundaries.

### 10/10

Research fork, decoder, examples, and writeup:
https://github.com/nullparole/FRV1T/tree/research/frv2-analysis

Credit for the original artifact: elder-plinius/FRV1T.

Next research step: reproducible agent evaluations measuring task changes and attempted tool actions.

## Evidence map

| Post | Primary evidence |
|---|---|
| 1, 3–5 | [Manifest](research/evidence/manifest.json), [format analysis](research/frv2-analysis.md) |
| 2 | [Pinned upstream README](https://github.com/elder-plinius/FRV1T/blob/24dbe8c9889df0e5ea428380baceb706854bbebe/README.md#L7) |
| 5–6 | [Recovered brief](research/evidence/decoded.txt#L26), [script directive](research/evidence/decoded.txt#L111) |
| 7 | [Operational constraints](research/evidence/decoded.txt#L138) |
| 8–9 | [Decoder](../scripts/decode_frv2.py), [tests](../tests/test_decode_frv2.py), [examples](../examples/README.md) |
| 10 | Research branch in the requested fork |

The posts target ordinary short-post lengths. A conservative check uses the [twitter-text v3 weight ranges and 23-character URL length](https://github.com/twitter/twitter-text/blob/master/config/v3.json), treating each non-ASCII emoji as two units. All bodies fit 280 units with space for their numbering. Check the final rendering in the composer before publication.
