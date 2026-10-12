"""A fixed harmless message demonstrating the observed FRV2 byte mapping."""

import gzip
import json

from scripts.decode_frv2 import CARRIER, decode


def main():
    message = b"Hello, research!\n"
    packet = b"FRV2" + gzip.compress(message, mtime=0)
    selectors = "".join(chr(0xFE00 + byte) if byte < 16
                        else chr(0xE0100 + byte - 16) for byte in packet)
    source = (CARRIER + selectors + "\n").encode("utf-8")
    result = decode(source)
    assert result.plaintext == message
    print(json.dumps({"message": result.plaintext.decode(),
                      "packet_prefix_hex": result.packet[:7].hex(),
                      "carrier_prefix_escaped": ascii((CARRIER + selectors)[:6]),
                      "integrity_verified": result.manifest["gzip"]["checksum_verified"]},
                     indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
