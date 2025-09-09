import sys, struct, re
from pathlib import Path

HEX_CHARS = set("0123456789abcdefABCDEF \t\r\n")

def is_hex_text(s: str) -> bool:
    return all(c in HEX_CHARS for c in s) and re.search(r"[0-9A-Fa-f]", s) is not None

def iter_packets_from_binary(data: bytes):
    i = 0
    n = len(data)
    while i + 6 <= n:
        first, seq, length = struct.unpack(">HHH", data[i:i+6])
        total = 6 + (length + 1)                     # CCSDS rule
        if i + total > n or total < 7:               # basic sanity
            break
        yield data[i:i+total]
        i += total

def iter_packets_from_hex_lines(text: str):
    for line in text.splitlines():
        line = re.sub(r"[^0-9A-Fa-f]", "", line)
        if len(line) < 12 or len(line) % 2:          # need at least 6 bytes header
            continue
        try:
            yield bytes.fromhex(line)
        except ValueError:
            continue

def parse_min(pkt: bytes):
    first, seq, length = struct.unpack(">HHH", pkt[:6])
    apid = first & 0x07FF
    ssc  = seq & 0x3FFF
    # PUS-C (common layout): flags @ +6, service @ +7, subservice @ +8
    svc  = pkt[7] if len(pkt) > 8 else None
    ssvc = pkt[8] if len(pkt) > 9 else None
    return apid, ssc, svc, ssvc, len(pkt)

def main(path: str):
    p = Path(path)
    raw = p.read_bytes()
    # Auto-detect hex dump vs binary
    packets = []
    try_text = False
    try:
        text = raw.decode("ascii")
        try_text = is_hex_text(text)
    except UnicodeDecodeError:
        try_text = False

    if try_text:
        for pkt in iter_packets_from_hex_lines(text):
            packets.append(pkt)
    else:
        # If your file was length-prefixed by 4 bytes (Yamcs “binary/length”),
        # set LENGTH_PREFIXED=True.
        LENGTH_PREFIXED = False
        if LENGTH_PREFIXED:
            i = 0
            while i + 4 <= len(raw):
                plen = struct.unpack(">I", raw[i:i+4])[0]
                i += 4
                packets.append(raw[i:i+plen])
                i += plen
        else:
            packets.extend(iter_packets_from_binary(raw))

    if not packets:
        print("No CCSDS packets detected. If this was a length-prefixed file, set LENGTH_PREFIXED=True.")
        sys.exit(1)

    for idx, pkt in enumerate(packets, 1):
        apid, ssc, svc, ssvc, plen = parse_min(pkt)
        print(f"#{idx:05d} len={plen:4d} APID={apid:4d} SSC={ssc:5d} SVC={svc} SUB={ssvc}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: tm_reader.py <dump.raw>")
        sys.exit(2)
    main(sys.argv[1])
