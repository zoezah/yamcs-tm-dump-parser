#!/usr/bin/env python3
import sys
import re

# Regex to match candump -t A format lines
candump_re = re.compile(
    r'\(\s*([0-9-]+\s+[0-9:.]+)\s*\)\s+(\S+)\s+([0-9A-Fa-f]+)\s+\[\d+\]\s*(.*)'
)

def parse_can_id(can_id_int):
    """Extract bitfields from CAN ID according to your structure."""
    to_addr  = (can_id_int >> 21) & 0xFF   # 8 bits
    msg_type = (can_id_int >> 18) & 0x7    # 3 bits
    from_addr = (can_id_int >> 10) & 0xFF  # 8 bits
    cmd_type = (can_id_int >> 7) & 0x7     # 3 bits
    cmd_xtra = can_id_int & 0x7F           # 7 bits
    return to_addr, msg_type, from_addr, cmd_type, cmd_xtra

def write_candump_line(line):
    m = candump_re.match(line)
    if not m:
        return  # skip malformed lines
    timestamp, iface, can_id_hex, data_part = m.groups()

    try:
        can_id_int = int(can_id_hex, 16)
    except ValueError:
        return

    to_addr, msg_type, from_addr, cmd_type, cmd_xtra = parse_can_id(can_id_int)

    # Parse data bytes
    data_bytes = [b for b in data_part.strip().split() if len(b) == 2]
    data_hex = ' '.join(data_bytes)
    data_ints = [int(b, 16) for b in data_bytes]

    print(
        f"{timestamp}  {iface}  "
        f"CAN_ID=0x{can_id_int:08X} "
        f"(to:{to_addr:02X}, type:{msg_type}, from:{from_addr:02X}, "
        f"cmd_type:{cmd_type}, cmd_xtra:{cmd_xtra}) "
        f"DATA= [{data_hex}]"
    )

def main():
    for line in sys.stdin:
        write_candump_line(line.strip())

if __name__ == "__main__":
    main()
