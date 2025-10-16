#!/usr/bin/env python3
import sys
import re

# Regex for candump -t A format
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


def parse_candump_line(line):
    m = candump_re.match(line)
    if not m:
        return None
    timestamp, iface, can_id_hex, data_part = m.groups()
    try:
        can_id_int = int(can_id_hex, 16)
    except ValueError:
        return None

    to_addr, msg_type, from_addr, cmd_type, cmd_xtra = parse_can_id(can_id_int)
    data_bytes = [b for b in data_part.strip().split() if len(b) == 2]
    return {
        "timestamp": timestamp,
        "iface": iface,
        "can_id_int": can_id_int,
        "to": to_addr,
        "msg_type": msg_type,
        "from": from_addr,
        "cmd_type": cmd_type,
        "cmd_xtra": cmd_xtra,
        "data": data_bytes,
    }


def direction_label(from_addr, to_addr):
    """Return human-readable direction based on addresses."""
    if from_addr == 0x41 and to_addr == 0x20:
        return "➡️ Message sent (41 → 20)"
    elif from_addr == 0x20 and to_addr == 0x41:
        return "⬅️  Message received (20 → 41)"
    else:
        return f"↔️  Frame {from_addr:02X} → {to_addr:02X}"


def print_group(group):
    """Print grouped frames with a direction label."""
    if not group:
        return
    first = group[0]
    label = direction_label(first["from"], first["to"])
    print(f"\n--- {label}  (count={len(group)}) ---")
    for g in group:
        data_hex = ' '.join(g["data"])
        print(f"{g['timestamp']}  {g['iface']}  "
              f"CAN_ID=0x{g['can_id_int']:08X} "
              f"(to:{g['to']:02X}, type:{g['msg_type']}, "
              f"from:{g['from']:02X}, cmd_type:{g['cmd_type']}, "
              f"cmd_xtra:{g['cmd_xtra']}) DATA=[{data_hex}]")


def main():
    current_group = []
    last_from = None
    last_to = None

    for line in sys.stdin:
        entry = parse_candump_line(line.strip())
        if not entry:
            continue

        if last_from is None:
            last_from, last_to = entry["from"], entry["to"]

        # same direction → keep grouping
        if entry["from"] == last_from and entry["to"] == last_to:
            current_group.append(entry)
        else:
            print_group(current_group)
            current_group = [entry]
            last_from, last_to = entry["from"], entry["to"]

    # print last group
    print_group(current_group)


if __name__ == "__main__":
    main()
