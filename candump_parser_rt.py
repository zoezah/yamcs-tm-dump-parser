import sys

def write_candump_line(line):
    try:
        # Split the line into parts
        parts = line.split(None, 3)        
        if len(parts) < 3:
            return None

        can_id = int(parts[1], 16)

        #print(can_id)        
        to_addr = (can_id >>21)  # 8 bits
        msg_type = (can_id >> 18) & 0x7 # 3 bits
        from_addr = (can_id >>10) & 0xFF  # 8 bits
        cmd_type = (can_id >>7)& 0x7 # 3 bits 
        cmd_xtra = can_id & 0x3F   # 7 bits
        
        print(f"CAN_ID: (to: {to_addr}, type: {msg_type}, from: {from_addr}, cmd_type: {cmd_type}, cmd_xtra: {cmd_xtra}) DATA: ", parts[3])
    except (IndexError, ValueError):
        # Handling cases where input data might be missing or malformed
        return None

for line in sys.stdin:
    write_candump_line(line.strip())
