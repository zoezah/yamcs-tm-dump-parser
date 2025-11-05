
action_tc = {
    "ccsds_version": 0,         # ALWAYS '000' 
    "ccsds_packettype": 1,      # 0x0: TM, 0x1: TC
    "ccsds_shflag": 1,          # always 1 except for TM: time packets
    "ccsds_apid": 10,          # destination APID
    "ccsds_seqcount": 50,
    "ccsds_length": 4,
    "pus_version": 1,
    "pus_ackflags": 0,
    "pus_type": 17,
    "pus_stype": 1,
    "pus_source_id": 0,
    "checksum": 2834
}


# how to decode this:
# CAN ID starts with 04: TC
# CAN ID starts with 08: TM
# [8] message length

# first part: 61 15 00 70 C0 0A 18 00  is CCSDS Header in CAN transport layer
# cut out first and last byte and flip bytewise:
# 18 0A C0 70 00 15 

# decode first two bytes:

# 18 in bits:
# 00011000 -> first three bits: ccsds version (here: 000)
# next bit: packet type (here: 1 (TC))
# next bit: secondary header flag (here: 1)

# next three bits part of the APID
# 0A in bits:
# 00001010
# next 11 bits: APID (here: 00000001010 = 10 (PF OBC A))

# --> 18 0A always TC to PF OBC A !!

# C0 in bits:
# 11000000 -> first two bits: sequence flags (always (except CFDP): 11)
# 70 in bits: 
# 01110000 -> 14 bits: sequence count per APID (here: 112)

# 00 15 in bits: 00000000 00010101 -> here: 21. 21+1 = 22 bytes packet length (8+8+6)

current_tc = None
previous_info = None
frames_left = 0

tcs_grouped = []



def parse_line(line):
    parts = line.split()
    timestamp = parts[1].strip(")")
    can_id = parts[3]
    data_length = parts[4].strip("[]")
    data_length = int(data_length)
    data = parts[5::]
    return{"timestamp": timestamp, "can_id": can_id, "data_length": data_length, "data": data}

def detect_frame_type(can_id: str):
    if can_id.startswith("04"):
        return "TC"
    if can_id.startswith("08"):
        return "TM"
    else:
        return "OTHER"

def is_tc_header(info, previous_info=None):
    if not info["can_id"].startswith("04"):
        return 0
    if info["data_length"] != 8:
        return 0
    if previous_info and previous_info["can_id"].startswith("08"):
        if info["data"] == previous_info["data"]:
            return 0
    parts = line.split()
    data = parts[5:]
    ccsds_header = data[1:len(data)-1]
    ccsds_header.reverse()
    #print(f"The CCSDS header is: {ccsds_header}")
    last_two_bytes = ccsds_header[4:6]
    data_field_length = int("".join(last_two_bytes), 16) + 1
    #print(f"The Data field length of the following TC is: {data_field_length} bytes")
    if data_field_length <= 8:
        frames_nr = 1
        print(f"The following frame belongs to this TC")
        return frames_nr
    else: 
        frames_nr, remainder = divmod(data_field_length, 8)
        if remainder != 0:
            frames_nr += 1
    return frames_nr

def decode_pus_secondary_header(tc):
    if len(tc["frames"]) < 2:
        return None

    data = tc["frames"][1]["data"]

    if len(data) < 3:
        return None
    
    pus_type = int(data[1], 16)
    pus_subtype = int(data[2], 16)
    return {"type": pus_type, "subtype": pus_subtype}
    

with open("candump_svc_23_copy_move_file.txt") as logfile:
    for line in logfile:
        if not line.strip():
            continue

        info = parse_line(line)
        if not info:
            continue
        
        # === CASE 1: continue collecting frames ===
        if frames_left > 0 and info["can_id"].startswith("04"):
            current_tc["frames"].append(info)
            frames_left -= 1
            if frames_left == 0:
                tcs_grouped.append(current_tc)
                pus_info = decode_pus_secondary_header(current_tc)
                if pus_info:
                    print(f"→ TC[{pus_info['type']},{pus_info['subtype']}]")

                current_tc = None
            previous_info = info
            continue


        # === CASE 2: check if new TC header ===
        frames_nr = is_tc_header(info, previous_info)
        if frames_nr:
            #print("TC header found:", info["can_id"], info["data"])
            frames_left = frames_nr
            current_tc = {
                "start_time": info["timestamp"],
                "header": info,
                "frames": [info]
            }

        previous_info = info

def parse_ccsds_header(line):
    parts = line.split()
    print(parts)
    print(len(parts))
    date = parts[0].strip("(")
    print(date)
    timestamp = parts[1].strip(")")
    print(timestamp)
    interface = parts[2]
    print(interface)
    can_id = int(parts[3])
    print(can_id)
    data_length = int(parts[4].strip("[]"))
    print(data_length)

    # if it is the first 04 in the CAN ID, this is the CCSDS header
    # after identifying that this is a header:
    data = parts[5:]
    print(data)
    can_layer_a = data[0] 
    can_layer_z = data[len(data)-1]
    print(can_layer_a)
    print(can_layer_z)
    ccsds_header = data[1:len(data)-1]
    ccsds_header.reverse()
    print(ccsds_header)


    first_two_bytes = ccsds_header[0:2]
    print(first_two_bytes)
    if first_two_bytes == ['18', '0A']:
        print("This is a TC for APID 10 (PF OBC A)")
    elif first_two_bytes == ['18', '0B']:
        print("This is a TC for APID 11 (PF OBC B)")
    elif first_two_bytes == ['18', '14']:
        print("This is a TC for APID 20 (COM OBC B)")
    elif first_two_bytes == ['18', '15']:
        print("This is a TC for APID 21 (COM OBC B)")
    else:
        print("Target APID unknown")

    next_two_bytes = ccsds_header[2:4]
    print(next_two_bytes)
    seq_word = int("".join(next_two_bytes), 16)         # 16-bit integer in binary in memory

    seq_flags = (seq_word >> 14) & 0b11
    print(seq_flags)
    seq_count = seq_word & 0x3FFF
    print(int(seq_count))

    last_two_bytes = ccsds_header[4:6]
    print(last_two_bytes)
    data_field_length = int("".join(last_two_bytes), 16) + 1
    print(data_field_length)

    frames_nr, remainder = divmod(data_field_length, 8)
    print(frames_nr)
    print(remainder)

