current_tc = None
current_tm = None

previous_info = None

tc_frames_left = 0
tm_frames_left = 0

tcs_grouped = []
tms_grouped = []

decoded_tcs = []
decoded_tms = []


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
        return frames_nr
    else: 
        frames_nr, remainder = divmod(data_field_length, 8)
        if remainder != 0:
            frames_nr += 1
    return frames_nr
    
def is_tm_header(info, previous_info=None):
    if not info["can_id"].startswith("08"):
        return 0
    if info["data_length"] != 8:
        return 0
    if previous_info and previous_info["can_id"].startswith("04"):
        if info["data"] == previous_info["data"]:
            return 0
    parts = line.split()
    data = parts[5:]
    ccsds_header = data[1:len(data)-1]
    ccsds_header.reverse()
    #print(f"The TM CCSDS header is: {ccsds_header}")
    last_two_bytes = ccsds_header[4:6]
    data_field_length = int("".join(last_two_bytes), 16) + 1
    #print(f"The Data field length of the following TM is: {data_field_length} bytes")
    if data_field_length <= 8:
        frames_nr = 1
        return frames_nr
    else:
        frames_nr, remainder = divmod(data_field_length, 8)
        if remainder != 0:
            frames_nr += 1
        return frames_nr

def decode_apid(tc):
    data = tc["header"]["data"]
    ccsds_header = data[1:len(data)-1]
    ccsds_header.reverse()
    if len(data) < 2:
        return None
    first_two_bytes = int("".join(ccsds_header[0:2]), 16)
    apid = first_two_bytes & 0x07FF   # keep the last 11 bits
    return apid  


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
        if tc_frames_left > 0 and info["can_id"].startswith("04"):
            current_tc["frames"].append(info)
            tc_frames_left -= 1
            if tc_frames_left == 0:
                tcs_grouped.append(current_tc)
                pus_info = decode_pus_secondary_header(current_tc)
                if pus_info:
                    apid = decode_apid(current_tc)
                    decoded_tcs.append({
                        "time": current_tc["start_time"],
                        "type": pus_info["type"],
                        "subtype": pus_info["subtype"],
                        "frames": len(current_tc["frames"]),
                        "apid": apid,
                    })
                    print(f"→ TC[{pus_info['type']},{pus_info['subtype']}] to APID {apid} at {current_tc['start_time']}")


                current_tc = None
            previous_info = info
            continue
        
        if tm_frames_left > 0 and info["can_id"].startswith("08"):
            current_tm["frames"].append(info)
            tm_frames_left -= 1
            if tm_frames_left == 0:
                tms_grouped.append(current_tm)
                pus_info = decode_pus_secondary_header(current_tm)
                if pus_info:
                    apid = decode_apid(current_tm)
                    decoded_tms.append({
                        "time": current_tm["start_time"],
                        "type": pus_info["type"],
                        "subtype": pus_info["subtype"],
                        "frames": len(current_tm["frames"]),
                        "apid": apid,
                    })
                    print(f"→ TM[{pus_info['type']},{pus_info['subtype']}] to APID {apid} at {current_tm['start_time']}")
                
                current_tm = None
            previous_info = info
            continue

        # === CASE 2: check if new header ===
        tc_frames_nr = is_tc_header(info, previous_info)
        if tc_frames_nr:
            #print("TC header found:", info["can_id"], info["data"])
            tc_frames_left = tc_frames_nr
            current_tc = {
                "start_time": info["timestamp"],
                "header": info,
                "frames": [info]
            }
        else:       # if not TC header, check if it is a TM header
            tm_frames_nr = is_tm_header(info, previous_info)
            if tm_frames_nr:
                #print("TM header found:", info["can_id"], info["data"])
                tm_frames_left = tm_frames_nr
                current_tm = {
                    "start_time": info["timestamp"],
                    "header": info,
                    "frames": [info]
                }

             
        

        previous_info = info

    print("\n=== Summary of TCs ===")
    for i, tc in enumerate(decoded_tcs, start=1):
        print(f"{i:02d} | {tc['time']} | TC[{tc['type']},{tc['subtype']}] | {tc['frames']} frames")
    print(f"Total TCs found: {len(decoded_tcs)}")

    print("\n=== Summary of TMs ===")
    for i, tc in enumerate(decoded_tms, start=1):
        print(f"{i:02d} | {tc['time']} | TM[{tc['type']},{tc['subtype']}] | {tc['frames']} frames")
    print(f"Total TMs found: {len(decoded_tms)}")