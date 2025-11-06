
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


def build_packet_id(apid: int, version=0, pkt_type=1, shflag=1) -> bytes:
    """ Build the first two bytes (Packet ID field) of the CCSDS primary header """
    # compose 16-bit value
    packet_id = ((version & 0x7) << 13) | ((pkt_type & 0x1) << 12) | ((shflag & 0x1) << 11) | (apid & 0x7FF)
    
    byte_packet_id = packet_id.to_bytes(2, byteorder="big")
    return byte_packet_id

packet_id = build_packet_id(apid=10)
print(packet_id)                # b'\x18\n'
print(f"Hex: {packet_id.hex().upper()}")  # '180A'
print(f"Bits: {packet_id[0]:08b} {packet_id[1]:08b}")


def build_seq_control(seqflags=3,seqcount=0) -> bytes:   # for raw TC sent by YAMCS no seq count needed for now
    seq_control = ((seqflags & 0x3) << 14) | (seqcount & 0x3FFF)

    byte_seq_control = seq_control.to_bytes(2, byteorder="big")
    return byte_seq_control

seq_control = build_seq_control()
print(seq_control)
print(f"Hex: {seq_control.hex().upper()}")  
print(f"Bits: {seq_control[0]:08b} {seq_control[1]:08b}")

def build_pck_length(pck_length=0) -> bytes:
    pck_length = (pck_length & 0xFFFF)
    print(pck_length)

    byte_pck_length = pck_length.to_bytes(2, byteorder="big")
    return byte_pck_length

pck_length = build_pck_length()
print(pck_length)
print(f"Hex: {pck_length.hex().upper()}")
print(f"Bits: {pck_length[0]:08b} {pck_length[1]:08b}")

def create_ccsds_header(packet_id,seq_control,pck_length) -> bytes:
    return packet_id + seq_control + pck_length

header = create_ccsds_header(packet_id, seq_control, pck_length)

print(header.hex().upper())
print(len(header))


def create_secondary_header(pus_type: int,pus_stype: int, pus_version=2,pus_ackflags=0xF,pus_source_id=0) -> bytes:
    first_byte = ((pus_version & 0x0F) << 4) | (pus_ackflags & 0x0F)

    header = bytes([
        first_byte,
        pus_type & 0xFF,
        pus_stype & 0xFF,
    ])
    header += pus_source_id.to_bytes(2, "big")
    return header

sec_header = create_secondary_header(pus_type=17,pus_stype=1)
print(sec_header.hex().upper())
print("Bits:",f"{sec_header[0]:08b}")


def build_complete_header(header: bytes, sec_header: bytes):
    
    return header + sec_header

compl_header = build_complete_header(header,sec_header)
print(compl_header)
print(compl_header.hex().upper())
print(len(compl_header))


