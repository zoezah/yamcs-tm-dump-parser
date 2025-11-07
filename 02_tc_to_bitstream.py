import binascii
def calc_checksum(TC: bytes) -> bytes:
    crc = binascii.crc_hqx(TC, 0xFFFF)
    return crc.to_bytes(2, "big")

def build_packet_id(apid: int, version=0, pkt_type=1, shflag=1) -> bytes:
    """ Build the first two bytes (Packet ID field) of the CCSDS primary header """
    # compose 16-bit value
    packet_id = ((version & 0x7) << 13) | ((pkt_type & 0x1) << 12) | ((shflag & 0x1) << 11) | (apid & 0x7FF)
    
    byte_packet_id = packet_id.to_bytes(2, byteorder="big")
    return byte_packet_id

def build_seq_control(seqflags=3,seqcount=0) -> bytes:   # for raw TC sent by YAMCS no seq count needed for now
    seq_control = ((seqflags & 0x3) << 14) | (seqcount & 0x3FFF)

    byte_seq_control = seq_control.to_bytes(2, byteorder="big")
    return byte_seq_control

def build_packet_length(packet_length=0) -> bytes: 
    packet_length = (packet_length & 0xFFFF)
    print(packet_length)

    byte_packet_length = packet_length.to_bytes(2, byteorder="big")
    return byte_packet_length

def create_ccsds_header(packet_id,seq_control,pck_length) -> bytes:
    return packet_id + seq_control + pck_length


def create_secondary_header(pus_type: int,pus_stype: int, pus_version=2,pus_ackflags=0xF,pus_source_id=0) -> bytes:
    first_byte = ((pus_version & 0x0F) << 4) | (pus_ackflags & 0x0F)

    sec_header = bytes([
        first_byte,
        pus_type & 0xFF,
        pus_stype & 0xFF,
    ])
    sec_header += pus_source_id.to_bytes(2, "big")
    return sec_header

def build_complete_header(header: bytes, sec_header: bytes):
    return header + sec_header



# build 19,1
def calculate_n_byte(n:int) -> bytes:
    n_byte = bytes([n & 0xFF])
    return n_byte

def create_apid_field(apid: int, spare=0) -> bytes:
    val = ((spare & 0x1F) << 11) | (apid & 0x7FF)
    apid_field = val.to_bytes(2, "big")
    return apid_field

def create_eid_bytes(event_id: int) -> bytes:
    eid_bytes = event_id.to_bytes(4, "big")
    return eid_bytes

def build_tc_19_1(apid:int, event_id: int, n: int = 1, spare: int = 0) -> bytes:
    """ Build the complete TC[19,1]"""
    # build primary header
    packet_id = build_packet_id(apid)
    seq_control = build_seq_control()
    packet_length = build_packet_length()
    header = create_ccsds_header(packet_id, seq_control, packet_length)

    # build secondary header
    sec_header = create_secondary_header(pus_type=19,pus_stype=1)

    # build inner TC -> currently only a string, has to be adapted
    inner_tc = "180AC00F00062F11010000345B"
    inner_bytes = bytes.fromhex(inner_tc)

    # create final TC
    compl_header = build_complete_header(header, sec_header)
    n_byte = calculate_n_byte(n)
    apid_field = create_apid_field(apid, spare)
    eid_bytes = create_eid_bytes(event_id)

    return compl_header + n_byte + apid_field + eid_bytes + inner_bytes

tc_19_1 = build_tc_19_1(apid=10,event_id=1)
print(tc_19_1.hex().upper())