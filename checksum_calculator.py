import binascii
data = bytes.fromhex("180ac00000062f11010000")
crc = binascii.crc_hqx(data, 0xFFFF)
print(hex(crc))



#180AC00F001A01000A00000012180AC00F00062F11010000345B