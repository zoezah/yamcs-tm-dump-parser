import binascii
data = bytes.fromhex("180ac00200062f11010000")
crc = binascii.crc_hqx(data, 0xFFFF)
print(hex(crc))
