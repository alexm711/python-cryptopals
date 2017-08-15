from utilities import pkcs_7_pad_remove
strings = []
strings.append("ICE ICE BABY\x04\x04\x04\x04".encode())
# strings.append("ICE ICE BABY\x05\x05\x05\x05".encode())
strings.append("ICE ICE BABY\x01\x02\x03\x04".encode())
for string in strings:
	print(string)
	print(pkcs_7_pad_remove(string))