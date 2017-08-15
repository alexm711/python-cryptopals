from binascii import a2b_hex
from utilities import single_byte_xor_cypher
from operator import itemgetter

lines = open("4.txt", 'r')

candidates = []
for i,line in enumerate(lines):
	ciphertext = bytes.fromhex(line.strip())
	result = single_byte_xor_cypher(ciphertext)
	result["line_num"] = i
	candidates.append(result)
result = max(candidates, key=itemgetter('score'))
print(result)