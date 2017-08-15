from utilities import  ecb_or_cbc
from binascii import b2a_hex


def get_candidates(input_lines):
	candidates = []
	for i,line in enumerate(input_lines, start=1):
		candidates.append( {'index': i, 'cipher_text': line} )
	return candidates

input_lines = [line.strip() for line in open("8.txt", 'r')]
candidates = get_candidates(input_lines)


winners = [x for x in candidates if ecb_or_cbc(bytes.fromhex(x['cipher_text'])) == 'ecb']


print("Encode in ECB:\n")
for winner in winners:
	print("line number: ", winner['index'])
	print("Ciphertext (hex): ", winner['cipher_text'], "\n")
