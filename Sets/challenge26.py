from utilities import ctr, pkcs_7_pad, pkcs_7_pad_remove, split_into_blocks, fixed_xor
from os import urandom

import re

AES_key = urandom(16)
nonce = '\x00'*(int(len(AES_key)/2))

# iv = bytes([0]*len(AES_key))


# ciphertext = ctr(plaintext, key, nonce)

def encrypt(input_string):
	prepend = "comment1=cooking%20MCs;userdata="
	append = ";comment2=%20like%20a%20pound%20of%20bacon"
	input_string = re.sub('[;=]', "", input_string, count=0, flags=0)
	new_string = prepend + input_string + append
	new_string = pkcs_7_pad(new_string.encode(),16)

	return ctr(new_string, AES_key, nonce)

def is_admin(cipher_text):
	plaintext = pkcs_7_pad_remove(ctr(cipher_text, AES_key, nonce))
	print(plaintext)
	return b";admin=true;" in plaintext

def generate_false_cipher_text():
	mask = ('\x01'+ '\x00' * 5 + '\x01'+ '\x00' * 9).encode()
	string =  ":admin<true" 
	cipher_text = encrypt(string)
	new_cipher_text = bytearray()
	# target_indices = [0,6,11]
	for i, block in enumerate(split_into_blocks(cipher_text,block_size=16 )):
		if i==2:
			block = fixed_xor(block,mask)
		new_cipher_text += block
	return new_cipher_text

new_cipher_text = generate_false_cipher_text()
assert is_admin(bytes(new_cipher_text)), "Not admin"
# print(temp)