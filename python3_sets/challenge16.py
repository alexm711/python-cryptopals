from utilities import gen_bytes, aes_128_cbc_encrypt, aes_128_cbc_decrypt, pkcs_7_pad, pkcs_7_pad_remove, split_into_blocks, fixed_xor

import re

AES_key = gen_bytes(16)

iv = bytes([0]*len(AES_key))

def first_function(input_string):
	prepend = "comment1=cooking%20MCs;userdata="
	append = ";comment2=%20like%20a%20pound%20of%20bacon"
	input_string = re.sub('[;=]', "", input_string, count=0, flags=0)
	new_string = prepend + input_string + append
	new_string = pkcs_7_pad(new_string.encode(),16)

	return aes_128_cbc_encrypt(AES_key, iv, new_string) 

def second_function(cipher_text):
	plaintext = pkcs_7_pad_remove(aes_128_cbc_decrypt(AES_key, iv, cipher_text))
	print(plaintext)
	return b";admin=true;" in plaintext

def generate_false_cipher_text():
	mask = ('\x01'+ '\x00' * 5 + '\x01'+ '\x00' * 9).encode()
	string =  "X"*16+":admin<true" 
	cipher_text = first_function(string)
	new_cipher_text = bytearray()
	# target_indices = [0,6,11]
	for i, block in enumerate(split_into_blocks(cipher_text,block_size=16 )):
		if i==2:
			block = fixed_xor(block,mask)
		new_cipher_text += block
	return new_cipher_text

new_cipher_text = generate_false_cipher_text()
temp = second_function(bytes(new_cipher_text))

print(temp)
# = is 61 and 00111101
# < is 60 and 00111100

# ; is 59 and 00111011
# : is 58 and 00111010