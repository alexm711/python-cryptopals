# Recover the key from CBC with IV=Key

from utilities import aes_128_cbc_encrypt, aes_128_cbc_decrypt, pkcs_7_pad, pkcs_7_pad_remove, split_into_blocks, fixed_xor

import re
from os import urandom
AES_key = urandom(16)


def encrypt(input_string):
	prepend = "comment1=cooking%20MCs;userdata="
	append = ";comment2=%20like%20a%20pound%20of%20bacon"
	input_string = re.sub('[;=]', "", input_string, count=0, flags=0)
	new_string = prepend + input_string + append
	new_string = pkcs_7_pad(new_string.encode(),16)

	return aes_128_cbc_encrypt(AES_key, AES_key, new_string)

def decrypt(cipher_text):
	return pkcs_7_pad_remove(aes_128_cbc_decrypt(AES_key, AES_key, cipher_text) )

def ascii_compliant(cipher_text):
	plaintext = decrypt(cipher_text)
	for i, ch in enumerate(plaintext):
		if type(plaintext) is type(bytes()) or type(plaintext) is type(bytearray()):
			if not ( ch >= 32 and ch < 127):
				return plaintext
		elif type(plaintext) is str:
			if not ( ord(ch) >= 32 and ord(ch) < 127):
				return plaintext
		else:
			assert type(plaintext) is str, str(type(plaintext))
	print("ascii compliant")
	return True

def modify_ciphertext(cipher_text,block_size):
	blocks = split_into_blocks(cipher_text, block_size=block_size)
	assert len(blocks) >= 3
	return (blocks[0]) + b'\x00'*block_size + (blocks[0]) + b''.join(blocks[3:])



print("key", AES_key)
string = "hey"
block_size = 16
ct = encrypt(string)
pt = decrypt(ct)
print(string,pt)
ct_new = modify_ciphertext(ct,block_size)
pt_new = ascii_compliant(ct_new)
xor_guess = fixed_xor(pt_new[:16],pt_new[32:48] )
print("xor guess: {} \norig. key: {}".format(xor_guess,AES_key    ) )
assert xor_guess == AES_key, "Did not guess correct key"
