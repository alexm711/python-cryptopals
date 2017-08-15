from random import  choice

from utilities import aes_128_cbc_encrypt, aes_128_cbc_decrypt, pkcs_7_pad,pkcs_7_pad_remove, split_into_blocks, fixed_xor
import pdb
from os import urandom

AES_key = urandom(16)

strings = [line.strip().encode() for line in open('17.txt','r')]
def first_func():
	string =  choice(strings)
	iv = bytes([0]*len(AES_key))
	string = pkcs_7_pad(string,16)
	return aes_128_cbc_encrypt(AES_key, iv, string), iv

def correct_padding(cipher_text):
	plaintext = aes_128_cbc_decrypt(AES_key, iv, cipher_text)
	num_padding = plaintext[-1]
	padding = (num_padding * bytes([num_padding]))
	return padding == plaintext[-num_padding:]


def getIntermediate(C1,C2,prepend):
	I2 = bytearray()
	for iByte in range(15,-1,-1):
		num_padding = 16-iByte
		while len(I2) + iByte != 16:
			C1prime = bytearray(urandom(16))
			for i,I2_byte in enumerate(I2,1):
				C1prime[-i] = I2_byte ^ num_padding
			for byte in range(256):
				C1prime[iByte] = byte
				if correct_padding(prepend + bytes(C1prime)+C2):
					I2.append(byte ^ num_padding )
					break
	return bytes(reversed(I2))


def decrypt(cipher_text,iv):
	blocks = [iv]+split_into_blocks(cipher_text,16)
	num_blocks = len(blocks)
	plaintext = []
	for b_idx in reversed(range(1,num_blocks)):
		C1, C2 = blocks[b_idx-1], blocks[b_idx]
		prepend = bytearray()
		for i in range(b_idx-1):
			prepend+=blocks[i]
		assert len(prepend) + (2+len(plaintext))*len(C2) == len(cipher_text) + len(iv)  
		Int = getIntermediate(C1, C2, bytes(prepend ))
		plaintext.append(fixed_xor(Int,C1 ) )
	plaintext = b''.join([x for x in plaintext[::-1] ])
	return pkcs_7_pad_remove(plaintext).decode()


cipher_text, iv = first_func()
print(correct_padding(cipher_text))

print(decrypt(cipher_text,iv))
