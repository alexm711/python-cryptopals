# Break fixed-nonce CTR statistically
from base64 import b64decode
from os import urandom
from utilities import ctr, xor_guess_repeated_multikey, fixed_xor, decode_w_key_guess, get_key_w_statistical_xor


plaintexts = [b64decode(line.strip()) for line in open('20.txt','r')]
AES_key = urandom(16)
nonce = '\x00'*(int(len(AES_key)/2))

ciphertexts = [ ctr(pt, AES_key, nonce) for pt in plaintexts]

def get_short_key_w_statistical_xor(ciphertexts):
	min_cipher_length = len(min(ciphertexts, key= lambda x: len(x)))

	concat_ciphertext = b''.join([   ct[:min_cipher_length]  for ct in ciphertexts])

	keysize = min_cipher_length
	key = xor_guess_repeated_multikey(concat_ciphertext,keysize)
	assert len(key) == min_cipher_length
	return key

key1 = get_key_w_statistical_xor(ciphertexts)


key2 = get_short_key_w_statistical_xor(ciphertexts)

plaintext_list1 = decode_w_key_guess(ciphertexts,key1)
plaintext_list2 = decode_w_key_guess(ciphertexts,key2)
print( '\n'.join( pt.decode() for pt in plaintext_list1))
print("____________")
print( '\n'.join( pt.decode() for pt in plaintext_list2))