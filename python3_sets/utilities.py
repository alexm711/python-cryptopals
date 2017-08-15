
#challenge 1.2
from binascii import a2b_hex, b2a_hex
def fixed_xor(bytes1,bytes2):
	return bytes([A^B for A,B in zip(bytes1,bytes2 ) ])

#challenge 1.3
from operator import itemgetter
# character_freqs = {'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29, 'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07}
character_frequency = {
    'e': 27,
    't': 26,
    'a': 25,
    'o': 24,
    'i': 23,
    'n': 22,
    's': 21,
    'r': 20,
    'h': 19,
    'l': 18,
    'd': 17,
    'c': 16,
    'u': 15,
    'm': 14,
    'f': 13,
    'p': 12,
    'g': 11,
    'w': 10,
    'y': 9,
    'b': 8,
    'v': 7,
    'k': 6,
    'x': 5,
    ' ': 4,
    'j': 3,
    'q': 2,
    'z': 1
}


def score_text(text_binary):
	return sum([character_frequency.get(chr(asc),0) for asc in  text_binary])	

def single_byte_xor(input_bytes, ascii_code):
    return bytearray( byte ^ ascii_code  for byte in input_bytes   )


def single_byte_xor_cypher(ciphertext):
	candidates = []

	for key_candidate in range(256):
		total_score = 0.0
		text_binary = single_byte_xor(ciphertext, key_candidate)
		char_score = score_text(text_binary)

		result = {
		'key': key_candidate,
		'score': char_score,
		'text_binary': text_binary
		}

		candidates.append(result)

	result = max(candidates, key=itemgetter('score'))
	return  result

# challenge 5
def repeating_xor_in_binary(input_bytes, binary_key):
	length =  len(binary_key)
	return bytearray( byte ^ binary_key[i%length]  for i, byte in enumerate(input_bytes)   )

# challenge 6
from itertools import combinations

def count1s(x):
    return bin(x).count('1')

# input 2 bytes objects
def hamming_distance(A,B):
	return sum([count1s(a^b ) for a,b in zip(A,B)])


def xor_guess_repeated_multikey(ciphertext,keysize=None):
	def normalized_sample_hamming_distance(keysize, samples=4):
		total_dist=0
		combos = list(combinations(range(samples),2))
		for x,y in combos:
			total_dist+= hamming_distance(ciphertext[keysize*x:keysize*(x+1)],  ciphertext[keysize*y:keysize*(y+1)])
			
		normalized_score = total_dist / (keysize*len(combos))
		return normalized_score


	def guess_keysize():
		candidates = []
		for keysize in range(2,41):
			candidates.append( {'keysize': keysize, 'norm_dist': normalized_sample_hamming_distance(keysize)} )

		return min(candidates, key=itemgetter('norm_dist'))['keysize']
	if keysize is None:	
		keysize = guess_keysize()
	# the ith character in the key only interacts with every keysize-th character in the cyphertext, starting from index i
	return bytearray([  single_byte_xor_cypher( ciphertext[i::keysize]    )['key']  	for i in range(keysize)] )

#challenge 7

#challenge 8

def split_into_blocks(input, block_size):
    return [ input[i:i+block_size]  for i in range(0, len(input), block_size) ]

def ecb_or_cbc(ciphertext):
    # Repeating blocks suggests ecb encoding
    blocks = split_into_blocks(ciphertext, block_size=16)
    for block in set(blocks):
        if blocks.count(block) > 1:
            return 'repeats: ecb'
    return 'no detectable repeats so probably: cbc' 

#challenge 9
def pkcs_7_pad(plaintext,length):
	assert length >1 and length < 256
	num_padding = length-(len(plaintext)%length)
	return plaintext + (num_padding * bytes([num_padding]))

def pkcs_7_pad_remove(plaintext):
	#instance(x,(bytes))
	num_padding = plaintext[-1]
	padding = (num_padding * bytes([num_padding]))
	assert padding == plaintext[-num_padding:], "Improper padding"
	return plaintext[:-num_padding]


#challenge 10
from Crypto.Cipher import AES


def aes_128_ebc_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)
 


def aes_128_cbc_encrypt(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)

    ciphertext = bytearray()
    ciphertext_block = iv

    for block in split_into_blocks(plaintext, block_size=16):
        ciphertext_block = cipher.encrypt(fixed_xor(block, ciphertext_block))
        ciphertext+=ciphertext_block

    return bytes(ciphertext)

def aes_128_cbc_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)

    plaintext = bytearray()
    prevblock = iv

    for block in split_into_blocks(ciphertext, block_size=16):
        plaintext += fixed_xor(cipher.decrypt(block), prevblock)
        prevblock = block

    return bytes(plaintext)

#challenge 11
from random import randint, choice
from os import urandom
def gen_bytes(num_bytes):
	# return bytes([randint(0,255) for p in range(num_bytes)])
	return urandom(num_bytes)

def append_bytes(plaintext):
	return gen_bytes(randint(5,10)) + plaintext + gen_bytes(randint(5,10))

def encryption_oracle(plaintext):
	key = gen_bytes(16)
	plaintext_appended = pkcs_7_pad(append_bytes(plaintext),16)
	if choice([True, False]):
		iv = gen_bytes(16)
		print('oracle uses cbc')
		return aes_128_cbc_encrypt(key, iv, plaintext_appended)
	else:
		print('oracle uses ebc')
		return aes_128_ebc_encrypt(key, plaintext_appended)


# challenge 12
from base64 import b64decode

global_key = b'\xfa\xbbl\xbb\xadR\xdb~F\xb4=\xb4\xa5\x1aFZ'
global_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\n\
						aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\n\
						dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\nYnkK"


def encryption_oracle_consistent(plaintext):
	plaintext_appended = pkcs_7_pad(plaintext+b64decode(global_string),16)
	return aes_128_ebc_encrypt(global_key, plaintext_appended)

#challenge 13
def kv_parse(string):
	tokens = string.split('&')
	dictionary = {}
	for token in tokens:
		assert  len(token.split('='))==2, "kv string not formatted correctly"
		key, value = token.split('=')
		dictionary[key] = value
	return dictionary

def kv_parse_reverse(dictionary):
	string = ""
	for key in dictionary:
		string+= key + "=" + dictionary[key] + "&"
	return string[:-1]


def email_formated(email):
	if len(email.split('@'))!=2:
		return False
	if len(email.split('@')[1].split('.'))!=2:
		return False
	return True


profiles = {}
import re

def profile_for(string):
	emailaddress = re.sub('[&=]', "", string, count=0, flags=0)
	assert email_formated(emailaddress), "email not formatted correctly"
	uid = 79     #I don't think this matter atm
	tempdict = {'email': emailaddress, 'uid': str(uid), 'role': "user"}
	return kv_parse_reverse(tempdict)

secret_key = gen_bytes(16)

def encrypt_user(string):
	cipher = AES.new(secret_key, AES.MODE_ECB)
	return cipher.encrypt(pkcs_7_pad(string.encode(),16))

def decrypt_user(ciphertext):
	cipher = AES.new(secret_key, AES.MODE_ECB)
	plaintext = pkcs_7_pad_remove( cipher.decrypt(ciphertext))
	return plaintext

# Challenge 14
def encryption_oracle_consistent_w_prepend(plaintext):
	plaintext_appended = pkcs_7_pad(gen_bytes(randint(16,16)) + plaintext+b64decode(global_string),16)
	return aes_128_ebc_encrypt(global_key, plaintext_appended)

# Challenge 18

import math
def int2str(x, nbytes):
	# little endian
	assert(x < 256 ** nbytes)
	string = ""
	for bytenum in range(nbytes):
		string = string + chr( (x >> (8 * bytenum)) % 256)
	return	string
    # little means least significant BYTE first.
	# return   ''.join([chr( (x >> (8 * bytenum))% 256 ) for bytenum in range(nbytes)])

def ctr(text, key, nonce):
    cipher = AES.new(key, AES.MODE_ECB)
    keystream = b''
    bs = len(key)
    n_blocks = math.ceil(len(text) / bs)
    # print(n_blocks)
    for i in range(n_blocks):
        counter = int2str(i, bs - len(nonce)) 
        # print(i,len(counter),len(nonce),counter.encode(),nonce.encode())
        # print(len(nonce + counter),(nonce + counter).encode()[:16])
        # print(len(nonce + counter),(nonce + counter).encode())
        keystream = keystream + cipher.encrypt((nonce.encode() + counter.encode())[:16])

    return fixed_xor(keystream,text)

# challenge 19
def get_key_w_statistical_xor(ciphertexts):
	max_cipher_length = len(max(ciphertexts, key= lambda x: len(x)))
	key = bytearray()
	for i in range(max_cipher_length):
		cross_section = bytearray()
		for ct in ciphertexts:
			if i < len(ct):
				cross_section.append(ct[i])
		candidate = single_byte_xor_cypher(cross_section)
		key.append(candidate["key"])
	return key

def decode_w_key_guess(ciphertexts,key, min_length=0):
	plaintext_list = []
	for ct in ciphertexts:
		temp = fixed_xor(ct[:len(key)],key[:len(ct)])
		if len(ct) >= min_length:
			plaintext_list.append(temp)
	return plaintext_list


# Challenge 21
# Credit to wikipedia
w, n, m, r = 32, 624, 397, 31
a = 0x9908B0DF 
(s, b) = (7, 0x9D2C5680)
(t, c) = (15, 0xEFC60000)

(u, d) = (11, 0xFFFFFFFF)
l = 18
f = 1812433253 #hex(1812433253) = '0x6c078965'

def _int32(x):
    # Get the 32 least significant bits.
    return int(d & x)

class MT19937:

    def __init__(self, seed):
        # Initialize the index to 0
        self.index = n
        assert type(seed) is int or type(seed) is list, "Seed is not int or list"
        if type(seed) is int:
            self.mt = [0] * n
            self.mt[0] = seed  # Initialize the initial state to the seed
            for i in range(1, n):
                self.mt[i] = _int32(
                    f * (self.mt[i - 1] ^ self.mt[i - 1] >> (w-2)) + i)
        else:
            assert len(seed) == n, "Seed length not n"
            for i in range(n):
                assert type(seed[i]) is int, "elem at idx {} is not an integer".format(i)
            self.mt = seed


    def extract_number(self):
        if self.index >= n:
            self.twist()

        y = self.mt[self.index]

        # Right shift by 11 bits
        y = y ^ y >> u & d
        # Shift y left by 7 and take the bitwise and of b = 2636928640
        y = y ^ y << s & b
        # Shift y left by 15 and take the bitwise and of y and  c = 4022730752
        y = y ^ y << t & c
        # Right shift by 18 bits
        y = y ^ y >> l

        self.index = self.index + 1

        return _int32(y)

    def twist(self):
        for i in range(n):
            # Get the most significant bit and add it to the less significant
            # bits of the next number
            y = _int32((self.mt[i] & 0x80000000) +
                       (self.mt[(i + 1) % n] & 0x7fffffff))
            self.mt[i] = self.mt[(i + m) % n] ^ y >> 1

            if y % 2 != 0:
                self.mt[i] = self.mt[i] ^ a
        self.index = 0
        #test
# Challenge 28
def bigendian64bitinteger(integer):
	return ''.join(chr((integer >> (56-8*i)) & 0xff )  for i in range(8) )

def computeMDpadding(message,prior_len=0):
	ml = len(message)*8
	padding = '\x80'

	currlen = ((ml+8)% 512)
	k = 448 - currlen if currlen < 448 else 448 + (512-currlen)
	# k_bytes = int(k/8)
	padding += '\x00'*int(k/8) + bigendian64bitinteger( ml+8*prior_len)

	assert len(message+padding) % int(512/8) == 0, len(message)

	return padding


# Rotate left: 0b1001 --> 0b0011
def rol(val, r_bits, max_bits):
	assert r_bits < max_bits
	mask = (2**max_bits-1)
	return (val << r_bits) & mask | \
	((val & mask) >> (max_bits-(r_bits)))
 

def get_words(chunk):
	words = [str_2_big_endian_int(chunk[i*4 : (i+1)*4]) for i in range(16)]
	for i in range(16,80):
		newword = rol( (words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16]) , 1, 32)
		words.append(newword)
	return words


def ext32(integer):
	return integer & 0xffffffff

# This function assumes big endian.
def str_2_big_endian_int(s):
    assert 0 < len(s) <= 4
    return sum( ord(char) << (i*8) for i,char in enumerate(s[::-1])   )

def SHA1(message, h0= 0x67452301, h1= 0xEFCDAB89,h2= 0x98BADCFE,
			h3 =0x10325476,h4 =0xC3D2E1F0, prior_len = 0):
	# h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
	message += computeMDpadding(message,prior_len)
	num_chunks = int(len(message)/64 )
	chunks = [message[ 64*i : 64*(i+1)] for i in range(num_chunks)]
	for chunk in chunks:
		w = get_words(chunk)
		a,b,c,d,e = h0, h1, h2, h3, h4
		#main loop
		for i in range(80):
			if i < 20:
				f = (b & c) | ((b ^ 0xffffffff) & d)
				k = 0x5A827999
			elif 20 <= i < 40:
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			elif 40 <= i < 60:
				f = (b & c) | (b & d) | (c & d) 
				k = 0x8F1BBCDC
			elif 60 <= i  < 80:
				f = b ^ c ^ d
				k = 0xCA62C1D6

			temp = rol(a, 5, 32) + f + e + k + w[i]
			a,b,c,d,e = ext32(temp), ext32(a), ext32(rol(b,30,32)), ext32(c), ext32(d)

		#main loop done
		h0, h1, h2, h3, h4 = ext32(h0 + a), ext32(h1 + b), ext32(h2 + c), ext32(h3 + d), ext32(h4 + e) 

	hh = (ext32(h0) << 128) | (ext32(h1) << 96) | (ext32(h2) << 64) | (ext32(h3) << 32) | ext32(h4)
	return hh

assert SHA1("") == 0xda39a3ee5e6b4b0d3255bfef95601890afd80709, SHA1("")
assert SHA1("The quick brown fox jumps over the lazy cog") == 0xde9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3, SHA1("The quick brown fox jumps over the lazy cog") 
assert SHA1("The quick brown fox jumps over the lazy dog") == 0x2fd4e1c67a2d28fced849ee1bb76e7391b93eb12, SHA1("The quick brown fox jumps over the lazy dog")

def secret_prefix_mac(key,message):
    return SHA1(key + message)

# Challenge30
# def MD4(messageh0= 0x67452301, h1= 0xEFCDAB89,h2= 0x98BADCFE,
# 			h3 =0x10325476, prior_len = 0):


# assert MD4("") == 0x31d6cfe0d16ae931b73c59d7e0c089c0, MD4("")
# assert MD4("The quick brown fox jumps over the lazy cog") == 0xb86e130ce7028da59e672d56ad0113df, MD4("The quick brown fox jumps over the lazy cog") 
# assert MD4("The quick brown fox jumps over the lazy dog") == 0x1bee69a46ba811185c194762abaeae90, MD4("The quick brown fox jumps over the lazy dog")


