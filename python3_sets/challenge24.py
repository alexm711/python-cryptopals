# Create the MT19937 stream cipher and break it
from utilities import MT19937, fixed_xor
from binascii import b2a_hex
from os import urandom
from random import randint
from time import time


def constructPlaintext(known):
	unknown = urandom(randint(1,10))
	return  unknown + known

def trivial_stream_cipher(text,key,numbits):
	assert key < 2**numbits
	r = MT19937(key)
	output = bytearray()
	num = r.extract_number()
	for char in text:
		if num == 0:
			num = r.extract_number()
		keystream_char = num & 0xff
		num = num>>8
		output.append(keystream_char^char)
	return bytes(output)

numbits = 16
seedkey = int(b2a_hex(urandom(int(numbits/8))),16)
knownendtext = b'A'*14
plaintext = constructPlaintext(knownendtext)
ciphertext = trivial_stream_cipher(plaintext,seedkey,numbits)

assert plaintext == trivial_stream_cipher(ciphertext,seedkey,numbits)

def pw_reset_token():
		r = MT19937(time())
		return r.extract_number()
#Brute force
def brute_force_2byte_key(ciphertext,knownendtext,numbits):
	for key in range(2**numbits):
		pt = trivial_stream_cipher(ciphertext,key,numbits)
		if pt[-len(knownendtext):] == knownendtext:
			return key
	assert False, "Did not find key"



print("Orig key {} and brute force key {}".format(seedkey,brute_force_2byte_key(ciphertext,knownendtext, numbits)))

