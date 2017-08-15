

from base64 import b64decode
from os import urandom
from utilities import ctr, fixed_xor
from Crypto.Cipher import AES

ecb_encrypted = b64decode(open('25.txt','r').read())

plaintext = AES.new("YELLOW SUBMARINE", AES.MODE_ECB).decrypt(ecb_encrypted)

key = urandom(16)
nonce = '\x00'*(int(len(key)/2))

ciphertext = ctr(plaintext, key, nonce)
assert plaintext ==  ctr(ciphertext, key, nonce) 



def edit(ciphertext, key, nonce, offset, newtext):
	assert offset>=0 and offset + len(newtext) <= len(ciphertext)
	plaintext = ctr(ciphertext, key, nonce)
	return ctr(plaintext[:offset] + newtext + plaintext[offset+len(newtext):], key, nonce)

def edit_pub(ciphertext,offset,newtext):
	return edit(ciphertext, key, nonce, offset, newtext)


def break_using_edit(ciphertext):
	keystream = edit_pub(ciphertext, 0, b'\x00'*len(ciphertext))
	return fixed_xor(keystream,ciphertext[:len(keystream)])


assert break_using_edit(ciphertext) == plaintext
