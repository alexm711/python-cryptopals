

#Break fixed-nonce CTR mode using substitutions
from base64 import b64decode
from os import urandom
from utilities import ctr, single_byte_xor_cypher, fixed_xor, get_key_w_statistical_xor, decode_w_key_guess


plaintexts = [b64decode(line.strip()) for line in open('19.txt','r')]
AES_key = urandom(16)
nonce = '\x00'*(int(len(AES_key)/2))

ciphertexts = [ ctr(pt, AES_key, nonce) for pt in plaintexts]


key = get_key_w_statistical_xor(ciphertexts)
plaintext_list = decode_w_key_guess(ciphertexts,key,0)
print( '\n'.join( pt.decode() for pt in plaintext_list))
# print("       ")
# currkey = key[31]
# base = currkey ^ ord('e')
# key[31] = base ^ ord('d')
