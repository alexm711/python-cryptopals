
from base64 import b64decode
from utilities import aes_128_cbc_encrypt, aes_128_cbc_decrypt


ciphertext = b64decode(open('10.txt', 'r').read())
key = b'YELLOW SUBMARINE'
iv = bytes([0]*len(key))

plaintext = aes_128_cbc_decrypt(key, iv, ciphertext)
ciphertext = aes_128_cbc_encrypt(key, iv, plaintext)
plaintext = aes_128_cbc_decrypt(key, iv, ciphertext)
# print(iv,key)
print(plaintext.decode())




