
from base64 import b64decode
from Crypto.Cipher import AES

cipher = AES.new(b'YELLOW SUBMARINE', AES.MODE_ECB)

ciphertext = b64decode(open('7.txt', 'r').read())

text = cipher.decrypt(ciphertext)


print("Excerpt: \n{}".format(text[:242].decode("utf-8")))