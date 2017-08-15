from base64 import b64decode
from utilities import ctr

ciphertext = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
key="YELLOW SUBMARINE"
nonce = '\x00'*(int(len(key)/2))

plaintext = ctr(ciphertext, key, nonce)
print(plaintext)
ciphertext = ctr(plaintext, key, nonce)
plaintext = ctr(ciphertext, key, nonce)
print(plaintext)

Code = "Hey, how ya doing?".encode()
print(Code)
ciphertext = ctr(Code, key, nonce)
Code = ctr(ciphertext, key, nonce)
print(Code)
