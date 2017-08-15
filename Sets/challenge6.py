

from utilities import hamming_distance, repeating_xor_in_binary, xor_guess_repeated_multikey
from base64 import b64decode



t1 = "this is a test"
t2 = "wokka wokka!!!"
print("This hamming distance test should yield 37: {}".format(hamming_distance(t1.encode(),t2.encode())))


ciphertext = b64decode(open('6.txt', 'r').read())

key_bytes = xor_guess_repeated_multikey(ciphertext)

text_binary = repeating_xor_in_binary(ciphertext,key_bytes)


print("Key: {} \n\nMessage excerpt: {}".format(str(key_bytes,'utf-8'), str(text_binary[:200],'utf-8') ))

