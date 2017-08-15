
from utilities import single_byte_xor_cypher
hex_input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"


ciphertext = bytes.fromhex(hex_input)

result = single_byte_xor_cypher(ciphertext)

print("The key is {} and the message is {}".format(result['key'],result['text_binary'].decode("UTF-8")))