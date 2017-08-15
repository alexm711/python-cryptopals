import codecs
from binascii import b2a_base64, a2b_hex
def convertHex2Base64_1(Hex):
    return codecs.encode(codecs.decode(Hex, 'hex'), 'base64').decode()
def convertHex2Base64_2(Hex):
    return b2a_base64(a2b_hex(Hex)).decode()
Hex = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
ans = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
print(convertHex2Base64_1(Hex).strip() == ans.strip())
print(convertHex2Base64_2(Hex).strip() == ans.strip())

