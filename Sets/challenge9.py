
from utilities import  pkcs_7_pad

string = "YELLOW SUBMARINE"
testans  = b'YELLOW SUBMARINE\x04\x04\x04\x04'

print(pkcs_7_pad(string.encode(),20) )
print(testans)
