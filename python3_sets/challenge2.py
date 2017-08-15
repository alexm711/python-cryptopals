


a = "1c0111001f010100061a024b53535009181c"
b = "686974207468652062756c6c277320657965"
ans = "746865206b696420646f6e277420706c6179"

from utilities import fixed_xor
from binascii import a2b_hex, b2a_hex

print(b2a_hex(fixed_xor(a2b_hex(a),a2b_hex(b))).decode().strip())
print(ans.strip() )