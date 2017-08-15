from utilities import secret_prefix_mac, bigendian64bitinteger, SHA1,ext32, computeMDpadding


def append_message_to_secret_prefix_mac(auth_code, attack_string, KOG_len_guess):
	h0, h1 = ext32(auth_code >> 128), ext32(auth_code >> 96)
	h2, h3, h4 = ext32(auth_code >> 64), ext32(auth_code >> 32), ext32(auth_code)
	return SHA1(attack_string,h0, h1, h2, h3, h4,KOG_len_guess)


message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
key = "YELLOW SUBMARINE"

key_len_guess = 16
auth_code = secret_prefix_mac(key,message)

glue_guess = computeMDpadding( "_"*key_len_guess + message)
KOG_len_guess = len(message) + key_len_guess + len(glue_guess)
new_auth_code = append_message_to_secret_prefix_mac(auth_code, ";admin=true", KOG_len_guess)

new_message = message + glue_guess + ";admin=true"
assert new_auth_code == secret_prefix_mac(key,new_message)

