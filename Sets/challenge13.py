from utilities import kv_parse,kv_parse_reverse, profile_for,encrypt_user, decrypt_user

test1 = "foo=bar&baz=qux&zap=zazzle"


assert test1 == kv_parse_reverse(kv_parse(test1))

emailtest = "foo@bar.com"
result = profile_for(emailtest)

assert profile_for(emailtest) ==  "email=foo@bar.com&uid=79&role=user"
assert result == decrypt_user(encrypt_user(result)).decode()

input1 = 'XXXXXXXXXXadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b@bar.com' #26  10 -  5 - 11  - comply with email standard
input2 = "fools@bar.com"   # 13 + 16(x) because we need everything up to "role=" to be the last chars in a block

ciphertext1, ciphertext2 = encrypt_user(profile_for(input1)), encrypt_user(profile_for(input2))

# By rearranging the ciphertext, Mallory can influence the resulting plaintext.
attack_ciphertext = ciphertext2[0:32] + ciphertext1[16:32]

# Creating a profile from the modified ciphertext
print(decrypt_user(attack_ciphertext))
