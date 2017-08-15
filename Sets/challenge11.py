from utilities import encryption_oracle, ecb_or_cbc

plaintext = "yellow submarine"*80

print(ecb_or_cbc(encryption_oracle(plaintext.encode())))