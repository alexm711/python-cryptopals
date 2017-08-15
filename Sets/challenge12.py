from utilities import encryption_oracle_consistent, ecb_or_cbc


plaintext = "yellow submarine"*80

#step 1 Kept adding characters until we graduated to the next block size (in this case 144->160 after 6 chars, suggesting the initial message has 138)
encryption_oracle_consistent("AA".encode())
secret_size, blocksize = 138, 16
#step 2
ecb_or_cbc(encryption_oracle_consistent(plaintext.encode()))

#step 3/4
answer = ""
for idx in range(secret_size):
	num_pad = blocksize- (idx%blocksize+1)
	template_string = 'A'*num_pad
	one_short_cipher = encryption_oracle_consistent(template_string.encode()	)

	diction = {}
	for i in range(256):
		test_string = template_string +answer +  chr(i)
		diction[test_string] = encryption_oracle_consistent(test_string.encode())
	for key in diction:
		if one_short_cipher[:(int(idx/blocksize) + 1) * blocksize] == diction[key][:(int(idx/blocksize) + 1)* blocksize]:
			answer+= key[-1]
print(answer)			