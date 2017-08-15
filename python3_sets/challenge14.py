from utilities import encryption_oracle_consistent_w_prepend, gen_bytes

secret_size, blocksize = 138, 16

def get_test_block_cipher(plaintext):
	while True:
		temp_cipher = encryption_oracle_consistent_w_prepend(2*plaintext)
		if temp_cipher[16:32] == temp_cipher[32:48]:
			return temp_cipher[16:32]

class get_usable_encrypt():
	def __init__(self, test_block, test_block_cipher):
		self.test_block = test_block
		self.test_block_cipher = test_block_cipher
	def get(self, plaintext):
		while True:
			temp_cipher = encryption_oracle_consistent_w_prepend(self.test_block+plaintext)
			if temp_cipher[16:32] == self.test_block_cipher:
				return temp_cipher[32:]


def break_oracle_w_prepend(secret_size,blocksize): 
	test_block = gen_bytes(16)
	test_block_cipher = get_test_block_cipher(test_block)
	func = get_usable_encrypt(test_block, test_block_cipher)
	answer = ""
	for idx in range(secret_size):
		num_pad, idx_after_block = blocksize - (idx%blocksize+1),  (int(idx/blocksize) + 1) * blocksize 
		template_string = 'A'*num_pad
		one_short_cipher = func.get(template_string.encode())

		diction = {}
		for i in range(256):
			test_string = template_string +answer +  chr(i)
			diction[test_string] = func.get(test_string.encode())
		for key in diction:
			if one_short_cipher[:idx_after_block] == diction[key][:idx_after_block]:
				answer+= key[-1]
	return answer

print(break_oracle_w_prepend(secret_size= 138, blocksize =16)	)			