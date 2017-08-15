from utilities import SHA1, secret_prefix_mac


message = 'The quick brown fox jumps over the lazy cog'
key = "YELLOW SUBMARINE"

SHAhash = secret_prefix_mac(key,message)
print("SHAhash for orig k+m: ", SHAhash)

for m in ["the quick brown fox jumps over the lazy cog", 
				"The quick brown fox jumps over the lazy Dog",
				"The quick brown fox jumps over the lazy dog",
				"The quick brown fox jumps over the lazy Cog"]:
    print("Tampered message: ", secret_prefix_mac(key,m))

for k in ["YELLOW sUBMARINE","YELLOm SUBMARINE","yELLOW SUBMARINE"]:
    print("Lost key\t\t", secret_prefix_mac(k,message))
