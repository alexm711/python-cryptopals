




from utilities import MT19937, s, b, t, c, u, d, l, n

# w: word size (in number of bits)
# n: degree of recurrence
# m: middle word, an offset used in the recurrence relation defining the series x, 1 ≤ m < n
# r: separation point of one word, or the number of bits of the lower bitmask, 0 ≤ r ≤ w - 1
# a: coefficients of the rational normal form twist matrix
# b, c: TGFSR(R) tempering bitmasks
# s, t: TGFSR(R) tempering bit shifts
# u, d, l: additional Mersenne Twister tempering bit shifts/masks

# (s, b) = (7, 0x9D2C5680)
# (t, c) = (15, 0xEFC60000)

# (u, d) = (11, 0xFFFFFFFF)
# l = 18

# n = 624
seed = 0
r = MT19937(seed)



def untemper_op_rightshift(y, k):
    output = y
    bits = k
    while bits < 32:
        output = y ^ (output >> k)
        bits += k
    return output

def untemper_op_leftshift_AND(y, k, mask):
    output = y
    bits = k
    while bits < 32:
        output = y ^ ((output << k) & mask)
        bits += k
    return output

def untemper(y):
    y =    untemper_op_rightshift(y, l)
    y =    untemper_op_leftshift_AND(y, t, c)
    y =    untemper_op_leftshift_AND(y, s, b)
    return untemper_op_rightshift(y, u)



state_nums = [untemper(r.extract_number()) for x in range(n)]

# state_nums = [untemper(num) for num in nums]
r2 = MT19937(state_nums)
nums2 = [r2.extract_number() for x in range(n)]
nums = [r.extract_number() for x in range(n)]

# for i in range(20):
# 	print(nums[i],nums2[i])
assert nums == nums2

print("cloning works")
