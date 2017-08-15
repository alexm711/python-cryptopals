

from utilities import MT19937

# w: word size (in number of bits)
# n: degree of recurrence
# m: middle word, an offset used in the recurrence relation defining the series x, 1 ≤ m < n
# r: separation point of one word, or the number of bits of the lower bitmask, 0 ≤ r ≤ w - 1
# a: coefficients of the rational normal form twist matrix
# b, c: TGFSR(R) tempering bitmasks
# s, t: TGFSR(R) tempering bit shifts
# u, d, l: additional Mersenne Twister tempering bit shifts/masks

r = MT19937(0)
print(r.extract_number())




