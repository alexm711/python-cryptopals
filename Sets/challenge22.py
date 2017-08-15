# Crack an MT19937 seed
from utilities import MT19937


import time

from random import randint
	
def wait(low,high):
	num_secs = randint(low,high)
	time.sleep(num_secs)

def find_seed(firstRNG,):
	curr_time, iters = int(time.time()), 0
	while True:
		assert iters < 10000, "too many iterations, over " + str(iters) 
		test_time = curr_time-iters
		testRNG = MT19937(test_time)
		if testRNG.extract_number() == firstRNG:
			return (test_time)
		iters+=1	


wait(1,4)
ts = int(time.time())
r = MT19937(ts)
wait(1,4)
firstRNG = r.extract_number()

print("Seed Time : {} \nSeed Guess: {}".format(ts,find_seed(firstRNG)))
