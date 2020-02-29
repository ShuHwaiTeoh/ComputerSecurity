#!/usr/bin/env/python3
# Homework Number:  hw06
# Name: Shu Hwai Teoh
# ECN Login: teoh0
# Due Date: Tuesday 02/25/2020 at 4:29 PM
import sys
from BitVector import *
import rsa

def solve_pRoot(p, x): #O(lgn) solution
	'''
	Finds pth root of an integer x.  Uses Binary Search logic.	Starts
	with a lower bound l and go up until upper bound u.	Breaks the problem into
	halves depending on the search logic.  The search logic says whether the mid
	(which is the mid value of l and u) raised to the power to p is less than x or
	it is greater than x.	Once we reach a mid that when raised to the power p is
	equal to x, we return mid + 1. 

	Author: Shayan Akbar 
		sakbar at purdue edu

	'''

	#Upper bound u is set to as follows:
	#We start with the 2**0 and keep increasing the power so that u is 2**1, 2**2, ...
	#Until we hit a u such that u**p is > x
	u = 1
	while u ** p <= x: u *= 2

	#Lower bound set to half of upper bound
	l = u // 2

	#Keep the search going until upper u becomes less than lower l
	while l < u:
		mid = (l + u) // 2
		mid_pth = mid ** p
		if l < mid and mid_pth < x:
			l = mid
		elif u > mid and mid_pth > x:
			u = mid
		else:
			# Found perfect pth root.
			return mid
	return mid + 1

if __name__ == '__main__':
    e = 3
    # python breakRSA.py -e message.txt enc1.txt enc2.txt enc3.txt n_1_2_3.txt
    if sys.argv[1] == "-e":
        # generate 3 keys
        n_set = set()
        num_of_bits_desired = 128 
        generator = rsa.PrimeGenerator( bits = num_of_bits_desired ) 
        while len(n_set)!=3:             
            p = generator.findPrime()
            while rsa.check_MSB(p) or rsa.ckeck_coprime_e(p, e):
                p = generator.findPrime()
            q = generator.findPrime()  
            while p==q or rsa.check_MSB(q) or rsa.ckeck_coprime_e(q, e):
                q = generator.findPrime()
            n_set.add(p*q)
        with open(sys.argv[6], "w") as f:
            for i in n_set:
                f.write(str(i))
    
        # encrypt the file with 3 keys
        for i in range(3):
            # encrypt the file by C = M^e mod n through Modular Exponentiation
            encryptedText = rsa.rsa_encrypt(sys.argv[2], e, n_set[i])
            # transform the ciphertext into the hex string and write out to the file
            with open(sys.argv[i+2], 'w') as f:
                f.write(encryptedText.get_hex_string_from_bitvector())

    # decrypt the file with cube-root M^3 mod n1*n2*n3  
    # python breakRSA.py -c enc1.txt enc2.txt enc3.txt n_1_2_3.txt cracked.txt
    if sys.argv[1] == "-d":
        with open(sys.argv[3], "r") as f:
            p = int(f.readline().strip())
        with open(sys.argv[4], "r") as f:
            q = int(f.readline().strip())
        # Calculate the modulus n = p*q
        n = p*q
        # Calculate the totient ϕ(n) = (p-1)*(q-1)
        totient_n = (p-1)*(q-1)
        # choose d as the multiplicative inverse of e modulo totient_n
        # Calculate for the private exponent a value for d such that 
        # d = e^(-1) mod ϕ(n) use the Extended Euclids Algorithm
        d = findMI(e, totient_n)
        # decrypt file by M = C^d mod n throgh Chinese Remainder Theorem
        decryptedText = rsa_decrypt(sys.argv[2], d, n, p, q)
        with open(sys.argv[5], "w") as f:
            f.write(decryptedText.get_text_from_bitvector())