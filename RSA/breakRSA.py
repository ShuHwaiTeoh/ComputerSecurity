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

def decrypt(encfile1, encfile2, encfile3, n_list):
    FILEIN = open(encfile1)
    input_bv1 = BitVector(hexstring=FILEIN.read())
    FILEIN = open(encfile2)
    input_bv2 = BitVector(hexstring=FILEIN.read())
    FILEIN = open(encfile3)
    input_bv3 = BitVector(hexstring=FILEIN.read())
    N = n_list[0]*n_list[1]*n_list[2]
    # N1 = N/n1
    N1 = n_list[1]*n_list[2]
    N1_MI = rsa.findMI(N1, n_list[0])
    N2 = n_list[0]*n_list[2]
    N2_MI = rsa.findMI(N2, n_list[1])
    N3 = n_list[0]*n_list[1]
    N3_MI = rsa.findMI(N3, n_list[2])
    # create empty bit vector to store output
    output_bv = BitVector(size=0)
    # loop through all the input and extract 64 bit at a time
    for j in range(0, input_bv1.length(), 256):
        bv1 = input_bv1[j:j+256]
        bv2 = input_bv2[j:j+256]
        bv3 = input_bv3[j:j+256]
        # Chinese Remainder Theorem M^3 mod N = n1*n2*n3
        M3 = (int(bv1)*N1*N1_MI + int(bv2)*N2*N2_MI + int(bv3)*N3*N3_MI) % N
        # cube-root
        M = solve_pRoot(3, M3)
        if j==0: print(M)
        output_bv += BitVector(intVal=M, size=128)
    return output_bv



if __name__ == '__main__':
    e = 3
    # ansn_list=[]
    # with open("ans_n_1_2_3.txt", "r") as f:
    #     for i in range(3):
    #         ansn_list.append(int(f.readline().strip()))
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
        n_set = list(n_set)
        with open(sys.argv[6], "w") as f:
            for i in n_set:
                f.write(str(i))
                f.write("\n")

        # encrypt the file with 3 keys
        for i in range(3):
            # encrypt the file by C = M^e mod n through Modular Exponentiation
            encryptedText = rsa.rsa_encrypt(sys.argv[2], e, n_set[i])
            # transform the ciphertext into the hex string and write out to the file
            with open(sys.argv[i+3], 'w') as f:
                f.write(encryptedText.get_hex_string_from_bitvector())

    # decrypt the file with cube-root M^3 mod n1*n2*n3  
    # python breakRSA.py -c enc1.txt enc2.txt enc3.txt n_1_2_3.txt cracked.txt
    if sys.argv[1] == "-c":
        n_list=[]
        with open(sys.argv[5], "r") as f:
            for i in range(3):
                n_list.append(int(f.readline().strip()))
        # decrypt file by M = C^d mod n throgh Chinese Remainder Theorem
        decryptedText = decrypt(sys.argv[2],sys.argv[3],sys.argv[4], n_list)
        with open(sys.argv[6], "w") as f:
            f.write(decryptedText.get_text_from_bitvector())