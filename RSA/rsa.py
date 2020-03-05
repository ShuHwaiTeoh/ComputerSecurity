#!/usr/bin/env/python3
# Homework Number:  hw06
# Name: Shu Hwai Teoh
# ECN Login: teoh0
# Due Date: Tuesday 03/03/2020 at 4:29 PM
import sys
from BitVector import *
import sys
import random

class PrimeGenerator( object ):                                              #(A1)

    def __init__( self, **kwargs ):                                          #(A2)
        bits = debug = None                                                  #(A3)
        if 'bits' in kwargs  :     bits = kwargs.pop('bits')                 #(A4)
        if 'debug' in kwargs :     debug = kwargs.pop('debug')               #(A5)
        self.bits            =     bits                                      #(A6)
        self.debug           =     debug                                     #(A7)
        self._largest        =     (1 << bits) - 1                           #(A8)

    def set_initial_candidate(self):                                         #(B1)
        candidate = random.getrandbits( self.bits )                          #(B2)
        if candidate & 1 == 0: candidate += 1                                #(B3)
        candidate |= (1 << self.bits-1)                                      #(B4)
        candidate |= (2 << self.bits-3)                                      #(B5)
        self.candidate = candidate                                           #(B6)

    def set_probes(self):                                                    #(C1)
        self.probes = [2,3,5,7,11,13,17]                                     #(C2)

    # This is the same primality testing function as shown earlier
    # in Section 11.5.6 of Lecture 11:
    def test_candidate_for_prime(self):                                      #(D1)
        # returns the probability if candidate is prime with high probability
        p = self.candidate                                                   #(D2)
        if p == 1: return 0                                                  #(D3)
        if p in self.probes:                                                 #(D4)
            self.probability_of_prime = 1                                    #(D5)
            return 1                                                         #(D6)
        if any([p % a == 0 for a in self.probes]): return 0                  #(D7)
        k, q = 0, self.candidate-1                                           #(D8)
        while not q&1:                                                       #(D9)
            q >>= 1                                                          #(D10)
            k += 1                                                           #(D11)
        if self.debug: print("q = %d  k = %d" % (q,k))                       #(D12)
        for a in self.probes:                                                #(D13)
            a_raised_to_q = pow(a, q, p)                                     #(D14)
            if a_raised_to_q == 1 or a_raised_to_q == p-1: continue          #(D15)
            a_raised_to_jq = a_raised_to_q                                   #(D16)
            primeflag = 0                                                    #(D17)
            for j in range(k-1):                                             #(D18)
                a_raised_to_jq = pow(a_raised_to_jq, 2, p)                   #(D19)
                if a_raised_to_jq == p-1:                                    #(D20)
                    primeflag = 1                                            #(D21)
                    break                                                    #(D22)
            if not primeflag: return 0                                       #(D23)
        self.probability_of_prime = 1 - 1.0/(4 ** len(self.probes))          #(D24)
        return self.probability_of_prime                                     #(D25)

    def findPrime(self):                                                     #(E1)
        self.set_initial_candidate()                                         #(E2)
        if self.debug:  print("    candidate is: %d" % self.candidate)       #(E3)
        self.set_probes()                                                    #(E4)
        if self.debug:  print("    The probes are: %s" % str(self.probes))   #(E5)
        max_reached = 0                                                      #(E6)
        while 1:                                                             #(E7)
            if self.test_candidate_for_prime():                              #(E8)
                if self.debug:                                               #(E9)
                    print("Prime number: %d with probability %f\n" %       
                          (self.candidate, self.probability_of_prime) )      #(E10)
                break                                                        #(E11)
            else:                                                            #(E12)
                if max_reached:                                              #(E13)
                    self.candidate -= 2                                      #(E14)
                elif self.candidate >= self._largest - 2:                    #(E15)
                    max_reached = 1                                          #(E16)
                    self.candidate -= 2                                      #(E17)
                else:                                                        #(E18)
                    self.candidate += 2                                      #(E19)
                if self.debug:                                               #(E20)
                    print("    candidate is: %d" % self.candidate)           #(E21)
        return self.candidate   

def check_MSB(number):
    bString = bin(number).replace("0b", "")
    return (bString[0] != "1" and bString[1] != "1")

def ckeck_coprime_e(number, e):
    if e > (number-1):
        a, b = e, number-1
    else:
        a, b = number-1, e
    while b:                                             
        a,b = b, a%b
    return a != 1

def findMI(number, m):
    bv_modulus = BitVector(intVal = m)
    bv = BitVector(intVal = number) 
    MI_bv = bv.multiplicative_inverse( bv_modulus )
    MI = int(MI_bv)
    return MI

def modular_Expo(A, B, n):
    C = 1
    while B > 0:
        if B & 1:
            # check the lowest bit of B
            C = ( C * A ) % n
        B = B >> 1
        # shift B by one bit to right
        A = ( A * A ) % n
    return C

def rsa_encrypt(fileName, e, n):
    FILEIN = open(fileName)
    input_bv = BitVector(textstring=FILEIN.read())
    # create empty bit vector to store output
    output_bv = BitVector(size=0)
    # e_bv = BitVector(intVal=e, size=256)
    # one = BitVector(intVal=1, size=256)
    # loop through all the input and extract 64 bit at a time
    for j in range(0, input_bv.length(), 128):
        if input_bv.length() < j+128:
            # padding the last byte with 0s
            bv = input_bv[j:] + BitVector(bitlist=[0] * (j+128-input_bv.length()))
            print(bv)
        else:
            bv = input_bv[j:j+128]            
        bv.pad_from_left(128)
        # C = M^e mod n
        B = e
        A = int(bv)
        C = modular_Expo(A, B, n)
        output_bv += BitVector(intVal=C, size=256)
    return output_bv

def rsa_decrypt(fileName, d, n, p, q):
    FILEIN = open(fileName)
    input_bv = BitVector(hexstring=FILEIN.read())
    # create empty bit vector to store output
    output_bv = BitVector(size=0)
    qMI = findMI(q, p)
    pMI = findMI(p, q)
    xp = q*qMI
    xq = p*pMI
    # loop through all the input and extract 64 bit at a time
    for j in range(0, input_bv.length(), 256):
        bv = input_bv[j:j+256]
        # M = C^d mod n throgh Chinese Remainder Theorem
        vp = modular_Expo(int(bv), d, p)
        vq = modular_Expo(int(bv), d, q)
        M = (vp*xp+vq*xq) % n
        output_bv += BitVector(intVal=M, size=128)
    print(output_bv[-128:])
    return output_bv

####################################  main  ######################################
if __name__ == '__main__':
    # modulus N: 256 bits
    # data block M: 128-bits from the text pedding from left with 0s 
    # to make it a 256-bit block.

    # Select for public exponent an integer e: has as few bits as possible equal 
    # to 1 for fast multiplication. Typical values for e are 3, 17, and 65537
    e = 65537

    # Generate two different primes p and q (each 128 bits)
    # python rsa.py -g p.txt q.txt
    if sys.argv[1] == "-g":
        num_of_bits_desired = 128 
        generator = PrimeGenerator( bits = num_of_bits_desired )              
        p = generator.findPrime()
        while check_MSB(p) or ckeck_coprime_e(p, e):
            print(check_MSB(p))
            p = generator.findPrime()
        q = generator.findPrime()  
        while p==q or check_MSB(q) or ckeck_coprime_e(q, e):
            q = generator.findPrime()
        with open(sys.argv[2], "w") as f:
            f.write(str(p))
        with open(sys.argv[3], "w") as f:
            f.write(str(q))
    
    # encrypt the file with RSA
    # python rsa.py -e message.txt p.txt q.txt encrypted.txt
    if sys.argv[1] == "-e":
        with open(sys.argv[3], "r") as f:
            p = int(f.readline().strip())
        with open(sys.argv[4], "r") as f:
            q = int(f.readline().strip())
        # Calculate the modulus n = p*q
        n = p*q
        # Calculate the totient phi(n) = (p-1)*(q-1)
        totient_n = (p-1)*(q-1)
        # encrypt the file by C = M^e mod n through Modular Exponentiation
        encryptedText = rsa_encrypt(sys.argv[2], e, n)
        # transform the ciphertext into the hex string and write out to the file
        with open(sys.argv[5], 'w') as f:
            f.write(encryptedText.get_hex_string_from_bitvector())

    # decrypt the file with RSA  
    # python rsa.py -d encrypted.txt p.txt q.txt decrypted.txt
    if sys.argv[1] == "-d":
        with open(sys.argv[3], "r") as f:
            p = int(f.readline().strip())
        with open(sys.argv[4], "r") as f:
            q = int(f.readline().strip())
        # Calculate the modulus n = p*q
        n = p*q
        # Calculate the totient phi(n) = (p-1)*(q-1)
        totient_n = (p-1)*(q-1)
        # choose d as the multiplicative inverse of e modulo totient_n
        # Calculate for the private exponent a value for d such that 
        # d = e^(-1) mod phi(n) use the Extended Euclids Algorithm
        d = findMI(e, totient_n)
        # decrypt file by M = C^d mod n throgh Chinese Remainder Theorem
        decryptedText = rsa_decrypt(sys.argv[2], d, n, p, q)
        with open(sys.argv[5], "wb") as f:
            decryptedText.write_to_file(f)
            # f.write(decryptedText.get_text_from_bitvector())