#!/usr/bin/env/python3
# Homework Number:  hw04
# Name: Shu Hwai Teoh
# ECN Login: teoh0
# Due Date: Tuesday 2/18/2020 at 4:29PM
import sys
from BitVector import *

AES_modulus = BitVector(bitstring='100011011')
subBytesTable = []       # for encryption
# invSubBytesTable = []    # for decryption

def genTables():
    c = BitVector(bitstring='01100011')
    # d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox, find the multiplicative inverse x′= x_in^(-1) in GF(2^8)
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        # scramble the bits of x′ by XORing x′ with 
        # four different circularly rotated versions of itself 
        # and with a special constant byte c = 0x63. 
        # The four circular rotations are through 4, 5, 6, and 7 bit positions to the right.
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        # b = BitVector(intVal = i, size=8)
        # # For bit scrambling for the decryption SBox entries:
        # b1,b2,b3 = [b.deep_copy() for x in range(3)]
        # b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        # check = b.gf_MI(AES_modulus, 8)
        # b = check if isinstance(check, BitVector) else 0
        # invSubBytesTable.append(int(b))

def gen_key_schedule_256(key_bv):
    # byte_sub_table = gen_subbytes_table()
    #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
    #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
    #  schedule. We will store all 60 keywords in the following list:
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(8,60):
        if i%8 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, subBytesTable)
            key_words[i] = key_words[i-8] ^ kwd
        elif (i - (i//8)*8) < 4:
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        elif (i - (i//8)*8) == 4:
            key_words[i] = BitVector(size = 0)
            for j in range(4):
                key_words[i] += BitVector(intVal = 
                                 subBytesTable[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
            key_words[i] ^= key_words[i-8] 
        elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        else:
            sys.exit("error in key scheduling algo for i = %d" % i)
    return key_words

def gee(keyword, round_constant, byte_sub_table):
    '''
    This is the g() function for key expension.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant

def keyEncryptExpend(key_file):
    # read key string from key.txt and turn it into a bitVector
    with open(key_file, "r") as f:
        key = f.read().strip()
    key_bv = BitVector(textstring=key)  
    key_words = gen_key_schedule_256(key_bv)
    key_schedule = []
    #Each 32-bit word of the key schedule is shown as a sequence of 4 one-byte integers
    for word_index,word in enumerate(key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i*8:i*8+8].intValue())
        # if word_index % 4 == 0: print("\n")
        # print("word %d:  %s" % (word_index, str(keyword_in_ints)))
        key_schedule.append(keyword_in_ints)
    num_rounds = 14
    round_keys = [None for i in range(num_rounds+1)]
    # de_round_key = [None for i in range(num_rounds+1)]
    for i in range(num_rounds+1):
        round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + 
                                    key_words[i*4+3])#.get_bitvector_in_hex()
        # de_round_key[num_rounds-i] = key_words[i*4+3] + key_words[i*4+2] + key_words[i*4+1] + key_words[i*4]
    return round_keys #, de_round_key #list of 32-bit bitVector (each round key has 4 words)

def AES_Encrypt(input_bv, round_keys):
    bv = input_bv
    # add round key
    bv = bv ^ round_keys[0]
    # 13 round
    for i in range(1,14):
        # substitute bytes
        bv = subBytes(bv)
        bv = shiftRows(bv)
        bv = mixColumns(bv)
        # add round key
        bv = bv ^ round_keys[i]
    #last round
    bv = subBytes(bv)
    bv = shiftRows(bv)
    bv = bv ^ round_keys[-1]
    output_bv = bv
    return output_bv # return the bit vector of the encrypted text for the whole content

def subBytes(bv):
    # c = BitVector(bitstring='01100011')
    # bv_out = BitVector(size=0)
    # for i in range(0, bv.length(), 8):
    #     # extract 1 byte at a time, 
    #     # bv_out += subBytesTable[int(bv[i:i+4]) *10 + int(bv[i+4:i+8])]
    #     a = bv[i:i+8].gf_MI(AES_modulus, 8) if int(bv[i:i+8]) != 0 else BitVector(intVal=0)
    #     # For bit scrambling for the encryption SBox entries:
    #     # scramble the bits of x′ by XORing x′ with 
    #     # four different circularly rotated versions of itself 
    #     # and with a special constant byte c = 0x63. 
    #     # The four circular rotations are through 4, 5, 6, and 7 bit positions to the right.
    #     a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
    #     a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
    #     bv_out += a
    bv_out = BitVector(size=0)
    # extract 1 byte at a time
    for i in range(0, bv.length(), 8):
        # use subBytesTable to substitute each byte
        bv_out += BitVector(intVal=int(subBytesTable[int(bv[i:i+8])]), size=8)
    return bv_out
def shiftRows(bv):
    #(i) not shifting the first row of the state array; 
    #(ii) circularly shifting the second row by one byte to the left; 
    #(iii) circularly shifting the third row by two bytes to the left; 
    #(iv) circularly shifting the last row by three bytes to the left.
    #[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
    # -> [0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11]
    bv_out = BitVector(size=0)
    for i in range(4):
        a = 4*i
        for j in range(4):
            b = a + 5*j
            if b <= 15:
                bv_out += bv[b*8:b*8+8]
            else:
                bv_out += bv[(b-15-1)*8:(b-15-1)*8+8]
    return bv_out
def mixColumns(bv):
    #  Each byte in a column is replaced by two times that byte, 
    # plus three times the next byte, plus the byte that comes next, 
    # plus the byte that follows.
    bv_out = BitVector(size=0)
    one = BitVector(intVal = 1, size = 8)
    two = BitVector(intVal = 2, size = 8)
    three = BitVector(intVal = 3, size = 8)
    m = [[two,three,one,one],[one,two, three, one],[one, one, two, three], [three, one, one, two]]
    for i in range(4):
        for j in range(4):
            a = m[j][0].gf_multiply_modular(bv[8*i*4:8*i*4+8], AES_modulus, 8)
            b = m[j][1].gf_multiply_modular(bv[8*(i*4+1):8*(i*4+1)+8], AES_modulus, 8)
            c = m[j][2].gf_multiply_modular(bv[8*(i*4+2):8*(i*4+2)+8], AES_modulus, 8)
            d = m[j][3].gf_multiply_modular(bv[8*(i*4+3):8*(i*4+3)+8], AES_modulus, 8)
            bv_out += (a^b^c^d)
    return bv_out


#Arguments:
# v0: 128-bit BitVector object containing the seed value
# dt: 128-bit BitVector object symbolizing the date and time
# key_file: String of file name containing the encryption key (in ASCII) for AES
# totalNum: integer indicating the total number of random numbers to generate
#Function Description
# Uses the arguments with the X9.31 algorithm to generate totalNum random
# numbers as BitVector objects
#Returns a list of BitVector objects, with each BitVector object representing a
# random number generated from X9.31
def x931(v0, dt, totalNum, key_file):
    genTables()
    # read key from file, encrypt and expend is as 60 round keys (each 4 words)
    round_keys = keyEncryptExpend(key_file)
    listX931 =[]
    # encrypt the time bitvector with AES
    dt_en = AES_Encrypt(dt, round_keys)
    vi = v0.deep_copy()
    for i in range(totalNum):
        # encrypt the output of vi XOR with the encrypted time to obtain a random number
        randNum = AES_Encrypt( vi ^ dt_en, round_keys)
        listX931.append(randNum)
        # obtain the bit vector vi for next generation of random number
        vi = AES_Encrypt(randNum ^ dt_en, round_keys)
    return listX931
