import cryptBreak
from BitVector import *

someRandomInteger = 25202 #Arbitrary integer for creating a BitVector
key_bv = BitVector(intVal=someRandomInteger, size=16)
decryptedMessage = cryptBreak.cryptBreak('encrypted.txt', key_bv)
if 'Mark Twain' in decryptedMessage:
    print('Encryption Broken!')
    print(decryptedMessage)
else:
    print('Not decrypted yet')