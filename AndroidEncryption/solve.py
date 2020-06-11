def xor(b1,b2):
    return bytes(b ^ B for b,B in zip(b1,b2))
from Crypto.Cipher import AES
enc = bytes.fromhex(b'1cc12214c5225d1534a147acc20a3b2d8ee135ae9390c281c2684cb1a080bd2f7ef96352769853980a57772b04aeebee')
iv2 = bytes.fromhex(b'e10073fb055574939c9d94f002d52f09')
key2 = bytes.fromhex(b'a488904e2120e576366ec6c40f316307') # gets our enc, iv and key from hex to bytes
curr = iv2
cipher = AES.new(key2, AES.MODE_ECB)
first = xor(curr,cipher.decrypt(enc[:16])) # decrypting the first block
curr = xor(first, enc[:16]) #changing the iv to previous ct block
second = xor(curr,cipher.decrypt(enc[16:32])) # decrypting second block
curr = xor(second,enc[16:32])#changing iv again
third = xor(curr,cipher.decrypt(enc[32:48])) # decrypting third block
print(first + second + third) #outputting result
