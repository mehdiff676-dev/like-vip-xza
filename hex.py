from Crypto.Cipher import AES
from Crypto.Util.Padding import pad , unpad



def DEc_AEs(HeX):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key , AES.MODE_CBC , iv)
    return unpad(cipher.decrypt(bytes.fromhex(HeX)), AES.block_size).hex()

hex = input('HEX : ')
input(DEc_AEs(hex))