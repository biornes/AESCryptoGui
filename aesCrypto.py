# This is a sample Python script.
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from base64 import b64decode, b64encode
from unpaddedbase64 import decode_base64, encode_base64

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

class AESCipher:

    def __init__(self, key, mode, iv = None, nonce = None, tag = None):
        if mode == 'ECB':
            algorithm = algorithms.AES(key)
            self.cipher = Cipher(algorithm, modes.ECB())
            self.decryptor = self.cipher.decryptor()
            self.encryptor = self.cipher.encryptor()
        elif mode == 'CBC' and iv != None:
            algorithm = algorithms.AES(key)
            self.cipher = Cipher(algorithm, modes.CBC(iv))
            self.decryptor = self.cipher.decryptor()
            self.encryptor = self.cipher.encryptor()
        elif mode == 'CTR' and nonce != None:
            algorithm = algorithms.AES(key)
            self.cipher = Cipher(algorithm, modes.CTR(nonce = nonce))
            self.decryptor = self.cipher.decryptor()
            self.encryptor = self.cipher.encryptor()
        elif mode == 'GCM' and iv != None and tag != None:
            algorithm = algorithms.AES(key)
            self.cipher = Cipher(algorithm, modes.GCM(iv, tag = tag))
            if tag == None:
                self.encryptor = self.cipher.encryptor()
            else:
                self.decryptor = self.cipher.decryptor()
        elif mode == 'GCM' and iv != None:
            algorithm = algorithms.AES(key)
            self.cipher = Cipher(algorithm, modes.GCM(iv))
            self.decryptor = self.cipher.decryptor()
            self.encryptor = self.cipher.encryptor()
        else:
            if tag != None:
                self.decryptor = AESCCM(key, tag_length=len(tag))
                self.encryptor = AESCCM(key, tag_length=len(tag))


    # bytes
    def decrypt(self, ciphertext, mode = 'bytes'):
        if mode == 'bytes':
            return self.decryptor.update(ciphertext) + self.decryptor.finalize()
        # elif mode == 'Base64':
        #     ciphertext = b64decode(ciphertext)
        #     return self.decryptor.update(ciphertext) + self.decryptor.finalize()
        # elif mode == 'Base64url':
        #     ciphertext = decode_base64(ciphertext)
        #     return self.decryptor.update(ciphertext) + self.decryptor.finalize()
        # elif mode == 'Hex':
        #     tempCiphertext = ciphertext.split()
        #     ciphertext = ''.join(tempCiphertext)
        #     ciphertext = bytes.fromhex(ciphertext)
        #     return self.decryptor.update(ciphertext) + self.decryptor.finalize()
        # elif mode == 'Java Bytes':
        #     ct = []
        #     ct.append()
        #     for i in ciphertext:
        #         if i < 0:
        #             ct.append(i + 255)
        #         else:
        #             ct.append(i)
        #     ciphertext = b''
        #     for j in ct:
        #         ciphertext += j.to_bytes(1, 'little')
        #     return self.decryptor.update(ciphertext) + self.decryptor.finalize()
    def encrypt(self, plaintext):
        if len(plaintext) % 16:
            paddedLength = (len(plaintext) // 16 + 1) * 16
            plaintext = plaintext.ljust(paddedLength, b'\x00')
        ciphertext = self.encryptor.update(plaintext) + self.encryptor.finalize()
        print ('tag', self.encryptor.tag)
        return ciphertext

def main():
    cipher = AESCipher(bytes.fromhex('0101010101010101010101010101010101010101010101010101010101010101'), 'ECB')
    print(cipher.decrypt('3CS3iT7BzDa9iFhKGuzWBA==', mode = 'base64'))
    pass

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
