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
            self.decryptor = self.cipher.decryptor()
            self.encryptor = self.cipher.encryptor()
        else:
            if tag != None:
                self.decryptor = AESCCM(key, tag_length=len(tag))


    # bytes
    def decrypt(self, ciphertext, mode = 'bytes'):
        if mode == 'bytes':
            return self.decryptor.update(ciphertext) + self.decryptor.finalize()
        elif mode == 'base64':
            ciphertext = b64decode(ciphertext)
            return self.decryptor.update(ciphertext) + self.decryptor.finalize()
        elif mode == 'base64url':
            ciphertext = decode_base64(ciphertext)
            return self.decryptor.update(ciphertext) + self.decryptor.finalize()
        elif mode == 'hex':
            tempCiphertext = ciphertext.split()
            ciphertext = ''.join(tempCiphertext)
            ciphertext = bytes.fromhex(ciphertext)
            return self.decryptor.update(ciphertext) + self.decryptor.finalize()


def main():
    cipher = AESCipher(bytes.fromhex('0101010101010101010101010101010101010101010101010101010101010101'), 'ECB')
    print(cipher.decrypt('3CS3iT7BzDa9iFhKGuzWBA==', mode = 'base64'))
    pass

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
