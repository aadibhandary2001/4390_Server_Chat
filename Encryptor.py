##############################################################################
#   File:   Encryptor.py
#   Author: Bryce McFarlane (CE)
#
#   Procedures:
#       encrypt:        -Take any arbitrary input and return a byte-encrypted version of it
#       decrypt:        -Take in an encrypted byte input and return a decrypted string version of it
#       give_random:    -Give a random strange based on Cryptodome's random to be used for generation of active-keys
#       run_SHA1:       -Take in bytes to run SHA1 on them. Intended to be used for the RES in authentication
#       run_MD5:        -Take in bytes to run MD5 on them. Intended to be used to generate a new Cryptographer key.
#############################################################################

# Importations from Cryptodome used for encryption/decryption.
# Use: "pip install pycryptodomex" if this gives you an error.
# May require putting the resultant Cryptodome package in the same folder. I don't know why.
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import unpad
import hashlib

# Creation of a Cryptographer class that will handle cryptography needs once authentication is complete.
# Makes use of the PyCryptodome library to take in any arbitrary key input and valid salt to create its
# encryption.

# A function to give 8 random bytes (as a string) to be used for challenges or key generation.
def give_random():
    return str(get_random_bytes(8))


# A function to run SHA1 on a message and return the bytes for challenges
def run_SHA1(message):
    temp_hash = hashlib.new('sha1', message)
    return temp_hash.digest()


# A function to run MD5 on a message and return the bytes for key generation.
def run_MD5(message):
    temp_hash = hashlib.new('md5', message)
    return temp_hash.digest()

class Cryptographer:
    def __init__(self, key, salt):
        # Casting of the key to bytes to ensure that any theoretical key will work
        byte_key= bytes(str(key), 'utf-8')
        # Creation of the actual cryptography key and subsequent library
        crypt_key = hashlib.pbkdf2_hmac('sha1', byte_key, salt, 3, AES.block_size)
        self.cipher = AES.new(crypt_key, AES.MODE_ECB)

    # A method to encrypt a message before sending it.
    def encrypt(self, message):
        # Attempt to encrypt a message
        try:
            # Turning the message into bytes
            byte_message=bytes(str(message), 'utf-8')
            # Returning the original message, encrypted, as a set of bytes.
            return self.cipher.encrypt(pad(byte_message, AES.block_size))
        # I have no clue what situation a value error could come up in for this side of encryption
        except ValueError:
            print("Unknown source of ValueError. I am not sure where this could happen.")

    # A method to encrypt a received message
    def decrypt(self, message):
        # Attempt to read decrypted data
        try:
            decrypted_message = unpad(self.cipher.decrypt(message), AES.block_size)
            # Returning the decrypted message directly as a string, while eliminating any New Line characters.
            return decrypted_message.decode().replace('\n', '')
        # If there was no data to read,it is most likely the TCP connection using this Encryptor has ended.
        except ValueError:
            print("A TCP connection has ended")


