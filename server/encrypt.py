import protocol
from Cryptodome import Random
from Cryptodome.Cipher import AES,PKCS1_OAEP
from Cryptodome.PublicKey import RSA
import base64

class Encryptor:
    def __init__(self,public_key, aes_key = Random.get_random_bytes(protocol.SYMM_KEY_SIZE)):
        self.public_key = public_key
        self.aes_key = aes_key
    
    def pad(self,message:str)->str:
        """Adds padding to message to match length of AES block size

        Args:
            message (str): message to add padding

        Returns:
            str: message with padding
        """ 
        return message + b"\0" * (AES.block_size - len(message) % AES.block_size)

    def encrypt(self, message):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")
    
    def encrypt_with_public_key(self, message):
        rsa_key = RSA.import_key(self.public_key)
        message_padded = self.pad(message)
        encryptor = PKCS1_OAEP.new(rsa_key)
        encrypted_msg = encryptor.encrypt(message_padded)
        return encrypted_msg


