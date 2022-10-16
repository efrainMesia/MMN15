import protocol
from Cryptodome import Random
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
import base64


unpad = lambda s: s[: -ord(s[len(s) - 1 :])]


class Encryptor:
    def __init__(self, public_key=None, aes_key=Random.get_random_bytes(protocol.SYMM_KEY_SIZE), logger=None):
        self.public_key = public_key
        self.aes_key = aes_key
        self.logger = logger

    def pad(self, message: str) -> str:
        """Adds padding to message to match length of AES block size

        Args:
            message (str): message to add padding

        Returns:
            str: message with padding
        """
        self.logger.debug("Padding message")
        return message + b"\0" * (AES.block_size - len(message) % AES.block_size)

    def unpad(self, message):
        self.logger.debug("Unpadding message")
        return message[: -ord(message[len(message) - 1 :])]

    def encrypt(self, message):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def decrypt(self, ciphertext, key):
        iv = ciphertext[: AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size :])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, path_in_file, path_out_file):
        try:
            self.logger.info(f"Decrypting file {path_in_file}")
            with open(path_in_file, "rb") as in_file, open(
                path_out_file, "wb"
            ) as out_file:
                iv = b"\0" * 16
                cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
                ciphertext = in_file.read()
                plaintext = cipher.decrypt(ciphertext)
                out_file.write(self.unpad(plaintext.rstrip(b'\0')))
                #chunk = cipher.decrypt(in_file.read(1024 * AES.block_size))
                #while len(chunk) != 0:
                #    #chunk = self.unpad(chunk)
                #    out_file.write(chunk)
                #    chunk = cipher.decrypt(in_file.read(1024 * AES.block_size))
            in_file.close()
            out_file.close()
            return True
        except Exception as e:
            self.logger.error(f"something went wrong :{e}")
        return False

    def encrypt_with_public_key(self, message:bytes) -> bytes:
        rsa_key = RSA.import_key(self.public_key)
        message_padded = self.pad(message)
        encryptor = PKCS1_OAEP.new(rsa_key)
        encrypted_msg = encryptor.encrypt(message_padded)
        self.logger.info("Message has been encrypted with client's public Key")
        return encrypted_msg
