from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from os import urandom


def blowfish_encrypt(plaintext, key):
    # generate a random IV (Initialization Vector)
    iv = urandom(8)

    # create Blowfish cipher
    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # padding the plaintext and encrypt
    padder = padding.PKCS7(algorithms.Blowfish.block_size).padder()
    padded_plaintext = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return iv + ciphertext



def blowfish_decrypt(ciphertext, key):
    # extract IV and actual ciphertext
    iv = ciphertext[:8]
    actual_ciphertext = ciphertext[8:]

    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    unpadder = padding.PKCS7(algorithms.Blowfish.block_size).unpadder()
    padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode('utf-8')


if __name__ == '__main__':
    key = urandom(16)
    plaintext = "Hello, Blowfish!"

    ciphertext = blowfish_encrypt(plaintext, key)
    print("Encrypted:", ciphertext)

    decrypted_text = blowfish_decrypt(ciphertext, key)
    print("Decrypted:", decrypted_text)
