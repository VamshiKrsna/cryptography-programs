from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def rijndael_encrypt(plaintext, key):
    # generate a random IV (Initialization Vector)
    iv = get_random_bytes(16)

    # create AES cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # padding the plaintext and encrypt
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))

    return iv + ciphertext


def rijndael_decrypt(ciphertext, key):
    # extract IV and actual ciphertext
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    # create AES cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # decrypt and unpad the plaintext
    plaintext = unpad(cipher.decrypt(actual_ciphertext), AES.block_size)

    return plaintext.decode('utf-8')


if __name__ == '__main__':
    key = get_random_bytes(16)
    plaintext = "Hello, Rijndael (AES)!"

    ciphertext = rijndael_encrypt(plaintext, key)
    print("Encrypted:", ciphertext)

    decrypted_text = rijndael_decrypt(ciphertext, key)
    print("Decrypted:", decrypted_text)
