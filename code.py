from Crypto.Cipher import AES, ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# AES encryption function
def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return cipher.iv + ciphertext

# AES decryption function
def aes_decrypt(key, ciphertext):
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# ChaCha20 encryption function
def chacha20_encrypt(key, plaintext):
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.nonce + cipher.encrypt(plaintext)
    return ciphertext

# ChaCha20 decryption function
def chacha20_decrypt(key, ciphertext):
    nonce = ciphertext[:8]
    ciphertext = ciphertext[8:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# Combined encryption function
def combined_encrypt(key, plaintext):
    # aes_key = get_random_bytes(32)  # AES key
    # chacha_key = get_random_bytes(32)  # ChaCha20 key
    aes_encrypted = aes_encrypt(key, plaintext)
    combined_ciphertext = chacha20_encrypt(key, key + aes_encrypted)
    return combined_ciphertext

# Combined decryption function
def combined_decrypt(key, ciphertext):
    chacha_key = key[:32]  # Extract ChaCha20 key
    aes_key_ciphertext = chacha20_decrypt(chacha_key, ciphertext)
    aes_key = aes_key_ciphertext[:32]  # Extract AES key
    aes_ciphertext = aes_key_ciphertext[32:]
    plaintext = aes_decrypt(aes_key, aes_ciphertext)
    return plaintext

# Example usage
key = get_random_bytes(32)  # Shared key
haha = input("input the string ")
message = bytes(haha,encoding="utf-8")

encrypted = combined_encrypt(key, message)
decrypted = combined_decrypt(key, encrypted)

print("Original message:", message)
print()
print("encrypted message:- "+str(encrypted))

print()
print("decrypted message:- "+str(decrypted,encoding="utf-8"))