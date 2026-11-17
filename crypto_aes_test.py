from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


# Generate a 256-bit AES key
key = AESGCM.generate_key(bit_length=256)

# Create AES-GCM object
aes = AESGCM(key)


# Message to encrypt
message = b"Hello Bob! This is a secret message."


# Generate a fresh 12-byte nonce
nonce = os.urandom(12)


# Encrypt the message
ciphertext = aes.encrypt(
    nonce,
    message,
    None
)


print("Original message:")
print(message.decode())

print()

print("Encrypted message:")
print(ciphertext.hex())

print()

# Decrypt the message
decrypted_message = aes.decrypt(
    nonce,
    ciphertext,
    None
)


print("Decrypted message:")
print(decrypted_message.decode())

print()

print("Encryption/Decryption successful?")
print(decrypted_message == message)


# -------------------------
# Tampering test
# -------------------------

tampered_ciphertext = bytearray(ciphertext)

# Change one byte
tampered_ciphertext[0] ^= 1

print()
print("Testing tampered message...")

try:
    aes.decrypt(
        nonce,
        bytes(tampered_ciphertext),
        None
    )

    print("Tampering was NOT detected")

except Exception:
    print("Tampering detected successfully!")