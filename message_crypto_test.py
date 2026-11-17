from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)

from message_crypto import (
    encrypt_message,
    decrypt_message,
    sign_message,
    verify_message_signature
)

from key_manager import generate_group_key


# -------------------------------------------------
# CREATE KEYS
# -------------------------------------------------

group_key = generate_group_key()

sender_private_key = Ed25519PrivateKey.generate()
sender_public_key = sender_private_key.public_key()


# -------------------------------------------------
# MESSAGE DETAILS
# -------------------------------------------------

message = "Hello group! This is a secure message."

sequence_number = 1
key_version = 2


# -------------------------------------------------
# ENCRYPT
# -------------------------------------------------

encrypted = encrypt_message(
    group_key,
    message
)

ciphertext = encrypted["ciphertext"]
nonce = encrypted["nonce"]


print("Encrypted message:")
print(ciphertext)

print()


# -------------------------------------------------
# SIGN
# -------------------------------------------------

signature = sign_message(
    sender_private_key,
    ciphertext,
    nonce,
    sequence_number,
    key_version
)


print("Signature created successfully.")
print()


# -------------------------------------------------
# VERIFY
# -------------------------------------------------

signature_valid = verify_message_signature(
    sender_public_key,
    signature,
    ciphertext,
    nonce,
    sequence_number,
    key_version
)


print("Signature valid?")
print(signature_valid)

print()


# -------------------------------------------------
# DECRYPT
# -------------------------------------------------

decrypted = decrypt_message(
    group_key,
    ciphertext,
    nonce
)


print("Decrypted message:")
print(decrypted)

print()


# -------------------------------------------------
# TAMPERING TEST
# -------------------------------------------------

tampered_ciphertext = ciphertext[:-2] + "AA"


print("Testing tampered message...")

tampered_valid = verify_message_signature(
    sender_public_key,
    signature,
    tampered_ciphertext,
    nonce,
    sequence_number,
    key_version
)


print("Tampered signature accepted?")
print(tampered_valid)