from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# Sender creates a private key
private_key = Ed25519PrivateKey.generate()

# Get public key
public_key = private_key.public_key()


# Message to sign
message = b"Hello group! This is Alice."


# Create digital signature
signature = private_key.sign(message)

print("Original message:")
print(message.decode())

print()

print("Signature:")
print(signature.hex())

print()


# Verify the signature
try:
    public_key.verify(signature, message)
    print("Signature verification successful!")

except Exception:
    print("Signature verification failed!")


# -------------------------
# Tampering test
# -------------------------

tampered_message = b"Hello group! This is Bob."

print()
print("Testing modified message...")

try:
    public_key.verify(signature, tampered_message)
    print("Tampering was NOT detected")

except Exception:
    print("Tampering detected successfully!")