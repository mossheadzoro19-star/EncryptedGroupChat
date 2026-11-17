from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# Alice creates her private key
alice_private_key = X25519PrivateKey.generate()

# Bob creates his private key
bob_private_key = X25519PrivateKey.generate()


# Get public keys
alice_public_key = alice_private_key.public_key()
bob_public_key = bob_private_key.public_key()


# X25519 key agreement
alice_shared_secret = alice_private_key.exchange(bob_public_key)
bob_shared_secret = bob_private_key.exchange(alice_public_key)


# Derive a new key using HKDF
alice_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"encrypted-group-chat"
).derive(alice_shared_secret)


bob_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"encrypted-group-chat"
).derive(bob_shared_secret)


print("Alice derived key:")
print(alice_derived_key.hex())

print()

print("Bob derived key:")
print(bob_derived_key.hex())

print()

print("Are both derived keys equal?")
print(alice_derived_key == bob_derived_key)