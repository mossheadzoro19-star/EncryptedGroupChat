from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


# Alice creates her private key
alice_private_key = X25519PrivateKey.generate()

# Bob creates his private key
bob_private_key = X25519PrivateKey.generate()


# Get their public keys
alice_public_key = alice_private_key.public_key()
bob_public_key = bob_private_key.public_key()


# Alice calculates the shared secret using Bob's public key
alice_shared_secret = alice_private_key.exchange(bob_public_key)


# Bob calculates the shared secret using Alice's public key
bob_shared_secret = bob_private_key.exchange(alice_public_key)


print("Alice shared secret:")
print(alice_shared_secret.hex())

print()

print("Bob shared secret:")
print(bob_shared_secret.hex())

print()

print("Are both secrets equal?")
print(alice_shared_secret == bob_shared_secret)