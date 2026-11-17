from crypto_utils import (
    generate_x25519_key_pair,
    create_shared_secret,
    wrap_group_key,
    unwrap_group_key
)


# -------------------------------------------------
# Generate Alice and Bob X25519 keys
# -------------------------------------------------

alice_private, alice_public = generate_x25519_key_pair()
bob_private, bob_public = generate_x25519_key_pair()


# -------------------------------------------------
# Create shared secret
# -------------------------------------------------

alice_shared_secret = create_shared_secret(
    alice_private,
    bob_public
)

bob_shared_secret = create_shared_secret(
    bob_private,
    alice_public
)


print(
    "Shared secrets equal:",
    alice_shared_secret == bob_shared_secret
)


# -------------------------------------------------
# Create a group key
# -------------------------------------------------

group_key = b"12345678901234567890123456789012"


# -------------------------------------------------
# Alice wraps the group key
# -------------------------------------------------

nonce, encrypted_group_key = wrap_group_key(
    group_key,
    alice_shared_secret
)


print(
    "Group key wrapped successfully"
)


# -------------------------------------------------
# Bob unwraps the group key
# -------------------------------------------------

recovered_group_key = unwrap_group_key(
    nonce,
    encrypted_group_key,
    bob_shared_secret
)


print(
    "Group key recovered:",
    recovered_group_key == group_key
)