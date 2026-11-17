from key_manager import generate_group_key

from member_keys import (
    get_or_create_x25519_key,
    create_group_key_envelope,
    open_group_key_envelope
)


# -------------------------------------------------
# Generate Alice and Bob X25519 keys
# -------------------------------------------------

alice_key = get_or_create_x25519_key(
    "Alice"
)

bob_key = get_or_create_x25519_key(
    "Bob"
)


# -------------------------------------------------
# Create a group key
# -------------------------------------------------

group_key = generate_group_key()


print(
    "Original group key length:",
    len(group_key)
)


# -------------------------------------------------
# Alice creates an encrypted envelope for Bob
# -------------------------------------------------

envelope = create_group_key_envelope(
    group_key,
    "Alice",
    "Bob"
)


print(
    "Encrypted group key created:",
    True
)


# -------------------------------------------------
# Bob opens the envelope
# -------------------------------------------------

recovered_group_key = open_group_key_envelope(
    envelope,
    "Bob"
)


# -------------------------------------------------
# Verify
# -------------------------------------------------

print(
    "Group key recovered correctly:",
    recovered_group_key == group_key
)