import time

from key_manager import generate_group_key
from member_keys import (
    get_or_create_x25519_key,
    create_group_key_envelope
)


NUMBER_OF_USERS = 20


print("Starting 20-user performance test...")
print()


# -------------------------------------------------
# Create 20 users
# -------------------------------------------------

users = []

start_time = time.perf_counter()

for i in range(1, NUMBER_OF_USERS + 1):

    username = f"TestUser{i}"

    get_or_create_x25519_key(username)

    users.append(username)


user_creation_time = (
    time.perf_counter() - start_time
)


# -------------------------------------------------
# Generate group key
# -------------------------------------------------

group_key = generate_group_key()


# -------------------------------------------------
# Create encrypted group-key envelopes
# -------------------------------------------------

start_time = time.perf_counter()

envelopes_created = 0

for username in users:

    envelope = create_group_key_envelope(
        group_key,
        "Alice",
        username
    )

    if envelope:
        envelopes_created += 1


envelope_time = (
    time.perf_counter() - start_time
)


# -------------------------------------------------
# Results
# -------------------------------------------------

print("Users tested:", NUMBER_OF_USERS)

print(
    "Users created:",
    len(users)
)

print(
    "Key envelopes created:",
    envelopes_created
)

print(
    "User key generation time:",
    round(user_creation_time, 4),
    "seconds"
)

print(
    "Envelope generation time:",
    round(envelope_time, 4),
    "seconds"
)

print()

print("20-user performance test completed successfully.")