from client_keys import (
    save_group_key,
    load_group_key,
    key_exists
)

import os


# Create a test 256-bit key
test_key = os.urandom(32)

group_id = 3
key_version = 2


# Save key
filename = save_group_key(
    group_id,
    key_version,
    test_key
)

print("Key saved:")
print(filename)

print()


# Check if key exists
print("Key exists?")
print(
    key_exists(
        group_id,
        key_version
    )
)

print()


# Load key
loaded_key = load_group_key(
    group_id,
    key_version
)

print("Loaded key matches original?")
print(
    loaded_key == test_key
)
