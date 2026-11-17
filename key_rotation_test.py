from key_manager import (
    generate_group_key,
    create_new_group_key_version
)


# Initial group key
old_key = generate_group_key()

old_version = 1

print("Old key version:")
print(old_version)

print()

print("Old group key:")
print(old_key.hex())

print()


# Rotate the group key
new_version, new_key = create_new_group_key_version(
    old_version
)

print("New key version:")
print(new_version)

print()

print("New group key:")
print(new_key.hex())

print()

print("Is the new key different?")
print(old_key != new_key)