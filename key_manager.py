import os


# -------------------------------------------------
# GROUP KEY GENERATION
# -------------------------------------------------

def generate_group_key():
    """
    Generate a random 256-bit group key.

    AES-256 requires a 32-byte key.
    """

    return os.urandom(32)


# -------------------------------------------------
# KEY VERSION
# -------------------------------------------------

def create_new_group_key_version(current_version):
    """
    Create a new group key and increase
    the group key version.
    """

    new_version = current_version + 1

    new_group_key = generate_group_key()

    return new_version, new_group_key


# -------------------------------------------------
# DISPLAY KEY FOR TESTING
# -------------------------------------------------

def key_to_hex(group_key):
    return group_key.hex()