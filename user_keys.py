import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)


KEY_FOLDER = "user_keys"


# -------------------------------------------------
# CREATE KEY FOLDER
# -------------------------------------------------

def create_key_folder():
    os.makedirs(KEY_FOLDER, exist_ok=True)


# -------------------------------------------------
# GENERATE USER SIGNING KEY
# -------------------------------------------------

def generate_user_signing_key(username):

    create_key_folder()

    private_key = Ed25519PrivateKey.generate()

    filename = os.path.join(
        KEY_FOLDER,
        f"{username}_signing.key"
    )

    with open(filename, "wb") as file:
        file.write(
            private_key.private_bytes_raw()
        )

    return private_key


# -------------------------------------------------
# LOAD USER SIGNING KEY
# -------------------------------------------------

def load_user_signing_key(username):

    create_key_folder()

    filename = os.path.join(
        KEY_FOLDER,
        f"{username}_signing.key"
    )

    if not os.path.exists(filename):
        return None

    with open(filename, "rb") as file:
        private_key_bytes = file.read()

    return Ed25519PrivateKey.from_private_bytes(
        private_key_bytes
    )


# -------------------------------------------------
# GET OR CREATE USER KEY
# -------------------------------------------------

def get_or_create_user_signing_key(username):

    private_key = load_user_signing_key(username)

    if private_key is not None:
        return private_key

    return generate_user_signing_key(username)