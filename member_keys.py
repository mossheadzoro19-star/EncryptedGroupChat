import os
import base64

from crypto_utils import (
    generate_x25519_key_pair,
    create_shared_secret,
    wrap_group_key,
    unwrap_group_key
)


KEY_FOLDER = "member_keys"


# -------------------------------------------------
# CREATE KEY FOLDER
# -------------------------------------------------

def create_key_folder():
    os.makedirs(
        KEY_FOLDER,
        exist_ok=True
    )


# -------------------------------------------------
# SAVE X25519 PRIVATE KEY
# -------------------------------------------------

def save_private_key(
    username,
    private_key
):

    create_key_folder()

    filename = os.path.join(
        KEY_FOLDER,
        f"{username}_x25519.key"
    )

    with open(filename, "wb") as file:

        file.write(
            private_key.private_bytes_raw()
        )


# -------------------------------------------------
# LOAD X25519 PRIVATE KEY
# -------------------------------------------------

def load_private_key(username):

    create_key_folder()

    filename = os.path.join(
        KEY_FOLDER,
        f"{username}_x25519.key"
    )

    if not os.path.exists(filename):

        return None

    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey
    )

    with open(filename, "rb") as file:

        private_key_bytes = file.read()

    return X25519PrivateKey.from_private_bytes(
        private_key_bytes
    )


# -------------------------------------------------
# GET OR CREATE X25519 KEY
# -------------------------------------------------

def get_or_create_x25519_key(username):

    private_key = load_private_key(
        username
    )

    if private_key is not None:

        return private_key

    private_key, public_key = (
        generate_x25519_key_pair()
    )

    save_private_key(
        username,
        private_key
    )

    return private_key


# -------------------------------------------------
# GET PUBLIC KEY
# -------------------------------------------------

def get_public_key(username):

    private_key = get_or_create_x25519_key(
        username
    )

    public_key = private_key.public_key()

    return base64.b64encode(
        public_key.public_bytes_raw()
    ).decode()


# -------------------------------------------------
# CREATE GROUP KEY ENVELOPE
# -------------------------------------------------

def create_group_key_envelope(
    group_key,
    sender_username,
    receiver_username
):

    sender_private_key = (
        get_or_create_x25519_key(
            sender_username
        )
    )

    receiver_private_key = (
        get_or_create_x25519_key(
            receiver_username
        )
    )

    receiver_public_key = (
        receiver_private_key.public_key()
    )

    shared_secret = create_shared_secret(
        sender_private_key,
        receiver_public_key
    )

    nonce, encrypted_group_key = (
        wrap_group_key(
            group_key,
            shared_secret
        )
    )

    return {
        "sender": sender_username,
        "receiver": receiver_username,
        "nonce": base64.b64encode(
            nonce
        ).decode(),
        "encrypted_group_key": base64.b64encode(
            encrypted_group_key
        ).decode()
    }


# -------------------------------------------------
# OPEN GROUP KEY ENVELOPE
# -------------------------------------------------

def open_group_key_envelope(
    envelope,
    receiver_username
):

    receiver_private_key = (
        get_or_create_x25519_key(
            receiver_username
        )
    )

    sender_private_key = (
        get_or_create_x25519_key(
            envelope["sender"]
        )
    )

    sender_public_key = (
        sender_private_key.public_key()
    )

    shared_secret = create_shared_secret(
        receiver_private_key,
        sender_public_key
    )

    nonce = base64.b64decode(
        envelope["nonce"]
    )

    encrypted_group_key = base64.b64decode(
        envelope["encrypted_group_key"]
    )

    return unwrap_group_key(
        nonce,
        encrypted_group_key,
        shared_secret
    )