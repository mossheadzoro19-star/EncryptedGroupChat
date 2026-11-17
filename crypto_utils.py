import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# -------------------------------------------------
# X25519
# -------------------------------------------------

def generate_x25519_key_pair():
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key


def create_shared_secret(private_key, other_public_key):
    return private_key.exchange(other_public_key)


# -------------------------------------------------
# HKDF
# -------------------------------------------------

def derive_key(shared_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"encrypted-group-chat"
    ).derive(shared_secret)


# -------------------------------------------------
# GROUP KEY WRAPPING
# -------------------------------------------------

def wrap_group_key(group_key, shared_secret):
    """
    Derive a wrapping key from the X25519 shared secret
    and use AES-256-GCM to protect the group key.
    """

    wrapping_key = derive_key(shared_secret)

    aes = AESGCM(wrapping_key)

    nonce = os.urandom(12)

    encrypted_group_key = aes.encrypt(
        nonce,
        group_key,
        None
    )

    return nonce, encrypted_group_key


def unwrap_group_key(nonce, encrypted_group_key, shared_secret):
    """
    Recover the group key using the same X25519-derived
    AES-256-GCM wrapping key.
    """

    wrapping_key = derive_key(shared_secret)

    aes = AESGCM(wrapping_key)

    group_key = aes.decrypt(
        nonce,
        encrypted_group_key,
        None
    )

    return group_key


# -------------------------------------------------
# AES-256-GCM
# -------------------------------------------------

def encrypt_message(key, message):
    aes = AESGCM(key)

    # Fresh nonce for every message
    nonce = os.urandom(12)

    ciphertext = aes.encrypt(
        nonce,
        message.encode(),
        None
    )

    return nonce, ciphertext


def decrypt_message(key, nonce, ciphertext):
    aes = AESGCM(key)

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode()


# -------------------------------------------------
# Ed25519
# -------------------------------------------------

def generate_signature_key_pair():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key


def sign_message(private_key, message):
    return private_key.sign(message)


def verify_signature(public_key, signature, message):
    try:
        public_key.verify(signature, message)

        return True

    except Exception:
        return False