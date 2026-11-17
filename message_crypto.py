import os
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)


# -------------------------------------------------
# ENCRYPT MESSAGE
# -------------------------------------------------

def encrypt_message(group_key, message):
    """
    Encrypt a message using AES-256-GCM.
    """

    nonce = os.urandom(12)

    aes = AESGCM(group_key)

    ciphertext = aes.encrypt(
        nonce,
        message.encode(),
        None
    )

    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode()
    }


# -------------------------------------------------
# DECRYPT MESSAGE
# -------------------------------------------------

def decrypt_message(group_key, ciphertext, nonce):
    """
    Decrypt an AES-256-GCM encrypted message.
    """

    aes = AESGCM(group_key)

    ciphertext_bytes = base64.b64decode(ciphertext)
    nonce_bytes = base64.b64decode(nonce)

    plaintext = aes.decrypt(
        nonce_bytes,
        ciphertext_bytes,
        None
    )

    return plaintext.decode()


# -------------------------------------------------
# SIGN MESSAGE
# -------------------------------------------------

def sign_message(private_key, ciphertext, nonce, sequence_number, key_version):
    """
    Sign message metadata and ciphertext using Ed25519.
    """

    data = (
        ciphertext.encode()
        + nonce.encode()
        + str(sequence_number).encode()
        + str(key_version).encode()
    )

    return private_key.sign(data)


# -------------------------------------------------
# VERIFY MESSAGE SIGNATURE
# -------------------------------------------------

def verify_message_signature(
    public_key,
    signature,
    ciphertext,
    nonce,
    sequence_number,
    key_version
):
    """
    Verify the sender's Ed25519 signature.
    """

    data = (
        ciphertext.encode()
        + nonce.encode()
        + str(sequence_number).encode()
        + str(key_version).encode()
    )

    try:
        public_key.verify(
            signature,
            data
        )

        return True

    except Exception:
        return False