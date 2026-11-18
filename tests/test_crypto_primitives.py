import base64

import pytest
from cryptography.exceptions import InvalidTag, InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import client_keys
import member_keys
from crypto_utils import (
    create_shared_secret,
    derive_key,
    generate_x25519_key_pair,
    unwrap_group_key,
    wrap_group_key,
)
from key_manager import create_new_group_key_version, generate_group_key
from message_crypto import (
    decrypt_message,
    encrypt_message,
    sign_message,
    verify_message_signature,
)


def test_group_key_is_32_random_bytes():
    first = generate_group_key()
    second = generate_group_key()
    assert len(first) == 32
    assert len(second) == 32
    assert first != second


def test_key_rotation_increments_version_and_changes_key():
    old_key = generate_group_key()
    version, new_key = create_new_group_key_version(4)
    assert version == 5
    assert len(new_key) == 32
    assert new_key != old_key


def test_x25519_parties_derive_same_shared_secret():
    alice_private, alice_public = generate_x25519_key_pair()
    bob_private, bob_public = generate_x25519_key_pair()
    assert create_shared_secret(alice_private, bob_public) == create_shared_secret(
        bob_private, alice_public
    )


def test_hkdf_derives_32_byte_key_deterministically():
    secret = b"shared secret for test"
    assert len(derive_key(secret)) == 32
    assert derive_key(secret) == derive_key(secret)


def test_group_key_wrap_and_unwrap_round_trip():
    alice_private, alice_public = generate_x25519_key_pair()
    bob_private, bob_public = generate_x25519_key_pair()
    alice_secret = create_shared_secret(alice_private, bob_public)
    bob_secret = create_shared_secret(bob_private, alice_public)
    group_key = generate_group_key()
    nonce, wrapped = wrap_group_key(group_key, alice_secret)
    assert unwrap_group_key(nonce, wrapped, bob_secret) == group_key


def test_wrapped_group_key_rejects_tampering():
    alice_private, alice_public = generate_x25519_key_pair()
    bob_private, bob_public = generate_x25519_key_pair()
    secret = create_shared_secret(alice_private, bob_public)
    nonce, wrapped = wrap_group_key(generate_group_key(), secret)
    damaged = bytearray(wrapped)
    damaged[0] ^= 1
    with pytest.raises(InvalidTag):
        unwrap_group_key(nonce, bytes(damaged), secret)


def test_message_encryption_decryption_round_trip():
    key = generate_group_key()
    encrypted = encrypt_message(key, "hello secure group")
    assert decrypt_message(key, encrypted["ciphertext"], encrypted["nonce"]) == (
        "hello secure group"
    )


def test_message_decryption_rejects_tampered_ciphertext():
    key = generate_group_key()
    encrypted = encrypt_message(key, "do not alter")
    raw = bytearray(base64.b64decode(encrypted["ciphertext"]))
    raw[0] ^= 1
    damaged = base64.b64encode(raw).decode()
    with pytest.raises(InvalidTag):
        decrypt_message(key, damaged, encrypted["nonce"])


def test_ed25519_signature_verifies_and_detects_changes():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    ciphertext = "ciphertext"
    nonce = "nonce"
    signature = sign_message(private_key, ciphertext, nonce, 1, 2)
    assert verify_message_signature(public_key, signature, ciphertext, nonce, 1, 2)
    assert not verify_message_signature(
        public_key, signature, ciphertext + "changed", nonce, 1, 2
    )
    assert not verify_message_signature(
        public_key, signature, ciphertext, nonce, 2, 2
    )


def test_group_key_envelope_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(member_keys, "KEY_FOLDER", str(tmp_path / "member_keys"))
    group_key = generate_group_key()
    envelope = member_keys.create_group_key_envelope(group_key, "Alice", "Bob")
    recovered = member_keys.open_group_key_envelope(envelope, "Bob")
    assert recovered == group_key


def test_group_key_storage_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(client_keys, "KEY_FOLDER", str(tmp_path / "client_keys"))
    key = generate_group_key()
    filename = client_keys.save_group_key(42, 3, key)
    assert client_keys.key_exists(42, 3)
    assert client_keys.load_group_key(42, 3) == key
    assert filename.endswith("group_42_v3.key")


def test_missing_stored_group_key_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(client_keys, "KEY_FOLDER", str(tmp_path / "client_keys"))
    assert client_keys.load_group_key(999, 1) is None
    assert not client_keys.key_exists(999, 1)
