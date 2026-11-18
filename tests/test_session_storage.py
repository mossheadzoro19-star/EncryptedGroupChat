import time

import database


def test_session_lifecycle_and_expiry(tmp_path, monkeypatch):
    db_path = tmp_path / "sessions.db"
    monkeypatch.setattr(database, "DATABASE_NAME", str(db_path))

    database.create_users_table()
    database.create_sessions_table()
    assert database.create_user("Alice", "test-password-hash")

    user = database.get_user("Alice")
    token_hash = "a" * 64

    database.store_session(
        user["id"],
        token_hash,
        int(time.time()) + 60,
    )
    session = database.get_valid_session(token_hash)

    assert session is not None
    assert session["username"] == "Alice"

    database.revoke_session(token_hash)
    assert database.get_valid_session(token_hash) is None


def test_expired_session_is_not_valid(tmp_path, monkeypatch):
    db_path = tmp_path / "expired.db"
    monkeypatch.setattr(database, "DATABASE_NAME", str(db_path))

    database.create_users_table()
    database.create_sessions_table()
    assert database.create_user("Bob", "test-password-hash")

    user = database.get_user("Bob")
    token_hash = "b" * 64
    database.store_session(user["id"], token_hash, int(time.time()) - 1)

    assert database.get_valid_session(token_hash) is None
