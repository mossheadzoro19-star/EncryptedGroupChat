
import sqlite3

DATABASE_NAME = "chat.db"


def get_connection():
    connection = sqlite3.connect(
        DATABASE_NAME,
        timeout=10
    )
    connection.row_factory = sqlite3.Row
    return connection


# -------------------------------------------------
# USERS
# -------------------------------------------------

def create_users_table():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def create_user(username, password_hash):
    connection = get_connection()

    existing_user = connection.execute(
        "SELECT id FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if existing_user:
        connection.close()
        return False

    connection.execute(
        """
        INSERT INTO users (username, password_hash)
        VALUES (?, ?)
        """,
        (username, password_hash)
    )

    connection.commit()
    connection.close()
    return True


def get_user(username):
    connection = get_connection()

    user = connection.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    connection.close()
    return user


# -------------------------------------------------
# GROUPS
# -------------------------------------------------

def create_groups_table():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            key_version INTEGER NOT NULL DEFAULT 1
        )
    """)

    connection.commit()
    connection.close()


# -------------------------------------------------
# GROUP MEMBERS
# -------------------------------------------------

def create_group_members_table():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS group_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            role TEXT NOT NULL DEFAULT 'member',
            UNIQUE(group_id, user_id)
        )
    """)

    # Add role column to older databases if needed.
    try:
        connection.execute("""
            ALTER TABLE group_members
            ADD COLUMN role TEXT NOT NULL DEFAULT 'member'
        """)
        connection.commit()
    except sqlite3.OperationalError:
        pass

    # Ensure every group with active members has an admin.
    groups = connection.execute(
        "SELECT id FROM groups"
    ).fetchall()

    for group in groups:
        admin_exists = connection.execute(
            """
            SELECT id
            FROM group_members
            WHERE group_id = ?
              AND active = 1
              AND role = 'admin'
            """,
            (group["id"],)
        ).fetchone()

        if admin_exists is None:
            first_member = connection.execute(
                """
                SELECT id
                FROM group_members
                WHERE group_id = ?
                  AND active = 1
                ORDER BY id ASC
                LIMIT 1
                """,
                (group["id"],)
            ).fetchone()

            if first_member:
                connection.execute(
                    """
                    UPDATE group_members
                    SET role = 'admin'
                    WHERE id = ?
                    """,
                    (first_member["id"],)
                )

    connection.commit()
    connection.close()


# -------------------------------------------------
# JOIN REQUESTS
# -------------------------------------------------

def create_join_requests_table():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS join_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending', 'approved', 'rejected')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(group_id, user_id)
        )
    """)

    connection.commit()
    connection.close()


def create_join_request(group_id, user_id):
    """Create a request or resubmit a previously rejected request."""

    connection = get_connection()

    # Check that the group exists.
    group = connection.execute(
        "SELECT id FROM groups WHERE id = ?",
        (group_id,)
    ).fetchone()

    if group is None:
        connection.close()
        return False, "Group not found."

    # Check that the user exists.
    user = connection.execute(
        "SELECT id FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if user is None:
        connection.close()
        return False, "User not found."

    # Existing active members do not need a join request.
    membership = connection.execute(
        """
        SELECT active
        FROM group_members
        WHERE group_id = ? AND user_id = ?
        """,
        (group_id, user_id)
    ).fetchone()

    if membership and membership["active"] == 1:
        connection.close()
        return False, "You are already an active member."

    # Prevent duplicate pending requests.
    existing_request = connection.execute(
        """
        SELECT id, status
        FROM join_requests
        WHERE group_id = ? AND user_id = ?
        """,
        (group_id, user_id)
    ).fetchone()

    if existing_request:
        if existing_request["status"] == "pending":
            connection.close()
            return False, "Your request is already pending."

        # Allow a rejected or previously handled request to be
        # submitted again, without creating duplicate rows.
        connection.execute(
            """
            UPDATE join_requests
            SET status = 'pending',
                created_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (existing_request["id"],)
        )
    else:
        connection.execute(
            """
            INSERT INTO join_requests (group_id, user_id, status)
            VALUES (?, ?, 'pending')
            """,
            (group_id, user_id)
        )

    connection.commit()
    connection.close()
    return True, "Join request submitted."


def get_group_join_requests(group_id):
    """Return join requests for a group, including usernames."""

    connection = get_connection()

    requests = connection.execute(
        """
        SELECT
            jr.id AS request_id,
            jr.group_id,
            jr.user_id,
            jr.status,
            jr.created_at,
            u.username
        FROM join_requests AS jr
        JOIN users AS u ON u.id = jr.user_id
        WHERE jr.group_id = ?
        ORDER BY
            CASE WHEN jr.status = 'pending' THEN 0 ELSE 1 END,
            jr.created_at DESC
        """,
        (group_id,)
    ).fetchall()

    connection.close()
    return requests


def get_join_request(request_id):
    connection = get_connection()

    request = connection.execute(
        """
        SELECT *
        FROM join_requests
        WHERE id = ?
        """,
        (request_id,)
    ).fetchone()

    connection.close()
    return request


def update_join_request_status(request_id, status):
    """Update a request to approved or rejected."""

    if status not in ("approved", "rejected"):
        return False

    connection = get_connection()

    cursor = connection.execute(
        """
        UPDATE join_requests
        SET status = ?
        WHERE id = ? AND status = 'pending'
        """,
        (status, request_id)
    )

    connection.commit()
    updated = cursor.rowcount > 0
    connection.close()
    return updated


# -------------------------------------------------
# GROUP KEY ENVELOPES
# -------------------------------------------------

def create_group_key_envelopes_table():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS group_key_envelopes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            key_version INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            nonce TEXT NOT NULL,
            encrypted_group_key TEXT NOT NULL,
            UNIQUE(group_id, key_version, user_id)
        )
    """)

    connection.commit()
    connection.close()


def save_group_key_envelope(
    group_id,
    key_version,
    user_id,
    nonce,
    encrypted_group_key
):
    connection = get_connection()

    connection.execute(
        """
        INSERT OR REPLACE INTO group_key_envelopes (
            group_id,
            key_version,
            user_id,
            nonce,
            encrypted_group_key
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            group_id,
            key_version,
            user_id,
            nonce,
            encrypted_group_key
        )
    )

    connection.commit()
    connection.close()


def get_group_key_envelope(group_id, key_version, user_id):
    connection = get_connection()

    envelope = connection.execute(
        """
        SELECT *
        FROM group_key_envelopes
        WHERE group_id = ?
          AND key_version = ?
          AND user_id = ?
        """,
        (group_id, key_version, user_id)
    ).fetchone()

    connection.close()
    return envelope


# -------------------------------------------------
# MESSAGES
# -------------------------------------------------

def create_messages_table():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            ciphertext TEXT NOT NULL,
            nonce TEXT NOT NULL,
            signature TEXT NOT NULL,
            sender_public_key TEXT,
            sequence_number INTEGER NOT NULL,
            key_version INTEGER NOT NULL
        )
    """)

    # Add the public-key column to older databases if needed.
    try:
        connection.execute("""
            ALTER TABLE messages
            ADD COLUMN sender_public_key TEXT
        """)
        connection.commit()
    except sqlite3.OperationalError:
        pass

    connection.close()


def save_message(
    group_id,
    sender_id,
    ciphertext,
    nonce,
    signature,
    sender_public_key,
    sequence_number,
    key_version
):
    connection = get_connection()

    cursor = connection.execute(
        """
        INSERT INTO messages (
            group_id,
            sender_id,
            ciphertext,
            nonce,
            signature,
            sender_public_key,
            sequence_number,
            key_version
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            group_id,
            sender_id,
            ciphertext,
            nonce,
            signature,
            sender_public_key,
            sequence_number,
            key_version
        )
    )

    message_id = cursor.lastrowid

    connection.commit()
    connection.close()
    return message_id


def get_group_messages(group_id):
    connection = get_connection()

    messages = connection.execute(
        """
        SELECT
            messages.*,
            users.username AS sender_username
        FROM messages
        JOIN users ON users.id = messages.sender_id
        WHERE messages.group_id = ?
        ORDER BY messages.sequence_number ASC
        """,
        (group_id,)
    ).fetchall()

    connection.close()
    return messages


def get_next_sequence_number(group_id):
    connection = get_connection()

    result = connection.execute(
        """
        SELECT MAX(sequence_number) AS max_sequence
        FROM messages
        WHERE group_id = ?
        """,
        (group_id,)
    ).fetchone()

    connection.close()

    if result["max_sequence"] is None:
        return 1

    return result["max_sequence"] + 1


# -------------------------------------------------
# REPLAY TRACKING
# -------------------------------------------------

def create_replay_table():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS replay_tracker (
            group_id INTEGER PRIMARY KEY,
            highest_sequence INTEGER NOT NULL DEFAULT 0
        )
    """)

    connection.commit()
    connection.close()


def get_highest_sequence(group_id):
    connection = get_connection()

    result = connection.execute(
        """
        SELECT highest_sequence
        FROM replay_tracker
        WHERE group_id = ?
        """,
        (group_id,)
    ).fetchone()

    connection.close()

    if result is None:
        return 0

    return result["highest_sequence"]


def update_highest_sequence(group_id, sequence_number):
    connection = get_connection()

    connection.execute(
        """
        INSERT INTO replay_tracker (group_id, highest_sequence)
        VALUES (?, ?)
        ON CONFLICT(group_id)
        DO UPDATE SET highest_sequence = excluded.highest_sequence
        """,
        (group_id, sequence_number)
    )

    connection.commit()
    connection.close()


# -------------------------------------------------
# ACTIVE MEMBER COUNT
# -------------------------------------------------

def get_active_member_count(group_id):
    connection = get_connection()

    result = connection.execute(
        """
        SELECT COUNT(*) AS member_count
        FROM group_members
        WHERE group_id = ?
          AND active = 1
        """,
        (group_id,)
    ).fetchone()

    connection.close()
    return result["member_count"]


# -------------------------------------------------
# CREATE ALL TABLES
# -------------------------------------------------

def create_all_tables():
    create_users_table()
    create_groups_table()
    create_group_members_table()
    create_join_requests_table()
    create_group_key_envelopes_table()
    create_messages_table()
    create_replay_table()
