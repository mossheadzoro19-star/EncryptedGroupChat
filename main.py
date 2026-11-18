
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import base64
import hashlib
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from database import (
    create_all_tables,
    create_user,
    get_user,
    get_connection,
    save_message,
    get_next_sequence_number,
    get_group_messages,
    get_highest_sequence,
    update_highest_sequence,
    save_group_key_envelope,
    get_group_key_envelope,
    get_active_member_count,
    create_join_request,
    get_group_join_requests,
    get_join_request,
    update_join_request_status,
)

from message_crypto import (
    encrypt_message,
    decrypt_message,
    sign_message,
    verify_message_signature,
)

from key_manager import generate_group_key
from client_keys import save_group_key, load_group_key
from user_keys import get_or_create_user_signing_key
from member_keys import get_or_create_x25519_key, create_group_key_envelope


app = FastAPI()
create_all_tables()

app.mount("/static", StaticFiles(directory="static"), name="static")


# -------------------------------------------------
# PAGES
# -------------------------------------------------

@app.get("/")
def home():
    return {"message": "Secure Group Chat Server is running!"}


@app.get("/chat")
def chat_page():
    return FileResponse("static/index.html")


# -------------------------------------------------
# REQUEST MODELS
# -------------------------------------------------

class UserRegistration(BaseModel):
    username: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class GroupCreate(BaseModel):
    group_name: str
    username: str


class AddMember(BaseModel):
    group_id: int
    username: str
    admin_username: str


class RemoveMember(BaseModel):
    group_id: int
    username: str
    admin_username: str


class SendMessage(BaseModel):
    group_id: int
    username: str
    message: str


class JoinRequestCreate(BaseModel):
    group_id: int
    username: str


class JoinRequestDecision(BaseModel):
    group_id: int
    request_id: int
    admin_username: str
    action: str


class GroupRoleChange(BaseModel):
    group_id: int
    admin_username: str
    username: str
    role: str


class MemberPermissionChange(BaseModel):
    group_id: int
    admin_username: str
    username: str
    can_add_members: bool


class MessageDelete(BaseModel):
    group_id: int
    admin_username: str


# -------------------------------------------------
# PASSWORD HASHING
# -------------------------------------------------

def hash_password(password):
    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        100000,
    )
    return salt.hex() + ":" + password_hash.hex()


def verify_password(password, stored_password):
    try:
        salt_hex, hash_hex = stored_password.split(":")
        salt = bytes.fromhex(salt_hex)
        new_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            100000,
        )
        return new_hash.hex() == hash_hex
    except (ValueError, TypeError):
        return False


# -------------------------------------------------
# GROUP KEY ENVELOPES
# -------------------------------------------------

def create_member_envelope(
    group_id,
    key_version,
    group_key,
    sender_username,
    receiver_username,
):
    envelope = create_group_key_envelope(
        group_key,
        sender_username,
        receiver_username,
    )

    receiver = get_user(receiver_username)
    if receiver is None:
        return False

    save_group_key_envelope(
        group_id,
        key_version,
        receiver["id"],
        envelope["nonce"],
        envelope["encrypted_group_key"],
    )
    return True


# -------------------------------------------------
# ADMIN / MEMBERSHIP HELPERS
# -------------------------------------------------

def get_user_by_id(user_id):
    connection = get_connection()
    try:
        return connection.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    finally:
        connection.close()


def is_group_admin(group_id, username):
    user = get_user(username)
    if user is None:
        return False

    connection = get_connection()
    try:
        member = connection.execute(
            """
            SELECT id
            FROM group_members
            WHERE group_id = ?
              AND user_id = ?
              AND active = 1
              AND role = 'admin'
            """,
            (group_id, user["id"]),
        ).fetchone()
        return member is not None
    finally:
        connection.close()


def can_member_add_members(group_id, username):
    user = get_user(username)
    if user is None:
        return False
    connection = get_connection()
    try:
        member = connection.execute(
            """
            SELECT role, can_add_members
            FROM group_members
            WHERE group_id = ? AND user_id = ? AND active = 1
            """,
            (group_id, user["id"]),
        ).fetchone()
        return bool(member and (
            member["role"] == "admin" or member["can_add_members"] == 1
        ))
    finally:
        connection.close()


def get_active_member_usernames(connection, group_id):
    return connection.execute(
        """
        SELECT users.username
        FROM group_members
        JOIN users ON group_members.user_id = users.id
        WHERE group_members.group_id = ?
          AND group_members.active = 1
        ORDER BY group_members.id ASC
        """,
        (group_id,),
    ).fetchall()


def rotate_group_key(group_id, sender_username):
    """
    Create a fresh group key and save an encrypted key envelope
    for every active member. Inactive members are excluded.
    """
    connection = get_connection()

    try:
        group = connection.execute(
            "SELECT * FROM groups WHERE id = ?",
            (group_id,),
        ).fetchone()

        if group is None:
            return None

        new_key_version = group["key_version"] + 1
        new_group_key = generate_group_key()

        connection.execute(
            "UPDATE groups SET key_version = ? WHERE id = ?",
            (new_key_version, group_id),
        )

        active_members = get_active_member_usernames(
            connection,
            group_id,
        )
        active_usernames = [
            member["username"] for member in active_members
        ]

        connection.commit()
    finally:
        connection.close()

    save_group_key(group_id, new_key_version, new_group_key)

    envelopes_created = 0
    envelope_errors = []

    for username in active_usernames:
        try:
            created = create_member_envelope(
                group_id,
                new_key_version,
                new_group_key,
                username,
                username,
            )
            if created:
                envelopes_created += 1
            else:
                envelope_errors.append(username)
        except Exception:
            envelope_errors.append(username)

    return {
        "key_version": new_key_version,
        "envelopes_created": envelopes_created,
        "envelope_errors": envelope_errors,
    }


# -------------------------------------------------
# REGISTER
# -------------------------------------------------

@app.post("/register")
def register(user: UserRegistration):
    if not user.username.strip() or not user.password:
        return {"message": "Username and password are required"}

    password_hash = hash_password(user.password)
    user_created = create_user(user.username, password_hash)

    if not user_created:
        return {"message": "Username already exists"}

    get_or_create_user_signing_key(user.username)
    get_or_create_x25519_key(user.username)

    return {
        "message": "User registered successfully",
        "username": user.username,
    }


# -------------------------------------------------
# LOGIN
# -------------------------------------------------

@app.post("/login")
def login(user: UserLogin):
    stored_user = get_user(user.username)

    if stored_user is None:
        return {"message": "Invalid username or password"}

    if not verify_password(user.password, stored_user["password_hash"]):
        return {"message": "Invalid username or password"}

    get_or_create_user_signing_key(user.username)
    get_or_create_x25519_key(user.username)

    return {
        "message": "Login successful",
        "username": user.username,
    }


# -------------------------------------------------
# CREATE GROUP
# -------------------------------------------------

@app.post("/groups/create")
def create_group(group: GroupCreate):
    user = get_user(group.username)

    if user is None:
        return {"message": "User does not exist"}

    if not group.group_name.strip():
        return {"message": "Group name is required"}

    get_or_create_x25519_key(group.username)
    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            INSERT INTO groups (name, key_version)
            VALUES (?, ?)
            """,
            (group.group_name.strip(), 1),
        )
        group_id = cursor.lastrowid

        connection.execute(
            """
            INSERT INTO group_members
                (group_id, user_id, active, role)
            VALUES (?, ?, ?, ?)
            """,
            (group_id, user["id"], 1, "admin"),
        )

        connection.commit()
    finally:
        connection.close()

    group_key = generate_group_key()
    save_group_key(group_id, 1, group_key)

    envelope_created = create_member_envelope(
        group_id,
        1,
        group_key,
        group.username,
        group.username,
    )

    return {
        "message": "Group created successfully",
        "group_id": group_id,
        "group_name": group.group_name,
        "key_version": 1,
        "role": "admin",
        "key_envelope_created": envelope_created,
    }


# -------------------------------------------------
# LIST GROUPS
# -------------------------------------------------

@app.get("/groups/list")
def list_groups():
    connection = get_connection()

    try:
        groups = connection.execute(
            """
            SELECT
                groups.id,
                groups.name,
                groups.key_version,
                COUNT(
                    CASE WHEN group_members.active = 1 THEN 1 END
                ) AS active_members
            FROM groups
            LEFT JOIN group_members
                ON groups.id = group_members.group_id
            GROUP BY groups.id, groups.name, groups.key_version
            ORDER BY groups.id DESC
            """
        ).fetchall()

        return {
            "groups": [
                {
                    "group_id": group["id"],
                    "group_name": group["name"],
                    "key_version": group["key_version"],
                    "active_members": group["active_members"],
                }
                for group in groups
            ]
        }
    finally:
        connection.close()


# -------------------------------------------------
# GROUP DIRECTORY FOR LOGGED-IN USER
# -------------------------------------------------

@app.get("/groups/discover/{username}")
def discover_groups(username: str):
    user = get_user(username)
    if user is None:
        return {"status": "rejected", "message": "User does not exist"}

    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT
                g.id AS group_id,
                g.name AS group_name,
                g.key_version,
                COUNT(CASE WHEN gm.active = 1 THEN 1 END) AS active_members,
                own.role AS my_role,
                COALESCE(jr.status, '') AS request_status
            FROM groups g
            LEFT JOIN group_members gm ON gm.group_id = g.id
            LEFT JOIN group_members own
                ON own.group_id = g.id AND own.user_id = ? AND own.active = 1
            LEFT JOIN join_requests jr
                ON jr.group_id = g.id AND jr.user_id = ?
            GROUP BY g.id, g.name, g.key_version, own.role, jr.status
            ORDER BY g.id DESC
            """,
            (user["id"], user["id"]),
        ).fetchall()

        return {
            "groups": [
                {
                    "group_id": row["group_id"],
                    "group_name": row["group_name"],
                    "key_version": row["key_version"],
                    "active_members": row["active_members"],
                    "my_role": row["my_role"] or "none",
                    "request_status": row["request_status"] or None,
                }
                for row in rows
            ]
        }
    finally:
        connection.close()


# -------------------------------------------------
# ACTIVE MEMBER COUNT
# -------------------------------------------------

@app.get("/groups/member-count/{group_id}")
def member_count(group_id: int):
    connection = get_connection()

    try:
        group = connection.execute(
            "SELECT id FROM groups WHERE id = ?",
            (group_id,),
        ).fetchone()

        if group is None:
            return {"message": "Group does not exist"}

        return {
            "group_id": group_id,
            "active_members": get_active_member_count(group_id),
        }
    finally:
        connection.close()


# -------------------------------------------------
# CHECK USER ROLE
# -------------------------------------------------

@app.get("/groups/role/{group_id}/{username}")
def get_group_role(group_id: int, username: str):
    user = get_user(username)

    if user is None:
        return {
            "group_id": group_id,
            "username": username,
            "role": "none",
        }

    connection = get_connection()

    try:
        member = connection.execute(
            """
            SELECT role, can_add_members
            FROM group_members
            WHERE group_id = ?
              AND user_id = ?
              AND active = 1
            """,
            (group_id, user["id"]),
        ).fetchone()

        return {
            "group_id": group_id,
            "username": username,
            "role": member["role"] if member else "none",
            "can_add_members": bool(member and (
                member["role"] == "admin" or member["can_add_members"]
            )),
        }
    finally:
        connection.close()


# -------------------------------------------------
# SUBMIT JOIN REQUEST
# -------------------------------------------------

@app.post("/groups/join-request")
def submit_join_request(request: JoinRequestCreate):
    user = get_user(request.username)

    if user is None:
        return {"message": "User does not exist", "status": "rejected"}

    result, message = create_join_request(
        request.group_id,
        user["id"],
    )

    return {
        "message": message,
        "status": "success" if result else "rejected",
        "group_id": request.group_id,
        "username": request.username,
    }


# -------------------------------------------------
# VIEW JOIN REQUESTS (ADMIN ONLY)
# -------------------------------------------------

@app.get("/groups/{group_id}/join-requests")
def list_join_requests(group_id: int, admin_username: str):
    if not is_group_admin(group_id, admin_username):
        return {
            "message": "Only the group admin can view join requests",
            "status": "rejected",
        }

    requests = get_group_join_requests(group_id)

    return {
        "group_id": group_id,
        "requests": [
            {
                "request_id": request["request_id"],
                "user_id": request["user_id"],
                "username": request["username"],
                "status": request["status"],
                "created_at": request["created_at"],
            }
            for request in requests
        ],
    }


# -------------------------------------------------
# APPROVE OR REJECT JOIN REQUEST (ADMIN ONLY)
# -------------------------------------------------

@app.post("/groups/join-request/decision")
def decide_join_request(decision: JoinRequestDecision):
    if not is_group_admin(
        decision.group_id,
        decision.admin_username,
    ):
        return {
            "message": "Only the group admin can decide join requests",
            "status": "rejected",
        }

    action = decision.action.strip().lower()

    if action not in ("approve", "reject"):
        return {
            "message": "Action must be approve or reject",
            "status": "rejected",
        }

    request = get_join_request(decision.request_id)

    if request is None:
        return {
            "message": "Join request does not exist",
            "status": "rejected",
        }

    if request["group_id"] != decision.group_id:
        return {
            "message": "Join request does not belong to this group",
            "status": "rejected",
        }

    if request["status"] != "pending":
        return {
            "message": "This join request has already been handled",
            "status": "rejected",
        }

    connection = get_connection()

    try:
        group = connection.execute(
            "SELECT * FROM groups WHERE id = ?",
            (decision.group_id,),
        ).fetchone()

        if group is None:
            return {
                "message": "Group does not exist",
                "status": "rejected",
            }

        requester = connection.execute(
            "SELECT * FROM users WHERE id = ?",
            (request["user_id"],),
        ).fetchone()

        if requester is None:
            return {
                "message": "Requesting user does not exist",
                "status": "rejected",
            }

        if action == "reject":
            updated = update_join_request_status(
                decision.request_id,
                "rejected",
            )

            if not updated:
                return {
                    "message": "Request is no longer pending",
                    "status": "rejected",
                }

            return {
                "message": "Join request rejected",
                "status": "success",
                "username": requester["username"],
                "group_id": decision.group_id,
            }

        # Approve: activate an existing inactive membership or add one.
        existing_member = connection.execute(
            """
            SELECT id, active
            FROM group_members
            WHERE group_id = ? AND user_id = ?
            """,
            (decision.group_id, requester["id"]),
        ).fetchone()

        if existing_member and existing_member["active"] == 1:
            update_join_request_status(
                decision.request_id,
                "approved",
            )
            return {
                "message": "User is already an active member",
                "status": "success",
                "username": requester["username"],
            }

        if existing_member:
            connection.execute(
                """
                UPDATE group_members
                SET active = 1, role = 'member'
                WHERE group_id = ? AND user_id = ?
                """,
                (decision.group_id, requester["id"]),
            )
        else:
            connection.execute(
                """
                INSERT INTO group_members
                    (group_id, user_id, active, role)
                VALUES (?, ?, 1, 'member')
                """,
                (decision.group_id, requester["id"]),
            )

        # Mark the request handled in the same database transaction.
        cursor = connection.execute(
            """
            UPDATE join_requests
            SET status = 'approved'
            WHERE id = ? AND status = 'pending'
            """,
            (decision.request_id,),
        )

        if cursor.rowcount != 1:
            connection.rollback()
            return {
                "message": "Request is no longer pending",
                "status": "rejected",
            }

        connection.commit()

    finally:
        connection.close()

    # Generate a new group key and envelopes for active members only.
    try:
        rotation = rotate_group_key(
            decision.group_id,
            decision.admin_username,
        )
    except Exception as exc:
        # Membership has been approved, but key distribution needs attention.
        return {
            "message": (
                "Request approved, but key rotation failed. "
                "Check the server logs before using the group."
            ),
            "status": "key_rotation_failed",
            "detail": str(exc),
            "username": requester["username"],
            "group_id": decision.group_id,
        }

    if rotation is None:
        return {
            "message": "Request approved, but group key rotation failed",
            "status": "key_rotation_failed",
        }

    return {
        "message": "Join request approved and group key rotated",
        "status": "success",
        "username": requester["username"],
        "group_id": decision.group_id,
        "new_key_version": rotation["key_version"],
        "envelopes_created": rotation["envelopes_created"],
        "envelope_errors": rotation["envelope_errors"],
    }


# -------------------------------------------------
# ADD MEMBER (ADMIN ONLY)
# -------------------------------------------------

@app.post("/groups/add-member")
def add_member(member: AddMember):
    if not can_member_add_members(member.group_id, member.admin_username):
        return {
            "message": "Only an admin or a member granted add-member permission can add members",
            "status": "rejected",
        }

    user = get_user(member.username)

    if user is None:
        return {"message": "User does not exist"}

    connection = get_connection()

    try:
        group = connection.execute(
            "SELECT id FROM groups WHERE id = ?",
            (member.group_id,),
        ).fetchone()

        if group is None:
            return {"message": "Group does not exist"}

        existing_member = connection.execute(
            """
            SELECT active
            FROM group_members
            WHERE group_id = ? AND user_id = ?
            """,
            (member.group_id, user["id"]),
        ).fetchone()

        if existing_member and existing_member["active"] == 1:
            return {"message": "User is already a group member"}

        if existing_member:
            connection.execute(
                """
                UPDATE group_members
                SET active = 1, role = 'member'
                WHERE group_id = ? AND user_id = ?
                """,
                (member.group_id, user["id"]),
            )
        else:
            connection.execute(
                """
                INSERT INTO group_members
                    (group_id, user_id, active, role)
                VALUES (?, ?, 1, 'member')
                """,
                (member.group_id, user["id"]),
            )

        connection.commit()
    finally:
        connection.close()

    get_or_create_x25519_key(member.username)

    rotation = rotate_group_key(
        member.group_id,
        member.admin_username,
    )

    if rotation is None:
        return {
            "message": "Member added, but key rotation failed",
            "status": "key_rotation_failed",
        }

    return {
        "message": "Member added successfully",
        "username": member.username,
        "group_id": member.group_id,
        "new_key_version": rotation["key_version"],
        "envelopes_created": rotation["envelopes_created"],
        "envelope_errors": rotation["envelope_errors"],
        "added_by": member.admin_username,
    }


# -------------------------------------------------
# REMOVE MEMBER / ACCESS REVOCATION
# -------------------------------------------------

@app.post("/groups/remove-member")
def remove_member(member: RemoveMember):
    if not is_group_admin(member.group_id, member.admin_username):
        return {
            "message": "Only the group admin can remove members",
            "status": "rejected",
        }

    if member.username == member.admin_username:
        return {
            "message": "Admin cannot remove themselves",
            "status": "rejected",
        }

    user = get_user(member.username)

    if user is None:
        return {"message": "User does not exist"}

    connection = get_connection()

    try:
        group = connection.execute(
            "SELECT id FROM groups WHERE id = ?",
            (member.group_id,),
        ).fetchone()

        if group is None:
            return {"message": "Group does not exist"}

        existing_member = connection.execute(
            """
            SELECT id
            FROM group_members
            WHERE group_id = ?
              AND user_id = ?
              AND active = 1
            """,
            (member.group_id, user["id"]),
        ).fetchone()

        if existing_member is None:
            return {"message": "User is not an active group member"}

        connection.execute(
            """
            UPDATE group_members
            SET active = 0
            WHERE group_id = ? AND user_id = ?
            """,
            (member.group_id, user["id"]),
        )
        connection.commit()
    finally:
        connection.close()

    rotation = rotate_group_key(
        member.group_id,
        member.admin_username,
    )

    if rotation is None:
        return {
            "message": "Member removed, but key rotation failed",
            "status": "key_rotation_failed",
        }

    return {
        "message": "Member removed and group key rotated",
        "username": member.username,
        "group_id": member.group_id,
        "new_key_version": rotation["key_version"],
        "envelopes_created": rotation["envelopes_created"],
        "envelope_errors": rotation["envelope_errors"],
        "removed_by": member.admin_username,
    }


# -------------------------------------------------
# SEND MESSAGE
# -------------------------------------------------

@app.post("/messages/send")
def send_message(message_data: SendMessage):
    user = get_user(message_data.username)

    if user is None:
        return {"message": "User does not exist"}

    connection = get_connection()

    try:
        group = connection.execute(
            "SELECT * FROM groups WHERE id = ?",
            (message_data.group_id,),
        ).fetchone()

        if group is None:
            return {"message": "Group does not exist"}

        member = connection.execute(
            """
            SELECT id
            FROM group_members
            WHERE group_id = ?
              AND user_id = ?
              AND active = 1
            """,
            (message_data.group_id, user["id"]),
        ).fetchone()

        if member is None:
            return {"message": "User is not an active group member"}
    finally:
        connection.close()

    group_key = load_group_key(
        message_data.group_id,
        group["key_version"],
    )

    if group_key is None:
        return {"message": "Current group key is not available"}

    sequence_number = get_next_sequence_number(message_data.group_id)

    encrypted = encrypt_message(group_key, message_data.message)
    ciphertext = encrypted["ciphertext"]
    nonce = encrypted["nonce"]

    signing_private_key = get_or_create_user_signing_key(
        message_data.username
    )
    signing_public_key = signing_private_key.public_key()

    signature = sign_message(
        signing_private_key,
        ciphertext,
        nonce,
        sequence_number,
        group["key_version"],
    )

    signature_encoded = base64.b64encode(signature).decode()
    public_key_encoded = base64.b64encode(
        signing_public_key.public_bytes_raw()
    ).decode()

    message_id = save_message(
        message_data.group_id,
        user["id"],
        ciphertext,
        nonce,
        signature_encoded,
        public_key_encoded,
        sequence_number,
        group["key_version"],
    )

    return {
        "message": "Message encrypted and stored successfully",
        "message_id": message_id,
        "group_id": message_data.group_id,
        "sender": message_data.username,
        "ciphertext": ciphertext,
        "nonce": nonce,
        "signature": signature_encoded,
        "sender_public_key": public_key_encoded,
        "sequence_number": sequence_number,
        "key_version": group["key_version"],
    }


# -------------------------------------------------
# GROUP MEMBER MANAGEMENT
# -------------------------------------------------

@app.get("/groups/{group_id}/members")
def list_group_members(group_id: int, requester_username: str):
    requester = get_user(requester_username)
    if requester is None:
        return {"status": "rejected", "message": "User does not exist"}

    connection = get_connection()
    try:
        active = connection.execute(
            """
            SELECT 1 FROM group_members
            WHERE group_id = ? AND user_id = ? AND active = 1
            """,
            (group_id, requester["id"]),
        ).fetchone()
        if active is None:
            return {"status": "rejected", "message": "You are not an active group member"}

        members = connection.execute(
            """
            SELECT u.username, gm.role, gm.can_add_members
            FROM group_members gm
            JOIN users u ON u.id = gm.user_id
            WHERE gm.group_id = ? AND gm.active = 1
            ORDER BY CASE WHEN gm.role = 'admin' THEN 0 ELSE 1 END, u.username
            """,
            (group_id,),
        ).fetchall()
        return {
            "group_id": group_id,
            "members": [
                {
                    "username": row["username"],
                    "role": row["role"],
                    "can_add_members": bool(row["can_add_members"]),
                }
                for row in members
            ],
        }
    finally:
        connection.close()


@app.post("/groups/member/role")
def change_member_role(change: GroupRoleChange):
    if not is_group_admin(change.group_id, change.admin_username):
        return {"status": "rejected", "message": "Only a group admin can change member roles"}

    role = change.role.strip().lower()
    if role not in ("admin", "member"):
        return {"status": "rejected", "message": "Role must be admin or member"}

    target = get_user(change.username)
    if target is None:
        return {"status": "rejected", "message": "User does not exist"}
    if change.username == change.admin_username and role == "member":
        return {"status": "rejected", "message": "You cannot demote yourself"}

    connection = get_connection()
    try:
        cursor = connection.execute(
            """
            UPDATE group_members
            SET role = ?, can_add_members = CASE WHEN ? = 'admin' THEN 1 ELSE 0 END
            WHERE group_id = ? AND user_id = ? AND active = 1
            """,
            (role, role, change.group_id, target["id"]),
        )
        if cursor.rowcount != 1:
            return {"status": "rejected", "message": "Target is not an active group member"}
        connection.commit()
    finally:
        connection.close()

    return {
        "status": "success",
        "message": f"{change.username} is now {role}",
        "username": change.username,
        "role": role,
    }


@app.post("/groups/member/permissions")
def change_member_permissions(change: MemberPermissionChange):
    if not is_group_admin(change.group_id, change.admin_username):
        return {"status": "rejected", "message": "Only a group admin can change permissions"}

    target = get_user(change.username)
    if target is None:
        return {"status": "rejected", "message": "User does not exist"}

    connection = get_connection()
    try:
        cursor = connection.execute(
            """
            UPDATE group_members
            SET can_add_members = ?
            WHERE group_id = ? AND user_id = ? AND active = 1 AND role != 'admin'
            """,
            (1 if change.can_add_members else 0, change.group_id, target["id"]),
        )
        if cursor.rowcount != 1:
            return {"status": "rejected", "message": "Target must be an active non-admin member"}
        connection.commit()
    finally:
        connection.close()

    return {
        "status": "success",
        "message": "Add-member permission updated",
        "username": change.username,
        "can_add_members": change.can_add_members,
    }


@app.post("/messages/{message_id}/delete")
def delete_group_message(message_id: int, deletion: MessageDelete):
    if not is_group_admin(deletion.group_id, deletion.admin_username):
        return {"status": "rejected", "message": "Only a group admin can delete messages"}

    connection = get_connection()
    try:
        cursor = connection.execute(
            """
            UPDATE messages
            SET deleted = 1, deleted_by = ?
            WHERE id = ? AND group_id = ? AND deleted = 0
            """,
            (deletion.admin_username, message_id, deletion.group_id),
        )
        if cursor.rowcount != 1:
            return {"status": "rejected", "message": "Message not found or already deleted"}
        connection.commit()
    finally:
        connection.close()

    return {"status": "success", "message": "Message deleted for everyone"}


# -------------------------------------------------
# RECEIVE / DECRYPT MESSAGES
# -------------------------------------------------

@app.get("/messages/{group_id}")
def receive_messages(group_id: int):
    messages = get_group_messages(group_id)
    results = []

    # Reading stored history is not a new message submission. Do not apply
    # the inbound replay high-water mark while rendering existing messages.
    for message in messages:
        sequence_number = message["sequence_number"]

        try:
            group_key = load_group_key(group_id, message["key_version"])

            if group_key is None:
                sender = get_user_by_id(message["sender_id"])
                results.append({
                    "message_id": message["id"],
                    "sender_username": sender["username"] if sender else "Unknown",
                    "sequence_number": sequence_number,
                    "status": "rejected",
                    "reason": "Group key not available",
                })
                continue

            public_key_bytes = base64.b64decode(
                message["sender_public_key"]
            )
            public_key = Ed25519PublicKey.from_public_bytes(
                public_key_bytes
            )
            signature = base64.b64decode(message["signature"])

            valid_signature = verify_message_signature(
                public_key,
                signature,
                message["ciphertext"],
                message["nonce"],
                sequence_number,
                message["key_version"],
            )

            if not valid_signature:
                sender = get_user_by_id(message["sender_id"])
                results.append({
                    "message_id": message["id"],
                    "sender_username": sender["username"] if sender else "Unknown",
                    "sequence_number": sequence_number,
                    "status": "rejected",
                    "reason": "Invalid signature",
                })
                continue

            sender = get_user_by_id(message["sender_id"])
            if message["deleted"]:
                results.append({
                    "message_id": message["id"],
                    "sender_username": sender["username"] if sender else "Unknown",
                    "sequence_number": sequence_number,
                    "key_version": message["key_version"],
                    "status": "deleted",
                    "message": "This message was deleted by an admin.",
                })
                continue

            plaintext = decrypt_message(
                group_key,
                message["ciphertext"],
                message["nonce"],
            )

            results.append({
                "message_id": message["id"],
                "sender_username": sender["username"] if sender else "Unknown",
                "sequence_number": sequence_number,
                "key_version": message["key_version"],
                "status": "verified",
                "message": plaintext,
            })

        except Exception:
            sender = get_user_by_id(message["sender_id"])
            results.append({
                "message_id": message["id"],
                "sender_username": sender["username"] if sender else "Unknown",
                "sequence_number": sequence_number,
                "status": "rejected",
                "reason": "Message verification or decryption failed",
            })

    return {
        "group_id": group_id,
        "messages": results,
    }


# -------------------------------------------------
# KEY ENVELOPE STATUS
# -------------------------------------------------

@app.get("/groups/key-status/{group_id}/{username}")
def key_status(group_id: int, username: str):
    user = get_user(username)

    if user is None:
        return {
            "status": "rejected",
            "reason": "User does not exist",
        }

    connection = get_connection()

    try:
        group = connection.execute(
            "SELECT * FROM groups WHERE id = ?",
            (group_id,),
        ).fetchone()

        if group is None:
            return {
                "status": "rejected",
                "reason": "Group does not exist",
            }

        member = connection.execute(
            """
            SELECT id
            FROM group_members
            WHERE group_id = ?
              AND user_id = ?
              AND active = 1
            """,
            (group_id, user["id"]),
        ).fetchone()

        if member is None:
            return {
                "group_id": group_id,
                "username": username,
                "key_version": group["key_version"],
                "status": "rejected",
                "reason": "User is not an active group member",
            }

        key_version = group["key_version"]
    finally:
        connection.close()

    envelope = get_group_key_envelope(
        group_id,
        key_version,
        user["id"],
    )

    if envelope is None:
        return {
            "group_id": group_id,
            "username": username,
            "key_version": key_version,
            "status": "rejected",
            "reason": "No encrypted group-key envelope found",
        }

    return {
        "group_id": group_id,
        "username": username,
        "key_version": key_version,
        "status": "available",
        "message": "Encrypted group-key envelope is available",
    }


# -------------------------------------------------
# TAMPERING TEST
# -------------------------------------------------

@app.post("/messages/tamper-test/{message_id}")
def tamper_test(message_id: int):
    connection = get_connection()

    try:
        message = connection.execute(
            "SELECT * FROM messages WHERE id = ?",
            (message_id,),
        ).fetchone()
    finally:
        connection.close()

    if message is None:
        return {"message": "Message not found"}

    original_ciphertext = message["ciphertext"]

    if not original_ciphertext:
        return {"message": "Message ciphertext is empty"}

    tampered_first_character = (
        "B" if original_ciphertext[0] == "A" else "A"
    )
    tampered_ciphertext = (
        tampered_first_character + original_ciphertext[1:]
    )

    try:
        public_key_bytes = base64.b64decode(
            message["sender_public_key"]
        )
        public_key = Ed25519PublicKey.from_public_bytes(
            public_key_bytes
        )
        signature = base64.b64decode(message["signature"])

        valid_signature = verify_message_signature(
            public_key,
            signature,
            tampered_ciphertext,
            message["nonce"],
            message["sequence_number"],
            message["key_version"],
        )

        if valid_signature:
            return {"message": "Tampering was NOT detected"}

        return {
            "message": "Tampering detected successfully!",
            "original_ciphertext": original_ciphertext,
            "tampered_ciphertext": tampered_ciphertext,
            "signature_valid": False,
        }

    except Exception:
        return {
            "message": "Tampering detected successfully!",
            "signature_valid": False,
        }