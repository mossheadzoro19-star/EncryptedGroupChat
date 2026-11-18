# End-to-End Encrypted Group Communication
## Secure Key Rotation & Access Revocation

### Cryptography and Network Security (CNS) Course Mini-Project

---

## 1. Project Overview

This project implements a secure group communication system that provides encrypted messaging, authenticated users, secure group-key management, key rotation, access revocation, replay protection, and tampering detection.

The system is designed as a course-level prototype demonstrating how cryptographic techniques can be combined to protect group communication.

The main cryptographic techniques used are:

- AES-256-GCM for message encryption
- X25519 for key agreement
- HKDF-SHA-256 for key derivation
- Ed25519 for digital signatures
- Sequence numbers for replay protection
- Group-key rotation for membership changes

---

## 2. Problem Statement

In a group communication system, simply encrypting messages is not sufficient.

The system must also ensure:

- Only authorized group members can communicate.
- Messages cannot be read or modified by unauthorized parties.
- The sender of a message can be authenticated.
- Replayed or duplicate messages are rejected.
- When a member joins or leaves, the group key is updated.
- A removed member cannot access future group communication.

This project addresses these requirements through encrypted messaging and secure group-key management.

---

## 3. Objectives

The main objectives of the project are:

1. Implement a secure client-server group communication system.
2. Provide user registration and authentication.
3. Implement group creation and membership management.
4. Encrypt messages using AES-256-GCM.
5. Use X25519 for secure key agreement.
6. Use HKDF-SHA-256 for deriving cryptographic keys.
7. Use Ed25519 signatures for sender authentication and message integrity.
8. Rotate the group key whenever group membership changes.
9. Prevent revoked users from sending messages to the group.
10. Detect tampered messages.
11. Detect replayed and duplicate messages.
12. Evaluate the system using controlled security and performance tests.

---

## 4. Technologies Used

### Programming Language

- Python

### Backend

- FastAPI
- Uvicorn

### Database

- SQLite

### Frontend

- HTML
- CSS
- JavaScript

### Cryptography

- Python `cryptography` library
- AES-256-GCM
- X25519
- HKDF-SHA-256
- Ed25519

### Development Tools

- Visual Studio Code
- Git / GitHub

---

## Where application data is stored

This prototype uses local files in the directory from which the FastAPI application is started:

| Data | Storage location |
|---|---|
| Usernames and password hashes | `chat.db` → SQLite `users` table |
| Group names and key versions | `chat.db` → `groups` table |
| Membership, roles and add-member permissions | `chat.db` → `group_members` table |
| Join requests | `chat.db` → `join_requests` table |
| Encrypted message records, signatures and nonces | `chat.db` → `messages` table |
| Encrypted group-key envelopes | `chat.db` → `group_key_envelopes` table |
| Group encryption keys | `client_keys/` |
| User Ed25519 private signing keys | `user_keys/` |
| User X25519 private keys | `member_keys/` |

These files are local to the running Codespace or server filesystem. They are not automatically stored in GitHub, Supabase, or a cloud database. The repository's `.gitignore` excludes the database, key files, and key directories from normal Git commits.

**Important security limitation:** this prototype currently stores group keys and users' private keys on the server filesystem. Therefore, despite encrypting messages, it is not a true server-blind end-to-end encrypted system. Do not deploy it with real private conversations or sensitive data.

For a Codespaces demo, stopping and recreating a Codespace can risk losing local data depending on the Codespace lifecycle. Back up `chat.db` and the key directories together if you need to preserve the demo state. Do not commit private keys or the database to a public repository.

## 5. System Architecture

The system contains a control plane and a data plane.

### Control Plane

The control plane manages:

- User authentication
- Group creation
- Group membership
- X25519 key establishment
- Group-key distribution
- Group-key rotation

### Data Plane

The data plane handles:

- Message encryption
- Message signing
- Message transmission
- Signature verification
- Replay detection
- Message decryption

### Basic Message Flow

```text
Sender
   |
   | Encrypt message using Group Key
   v
AES-256-GCM
   |
   | Sign ciphertext + metadata
   v
Ed25519 Signature
   |
   v
FastAPI Server
   |
   | Store / Relay protected message
   v
Recipient
   |
   | Verify signature
   v
Replay Check
   |
   | Decrypt using Group Key
   v
Plaintext Message

## Implementation status and security boundaries

The repository is an evolving academic prototype. The title describes the intended design, not a claim that every end-to-end security property is already achieved.

### Implemented in the current branch
- SQLite persistence for users, groups, memberships, join requests and message records.
- Password verification with scrypt for new/updated credentials; legacy PBKDF2 hashes are verified and upgraded after successful login.
- Server-issued, opaque, HttpOnly, SameSite=Strict session cookies with a 12-hour expiry and server-side revocation.
- Protected API boundary that binds actor usernames in requests to the authenticated session and checks active membership for group-scoped reads.
- Admin/member role controls and delegated add-member permission.
- Automatic chat refresh and sender-labelled messages.
- Initial cryptographic primitive tests, session-storage tests and GitHub Actions CI.

### Not yet implemented / not safe to claim
- True server-blind end-to-end encryption: the current message receive path decrypts messages on the server, and group/private keys are stored on the server filesystem.
- Client-generated and client-held X25519/Ed25519 private keys with verified identity-key binding.
- Browser-side AES-GCM encryption with AAD binding for message/group/sender/sequence/key epoch.
- WebSocket delivery, authenticated socket subscriptions and revocation of socket channels.
- Atomic key rotation with recipient-only envelopes and a pending-rotation state.
- Persistent per-sender replay detection with concurrency-safe sequence allocation.
- Full security attack lab and real concurrent-user/performance benchmarks.
- Production deployment controls such as HTTPS termination, rate limiting, monitoring and backup/restore.

**Do not use this prototype for real confidential conversations or claim production-grade E2EE.** The server currently has access to plaintext during message retrieval. The next architectural milestone is moving encryption, decryption and private-key custody to clients before adding WebSockets and attack/performance dashboards.
