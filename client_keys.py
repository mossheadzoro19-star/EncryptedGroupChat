import os
import base64


KEY_FOLDER = "client_keys"


def create_key_folder():
    os.makedirs(KEY_FOLDER, exist_ok=True)


def save_group_key(group_id, key_version, group_key):
    create_key_folder()

    filename = os.path.join(
        KEY_FOLDER,
        f"group_{group_id}_v{key_version}.key"
    )

    with open(filename, "wb") as file:
        file.write(group_key)

    return filename


def load_group_key(group_id, key_version):
    filename = os.path.join(
        KEY_FOLDER,
        f"group_{group_id}_v{key_version}.key"
    )

    if not os.path.exists(filename):
        return None

    with open(filename, "rb") as file:
        return file.read()


def key_exists(group_id, key_version):
    filename = os.path.join(
        KEY_FOLDER,
        f"group_{group_id}_v{key_version}.key"
    )

    return os.path.exists(filename)