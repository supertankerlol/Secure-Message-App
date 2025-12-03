import os
import json
import base64
import bcrypt
import hashlib
import hmac
import uuid
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


USERS_FILE = "users.json"
MESSAGES_FILE = "messages.json"


def b64e(b: bytes) -> str:
    """Bytes -> base64 string."""
    return base64.b64encode(b).decode("utf-8")


def b64d(s: str) -> bytes:
    """Base64 string -> bytes."""
    return base64.b64decode(s.encode("utf-8"))


class SimpleHMAC:
    """
    Custom HMAC-SHA256 implementation:
    H(K, m) = SHA256((K xor opad) || SHA256((K xor ipad) || m))
    """

    BLOCK_SIZE = 64  # SHA-256 block size

    @staticmethod
    def hmac_sha256(key: bytes, data: bytes) -> bytes:
        # If key is longer than block size, hash it
        if len(key) > SimpleHMAC.BLOCK_SIZE:
            key = hashlib.sha256(key).digest()

        # Pad key with zeros to block size
        if len(key) < SimpleHMAC.BLOCK_SIZE:
            key = key + b"\x00" * (SimpleHMAC.BLOCK_SIZE - len(key))

        o_key_pad = bytes((b ^ 0x5C) for b in key)
        i_key_pad = bytes((b ^ 0x36) for b in key)

        inner = hashlib.sha256(i_key_pad + data).digest()
        return hashlib.sha256(o_key_pad + inner).digest()


class UserStore:
    """Simple JSON-based user storage."""

    def __init__(self, path: str = USERS_FILE):
        self.path = path
        if not os.path.exists(self.path):
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump([], f)

    def _load(self):
        with open(self.path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save(self, data):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def get_user(self, username: str):
        users = self._load()
        for u in users:
            if u["username"] == username:
                return u
        return None

    def add_user(self, user_dict: dict):
        users = self._load()
        if any(u["username"] == user_dict["username"] for u in users):
            raise ValueError("User already exists")
        users.append(user_dict)
        self._save(users)


class MessageStore:
    """Simple JSON-based message storage."""

    def __init__(self, path: str = MESSAGES_FILE):
        self.path = path
        if not os.path.exists(self.path):
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump([], f)

    def _load(self):
        with open(self.path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save(self, data):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def add_message(self, msg_dict: dict):
        messages = self._load()
        messages.append(msg_dict)
        self._save(messages)

    def get_messages_for(self, username: str):
        messages = self._load()
        return [m for m in messages if m["recipient"] == username]


class CryptoUtils:
    """Wrapper for all cryptographic operations."""

    @staticmethod
    def generate_rsa_keypair():
        """Generate RSA-2048 key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def serialize_public_key(public_key) -> str:
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode("utf-8")

    @staticmethod
    def serialize_private_key(private_key) -> str:
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return pem.decode("utf-8")

    @staticmethod
    def load_public_key(pem_str: str):
        return serialization.load_pem_public_key(pem_str.encode("utf-8"))

    @staticmethod
    def load_private_key(pem_str: str):
        return serialization.load_pem_private_key(
            pem_str.encode("utf-8"), password=None
        )

    @staticmethod
    def derive_key_from_password(password: str, salt: bytes) -> bytes:
        """PBKDF2-HMAC-SHA256 to derive 32-byte key from password."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200_000,
        )
        return kdf.derive(password.encode("utf-8"))

    @staticmethod
    def encrypt_private_key(pem_priv: str, password: str) -> dict:
        """
        Encrypt private key with AES-256-GCM.
        AES key derived from password using PBKDF2.
        """
        salt = os.urandom(16)
        key = CryptoUtils.derive_key_from_password(password, salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, pem_priv.encode("utf-8"), None)
        return {
            "salt": b64e(salt),
            "nonce": b64e(nonce),
            "ciphertext": b64e(ct),
        }

    @staticmethod
    def decrypt_private_key(enc_dict: dict, password: str) -> str:
        salt = b64d(enc_dict["salt"])
        nonce = b64d(enc_dict["nonce"])
        ct = b64d(enc_dict["ciphertext"])
        key = CryptoUtils.derive_key_from_password(password, salt)
        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ct, None)
        except Exception as e:
            raise ValueError("Failed to decrypt private key (wrong password?)") from e
        return plaintext.decode("utf-8")

    @staticmethod
    def encrypt_message_aes(plaintext: str, aes_key: bytes):
        """Encrypt message with AES-256-GCM."""
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return nonce, ciphertext

    @staticmethod
    def decrypt_message_aes(nonce: bytes, ciphertext: bytes, aes_key: bytes) -> str:
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")

    @staticmethod
    def rsa_encrypt(data: bytes, public_key):
        """RSA-OAEP encryption (key exchange)."""
        return public_key.encrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    @staticmethod
    def rsa_decrypt(ciphertext: bytes, private_key):
        """RSA-OAEP decryption."""
        return private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    @staticmethod
    def sign(data: bytes, private_key):
        """RSA-PSS signature with SHA-256."""
        return private_key.sign(
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    @staticmethod
    def verify_signature(data: bytes, signature: bytes, public_key):
        """Verify RSA-PSS signature."""
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )


class SecureMessagingApp:
    """CLI secure messaging application."""

    def __init__(self):
        self.user_store = UserStore()
        self.msg_store = MessageStore()
        self.current_user = None
        self.current_private_key = None
        self.current_public_key = None

    # ---------- Authentication & user management ----------

    def register(self):
        print("=== Register new user ===")
        username = input("Username: ").strip()
        password = input("Password: ").strip()

        if self.user_store.get_user(username):
            print("User already exists.")
            return

        # Hash password with bcrypt
        password_bytes = password.encode("utf-8")
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password_bytes, salt)

        # Generate RSA keypair
        priv, pub = CryptoUtils.generate_rsa_keypair()
        priv_pem = CryptoUtils.serialize_private_key(priv)
        pub_pem = CryptoUtils.serialize_public_key(pub)

        # Encrypt private key with key derived from password
        enc_priv = CryptoUtils.encrypt_private_key(priv_pem, password)

        user_record = {
            "username": username,
            "password_hash": password_hash.decode("utf-8"),
            "public_key_pem": pub_pem,
            "encrypted_private_key": enc_priv,
        }

        self.user_store.add_user(user_record)
        print(f"User '{username}' registered successfully.")

    def login(self):
        print("=== Login ===")
        username = input("Username: ").strip()
        password = input("Password: ").strip()

        user = self.user_store.get_user(username)
        if not user:
            print("User not found.")
            return

        if not bcrypt.checkpw(
                password.encode("utf-8"),
                user["password_hash"].encode("utf-8"),
        ):
            print("Invalid password.")
            return

        # Decrypt private key using password-derived key
        try:
            priv_pem = CryptoUtils.decrypt_private_key(
                user["encrypted_private_key"],
                password,
            )
        except ValueError as e:
            print(str(e))
            return

        priv_key = CryptoUtils.load_private_key(priv_pem)
        pub_key = CryptoUtils.load_public_key(user["public_key_pem"])

        self.current_user = username
        self.current_private_key = priv_key
        self.current_public_key = pub_key

        print(f"Logged in as '{username}'.")

    def logout(self):
        self.current_user = None
        self.current_private_key = None
        self.current_public_key = None
        print("Logged out.")

    # ---------- Messaging ----------

    def send_message(self):
        if not self.current_user:
            print("You must log in first.")
            return

        recipient = input("Recipient username: ").strip()
        recipient_user = self.user_store.get_user(recipient)
        if not recipient_user:
            print("Recipient not found.")
            return

        message_text = input("Message: ")

        recipient_pub = CryptoUtils.load_public_key(
            recipient_user["public_key_pem"]
        )

        # Generate ephemeral AES-256 key
        aes_key = os.urandom(32)

        # Encrypt message with AES-GCM
        nonce, ciphertext = CryptoUtils.encrypt_message_aes(
            message_text, aes_key
        )

        # Encrypt AES key with recipient's RSA public key
        enc_aes_key = CryptoUtils.rsa_encrypt(aes_key, recipient_pub)

        # Compute SHA-256 hash of ciphertext
        msg_hash = hashlib.sha256(ciphertext).digest()

        # Sign hash with sender's private key
        signature = CryptoUtils.sign(msg_hash, self.current_private_key)

        # Compute HMAC-SHA256 over (nonce || ciphertext)
        hmac_tag = SimpleHMAC.hmac_sha256(aes_key, nonce + ciphertext)

        msg_record = {
            "id": str(uuid.uuid4()),
            "sender": self.current_user,
            "recipient": recipient,
            "timestamp": datetime.utcnow().isoformat(),
            "aes_nonce": b64e(nonce),
            "ciphertext": b64e(ciphertext),
            "enc_aes_key": b64e(enc_aes_key),
            "signature": b64e(signature),
            "hmac": b64e(hmac_tag),
        }

        self.msg_store.add_message(msg_record)
        print("Message sent securely.")

    def read_messages(self):
        if not self.current_user:
            print("You must log in first.")
            return

        messages = self.msg_store.get_messages_for(self.current_user)
        if not messages:
            print("No messages.")
            return

        print(f"=== Inbox for {self.current_user} ===")
        for m in messages:
            try:
                # Decrypt AES key
                aes_key = CryptoUtils.rsa_decrypt(
                    b64d(m["enc_aes_key"]),
                    self.current_private_key,
                )

                nonce = b64d(m["aes_nonce"])
                ciphertext = b64d(m["ciphertext"])
                signature = b64d(m["signature"])
                hmac_tag = b64d(m["hmac"])

                # Verify HMAC
                expected_hmac = SimpleHMAC.hmac_sha256(aes_key, nonce + ciphertext)
                if not hmac.compare_digest(expected_hmac, hmac_tag):
                    print(f"[{m['id']}] HMAC verification failed. Skipping.")
                    continue

                # Verify signature
                sender_user = self.user_store.get_user(m["sender"])
                if not sender_user:
                    print(f"[{m['id']}] Unknown sender.")
                    continue

                sender_pub = CryptoUtils.load_public_key(
                    sender_user["public_key_pem"]
                )

                msg_hash = hashlib.sha256(ciphertext).digest()
                CryptoUtils.verify_signature(msg_hash, signature, sender_pub)

                # Decrypt message
                plaintext = CryptoUtils.decrypt_message_aes(
                    nonce, ciphertext, aes_key
                )

                print(
                    f"- From: {m['sender']} at {m['timestamp']} (id: {m['id']})\n"
                    f"  Message: {plaintext}\n"
                )

            except Exception as e:
                print(f"[{m['id']}] Failed to decrypt/verify message: {e}")

    # ---------- CLI loop ----------

    def run(self):
        while True:
            print("\n=== Secure Messaging App ===")
            print("1) Register")
            print("2) Login")
            print("3) Send message")
            print("4) Read my messages")
            print("5) Logout")
            print("0) Exit")

            choice = input("Choose: ").strip()

            if choice == "1":
                self.register()
            elif choice == "2":
                self.login()
            elif choice == "3":
                self.send_message()
            elif choice == "4":
                self.read_messages()
            elif choice == "5":
                self.logout()
            elif choice == "0":
                print("Goodbye.")
                break
            else:
                print("Invalid choice.")


if __name__ == "__main__":
    app = SecureMessagingApp()
    app.run()
