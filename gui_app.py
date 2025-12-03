import tkinter as tk
from tkinter import messagebox, scrolledtext

import os
import uuid
import hashlib
import hmac
import bcrypt
from datetime import datetime

from main import UserStore, MessageStore, CryptoUtils, SimpleHMAC, b64e, b64d


class SecureMessagingCore:

    def __init__(self):
        self.user_store = UserStore()
        self.msg_store = MessageStore()
        self.current_user = None
        self.current_private_key = None
        self.current_public_key = None

    def register(self, username: str, password: str):
        if not username or not password:
            raise ValueError("Username and password cannot be empty")

        if self.user_store.get_user(username):
            raise ValueError("User already exists")

        pw_bytes = password.encode("utf-8")
        pw_hash = bcrypt.hashpw(pw_bytes, bcrypt.gensalt())

        priv, pub = CryptoUtils.generate_rsa_keypair()
        priv_pem = CryptoUtils.serialize_private_key(priv)
        pub_pem = CryptoUtils.serialize_public_key(pub)

        enc_priv = CryptoUtils.encrypt_private_key(priv_pem, password)

        user_record = {
            "username": username,
            "password_hash": pw_hash.decode("utf-8"),
            "public_key_pem": pub_pem,
            "encrypted_private_key": enc_priv,
        }

        self.user_store.add_user(user_record)

    def login(self, username: str, password: str):
        user = self.user_store.get_user(username)
        if not user:
            raise ValueError("User not found")

        if not bcrypt.checkpw(
                password.encode("utf-8"),
                user["password_hash"].encode("utf-8")
        ):
            raise ValueError("Invalid password")

        try:
            priv_pem = CryptoUtils.decrypt_private_key(
                user["encrypted_private_key"],
                password,
            )
        except Exception:
            raise ValueError("Failed to decrypt private key (wrong password?)")

        priv_key = CryptoUtils.load_private_key(priv_pem)
        pub_key = CryptoUtils.load_public_key(user["public_key_pem"])

        self.current_user = username
        self.current_private_key = priv_key
        self.current_public_key = pub_key

    def logout(self):
        self.current_user = None
        self.current_private_key = None
        self.current_public_key = None

    def send_message(self, recipient: str, message_text: str):
        if not self.current_user:
            raise ValueError("Not logged in")

        if not recipient:
            raise ValueError("Recipient is empty")

        recipient_user = self.user_store.get_user(recipient)
        if not recipient_user:
            raise ValueError("Recipient not found")

        recipient_pub = CryptoUtils.load_public_key(
            recipient_user["public_key_pem"]
        )

        aes_key = os.urandom(32)
        nonce, ciphertext = CryptoUtils.encrypt_message_aes(
            message_text, aes_key
        )

        enc_aes_key = CryptoUtils.rsa_encrypt(aes_key, recipient_pub)

        msg_hash = hashlib.sha256(ciphertext).digest()
        signature = CryptoUtils.sign(msg_hash, self.current_private_key)

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

    def get_inbox(self):
        """Вернуть список расшифрованных сообщений для текущего пользователя."""
        if not self.current_user:
            raise ValueError("Not logged in")

        messages = self.msg_store.get_messages_for(self.current_user)
        result = []

        for m in messages:
            try:
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
                    result.append({
                        "id": m["id"],
                        "sender": m["sender"],
                        "timestamp": m["timestamp"],
                        "error": "HMAC verification failed",
                    })
                    continue

                sender_user = self.user_store.get_user(m["sender"])
                if not sender_user:
                    result.append({
                        "id": m["id"],
                        "sender": m["sender"],
                        "timestamp": m["timestamp"],
                        "error": "Unknown sender",
                    })
                    continue

                sender_pub = CryptoUtils.load_public_key(
                    sender_user["public_key_pem"]
                )

                msg_hash = hashlib.sha256(ciphertext).digest()
                CryptoUtils.verify_signature(msg_hash, signature, sender_pub)

                plaintext = CryptoUtils.decrypt_message_aes(
                    nonce, ciphertext, aes_key
                )

                result.append({
                    "id": m["id"],
                    "sender": m["sender"],
                    "timestamp": m["timestamp"],
                    "text": plaintext,
                    "error": None,
                })

            except Exception as e:
                result.append({
                    "id": m["id"],
                    "sender": m["sender"],
                    "timestamp": m["timestamp"],
                    "error": f"Failed to decrypt/verify: {e}",
                })

        return result


class SecureMessagingGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure Messaging App (GUI)")
        self.core = SecureMessagingCore()

        self.colors = {
            "bg": "#0F1115",
            "bg_alt": "#131720",
            "card": "#181B22",
            "card_soft": "#1F2430",
            "text": "#F5F6F7",
            "muted": "#8C92A4",
            "accent": "#2F80ED",
            "accent_soft": "#1F3A68",
            "warning": "#F2994A",
        }

        self.root.configure(bg=self.colors["bg"])
        self.root.geometry("980x620")
        self.root.minsize(880, 560)

        self.auth_frame = tk.Frame(self.root, bg=self.colors["bg"])
        self.main_frame = tk.Frame(self.root, bg=self.colors["bg"])

        self.stat_labels = {}
        self.auth_mode = "login"

        self._build_auth_frame()
        self._build_main_frame()

        self.auth_frame.pack(fill="both", expand=True)
        self._update_dashboard_stats()

    # ---------- UI building ----------

    def _build_auth_frame(self):
        frame = self.auth_frame
        frame.configure(bg=self.colors["bg"])

        tk.Label(
            frame,
            text="Secure Messaging Portal",
            font=("Segoe UI", 20, "bold"),
            fg=self.colors["text"],
            bg=self.colors["bg"],
        ).pack(pady=(30, 10))

        tk.Label(
            frame,
            text="Register a new account or log into your workspace to access encrypted mailboxes.",
            font=("Segoe UI", 11),
            fg=self.colors["muted"],
            bg=self.colors["bg"],
            wraplength=640,
            justify="center",
        ).pack(pady=(0, 20))

        toggle = tk.Frame(frame, bg=self.colors["bg"])
        toggle.pack(pady=(0, 10))
        self.btn_auth_login = tk.Button(
            toggle,
            text="Login",
            command=lambda: self._switch_auth_mode("login"),
            font=("Segoe UI", 11, "bold"),
            bd=0,
            relief="flat",
            padx=24,
            pady=8,
            cursor="hand2",
            highlightthickness=0,
        )
        self.btn_auth_login.pack(side="left", padx=6)

        self.btn_auth_register = tk.Button(
            toggle,
            text="Registration",
            command=lambda: self._switch_auth_mode("register"),
            font=("Segoe UI", 11, "bold"),
            bd=0,
            relief="flat",
            padx=24,
            pady=8,
            cursor="hand2",
            highlightthickness=0,
        )
        self.btn_auth_register.pack(side="left", padx=6)

        self.auth_card_container = tk.Frame(
            frame,
            bg=self.colors["bg"],
        )
        self.auth_card_container.pack(fill="both", expand=True, padx=30, pady=20)

        self.login_card = self._build_login_card(self.auth_card_container)
        self.register_card = self._build_register_card(self.auth_card_container)
        self._switch_auth_mode(self.auth_mode)

    def _build_main_frame(self):
        frame = self.main_frame
        frame.configure(bg=self.colors["bg"])

        layout = tk.Frame(frame, bg=self.colors["bg"])
        layout.pack(fill="both", expand=True)

        sidebar = tk.Frame(layout, bg="#0B0D13", width=90)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        tk.Label(
            sidebar,
            text="GEA",
            font=("Segoe UI", 16, "bold"),
            fg=self.colors["text"],
            bg="#0B0D13",
        ).pack(pady=(30, 20))

        # keep sidebar minimal per mockup
        for _ in range(4):
            spacer = tk.Frame(sidebar, bg="#0B0D13", height=48)
            spacer.pack(fill="x", pady=18)

        main_content = tk.Frame(layout, bg=self.colors["bg"])
        main_content.pack(side="left", fill="both", expand=True, padx=25, pady=25)

        header = tk.Frame(main_content, bg=self.colors["bg"])
        header.pack(fill="x")

        self.lbl_current_user = tk.Label(
            header,
            text="Not logged in",
            font=("Segoe UI", 14, "bold"),
            fg=self.colors["text"],
            bg=self.colors["bg"],
        )
        self.lbl_current_user.pack(side="left")

        header_actions = tk.Frame(header, bg=self.colors["bg"])
        header_actions.pack(side="right")

        view_users_btn = self._create_button(
            header_actions,
            text="View users.json",
            command=self.on_view_users,
            accent=False,
        )
        view_users_btn.pack(side="left", padx=6)

        logout_btn = self._create_button(
            header_actions,
            text="Logout",
            command=self.on_logout,
            accent=False,
        )
        logout_btn.pack(side="left")

        summary_frame = tk.Frame(main_content, bg=self.colors["bg"])
        summary_frame.pack(fill="x", pady=(20, 10))
        for i in range(3):
            summary_frame.columnconfigure(i, weight=1, uniform="stats")

        stats = [
            ("Clients", "stat_users"),
            ("Messages", "stat_messages"),
            ("Inbox items", "stat_inbox"),
        ]
        for idx, (title, key) in enumerate(stats):
            card = tk.Frame(
                summary_frame,
                bg=self.colors["card"],
                padx=20,
                pady=18,
            )
            card.grid(row=0, column=idx, sticky="nsew", padx=(0 if idx == 0 else 12, 0))
            tk.Label(
                card,
                text=title,
                fg=self.colors["muted"],
                bg=self.colors["card"],
                font=("Segoe UI", 10),
            ).pack(anchor="w")
            value_lbl = tk.Label(
                card,
                text="0",
                fg=self.colors["text"],
                bg=self.colors["card"],
                font=("Segoe UI", 22, "bold"),
            )
            value_lbl.pack(anchor="w", pady=(6, 0))
            self.stat_labels[key] = value_lbl

        cards_container = tk.Frame(main_content, bg=self.colors["bg"])
        cards_container.pack(fill="both", expand=True, pady=(10, 0))
        cards_container.columnconfigure(0, weight=1)
        cards_container.columnconfigure(1, weight=1)

        send_card = tk.Frame(cards_container, bg=self.colors["card"], padx=20, pady=20)
        send_card.grid(row=0, column=0, sticky="nsew", padx=(0, 12), pady=(0, 20))

        tk.Label(
            send_card,
            text="Secure dispatch",
            font=("Segoe UI", 13, "bold"),
            fg=self.colors["text"],
            bg=self.colors["card"],
        ).pack(anchor="w")

        tk.Label(
            send_card,
            text="Recipient username",
            fg=self.colors["muted"],
            bg=self.colors["card"],
        ).pack(anchor="w", pady=(15, 4))
        self.entry_recipient = self._create_entry(send_card)

        tk.Label(
            send_card,
            text="Message",
            fg=self.colors["muted"],
            bg=self.colors["card"],
        ).pack(anchor="w", pady=(15, 4))
        self.text_message = scrolledtext.ScrolledText(
            send_card,
            height=6,
            bg=self.colors["bg_alt"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground="#232838",
        )
        self.text_message.pack(fill="both", expand=True)

        send_btn = self._create_button(
            send_card,
            text="Send now",
            command=self.on_send,
            accent=True,
        )
        send_btn.pack(fill="x", pady=(20, 0))

        inbox_card = tk.Frame(cards_container, bg=self.colors["card"], padx=20, pady=20)
        inbox_card.grid(row=0, column=1, sticky="nsew", pady=(0, 20))

        inbox_header = tk.Frame(inbox_card, bg=self.colors["card"])
        inbox_header.pack(fill="x")

        tk.Label(
            inbox_header,
            text="Inbox",
            font=("Segoe UI", 13, "bold"),
            fg=self.colors["text"],
            bg=self.colors["card"],
        ).pack(side="left")

        refresh_btn = self._create_button(
            inbox_header,
            text="Refresh",
            command=self.on_refresh_inbox,
            accent=False,
        )
        refresh_btn.pack(side="right")

        self.inbox_text = scrolledtext.ScrolledText(
            inbox_card,
            state="disabled",
            bg=self.colors["bg_alt"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground="#232838",
        )
        self.inbox_text.pack(fill="both", expand=True, pady=(15, 0))

    def _build_login_card(self, parent):
        card = tk.Frame(parent, bg=self.colors["card"], padx=40, pady=40)

        tk.Label(
            card,
            text="Welcome back",
            font=("Segoe UI", 16, "bold"),
            fg=self.colors["text"],
            bg=self.colors["card"],
        ).pack(anchor="w")

        tk.Label(
            card,
            text="Sign in to review secure correspondence",
            font=("Segoe UI", 11),
            fg=self.colors["muted"],
            bg=self.colors["card"],
        ).pack(anchor="w", pady=(4, 20))

        tk.Label(
            card,
            text="Username",
            fg=self.colors["muted"],
            bg=self.colors["card"],
        ).pack(anchor="w")
        self.login_username = self._create_entry(card)

        tk.Label(
            card,
            text="Password",
            fg=self.colors["muted"],
            bg=self.colors["card"],
        ).pack(anchor="w", pady=(14, 0))
        self.login_password = self._create_entry(card, show="*")

        login_btn = self._create_button(
            card,
            text="Login",
            command=self.on_login,
            accent=True,
        )
        login_btn.pack(fill="x", pady=(26, 0))

        return card

    def _build_register_card(self, parent):
        card = tk.Frame(parent, bg=self.colors["card"], padx=40, pady=40)

        tk.Label(
            card,
            text="Create account",
            font=("Segoe UI", 16, "bold"),
            fg=self.colors["text"],
            bg=self.colors["card"],
        ).pack(anchor="w")

        tk.Label(
            card,
            text="Set up credentials to start exchanging encrypted messages.",
            font=("Segoe UI", 11),
            fg=self.colors["muted"],
            bg=self.colors["card"],
            wraplength=420,
        ).pack(anchor="w", pady=(4, 20))

        tk.Label(
            card,
            text="Username",
            fg=self.colors["muted"],
            bg=self.colors["card"],
        ).pack(anchor="w")
        self.reg_username = self._create_entry(card)

        tk.Label(
            card,
            text="Password",
            fg=self.colors["muted"],
            bg=self.colors["card"],
        ).pack(anchor="w", pady=(14, 0))
        self.reg_password = self._create_entry(card, show="*")

        register_btn = self._create_button(
            card,
            text="Register",
            command=self.on_register,
            accent=True,
        )
        register_btn.pack(fill="x", pady=(26, 0))

        tk.Label(
            card,
            text="Passwords are hashed with bcrypt and keys are encrypted locally.",
            fg=self.colors["muted"],
            bg=self.colors["card"],
            wraplength=420,
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(12, 0))

        return card

    def _switch_auth_mode(self, mode: str):
        if mode not in ("login", "register"):
            return
        self.auth_mode = mode
        self.login_card.pack_forget()
        self.register_card.pack_forget()
        if mode == "login":
            self.login_card.pack(fill="both", expand=True)
        else:
            self.register_card.pack(fill="both", expand=True)
        self._update_auth_tabs()

    def _update_auth_tabs(self):
        active_login = self.auth_mode == "login"
        self._style_tab_button(self.btn_auth_login, active_login)
        self._style_tab_button(self.btn_auth_register, not active_login)

    # ---------- helpers ----------

    def _create_entry(self, parent, show=None):
        entry = tk.Entry(
            parent,
            show=show,
            bg=self.colors["bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground="#232838",
            highlightcolor=self.colors["accent"],
            font=("Segoe UI", 11),
        )
        entry.pack(fill="x", pady=(4, 0))
        return entry

    def _create_button(self, parent, text, command, accent=True):
        if accent:
            bg = self.colors["accent"]
            active = "#3C8BFF"
        else:
            bg = self.colors["card_soft"]
            active = "#2A3040"
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=self.colors["text"],
            activebackground=active,
            activeforeground=self.colors["text"],
            relief="flat",
            bd=0,
            pady=8,
            font=("Segoe UI", 10, "bold"),
            cursor="hand2",
            highlightthickness=0,
        )
        return btn

    def _style_tab_button(self, button, active: bool):
        if active:
            button.config(
                bg=self.colors["accent"],
                fg=self.colors["text"],
                activebackground="#3C8BFF",
                activeforeground=self.colors["text"],
            )
        else:
            button.config(
                bg=self.colors["card_soft"],
                fg=self.colors["muted"],
                activebackground="#2A3040",
                activeforeground=self.colors["text"],
            )

    def _update_dashboard_stats(self):
        total_users = 0
        total_messages = 0
        inbox_messages = 0

        try:
            total_users = len(self.core.user_store._load())
        except Exception:
            pass

        try:
            total_messages = len(self.core.msg_store._load())
        except Exception:
            pass

        if self.core.current_user:
            try:
                inbox_messages = len(
                    self.core.msg_store.get_messages_for(self.core.current_user)
                )
            except Exception:
                pass

        if "stat_users" in self.stat_labels:
            self.stat_labels["stat_users"].config(text=str(total_users))
        if "stat_messages" in self.stat_labels:
            self.stat_labels["stat_messages"].config(text=str(total_messages))
        if "stat_inbox" in self.stat_labels:
            self.stat_labels["stat_inbox"].config(text=str(inbox_messages))

    # ---------- Handlers ----------

    def on_view_users(self):
        path = getattr(self.core.user_store, "path", "users.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except FileNotFoundError:
            messagebox.showerror("Not found", f"Could not locate '{path}'")
            return
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return

        win = tk.Toplevel(self.root)
        win.title(f"users.json ({os.path.basename(path)})")
        win.configure(bg=self.colors["bg"])
        win.geometry("520x420")

        tk.Label(
            win,
            text="Current hashed entries from users.json",
            fg=self.colors["text"],
            bg=self.colors["bg"],
            font=("Segoe UI", 11, "bold"),
        ).pack(pady=(12, 6))

        txt = scrolledtext.ScrolledText(
            win,
            bg=self.colors["bg_alt"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground="#232838",
        )
        txt.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        txt.insert("1.0", content)
        txt.configure(state="disabled")

    def on_register(self):
        username = self.reg_username.get().strip()
        password = self.reg_password.get().strip()
        try:
            self.core.register(username, password)
            messagebox.showinfo("Success", f"User '{username}' registered")
            self._switch_auth_mode("login")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def on_login(self):
        username = self.login_username.get().strip()
        password = self.login_password.get().strip()
        try:
            self.core.login(username, password)
            self.lbl_current_user.config(text=f"Logged in as: {username}")
            self.auth_frame.pack_forget()
            self.main_frame.pack(fill="both", expand=True)
            self._update_dashboard_stats()
        except Exception as e:
            messagebox.showerror("Login failed", str(e))

    def on_logout(self):
        self.core.logout()

        # очистить поля логина
        self.login_username.delete(0, "end")
        self.login_password.delete(0, "end")

        # очистить поля регистрации
        self.reg_username.delete(0, "end")
        self.reg_password.delete(0, "end")

        # UI переключить обратно
        self.main_frame.pack_forget()
        self.auth_frame.pack(fill="both", expand=True)
        self.lbl_current_user.config(text="Not logged in")
        self._switch_auth_mode("login")
        self._update_dashboard_stats()


    def on_send(self):
        recipient = self.entry_recipient.get().strip()
        message_text = self.text_message.get("1.0", "end").strip()
        if not message_text:
            messagebox.showwarning("Warning", "Message is empty")
            return
        try:
            self.core.send_message(recipient, message_text)
            messagebox.showinfo("Success", "Message sent")
            self.text_message.delete("1.0", "end")
            self._update_dashboard_stats()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def on_refresh_inbox(self):
        try:
            messages = self.core.get_inbox()
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return
        finally:
            self._update_dashboard_stats()

        self.inbox_text.configure(state="normal")
        self.inbox_text.delete("1.0", "end")

        if not messages:
            self.inbox_text.insert("end", "No messages.\n")
        else:
            for m in messages:
                self.inbox_text.insert(
                    "end",
                    f"ID: {m['id']}\nFrom: {m['sender']} at {m['timestamp']}\n",
                )
                if m.get("error"):
                    self.inbox_text.insert("end", f"[ERROR] {m['error']}\n\n")
                else:
                    self.inbox_text.insert("end", f"Message: {m['text']}\n\n")

        self.inbox_text.configure(state="disabled")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureMessagingGUI(root)
    root.mainloop()
