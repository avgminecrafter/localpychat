import json
import os
import base64
import queue
import socket
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Dict, Optional

from chat_network import ChatClient, ChatServer
from crypto_utils import decrypt_bytes, ALG_IDENTIFIER


class ChatApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Local LAN Chat (JSON)")

        # State
        self.username_var = tk.StringVar(value="User")
        self.mode_var = tk.StringVar(value="Listener")  # Listener or Connect
        self.host_var = tk.StringVar(value=self._get_default_host())
        self.port_var = tk.StringVar(value="5000")

        self.network_server: Optional[ChatServer] = None
        self.network_client: Optional[ChatClient] = None

        self.incoming_queue: "queue.Queue[Dict[str, str]]" = queue.Queue()

        self._build_ui()
        self._schedule_poll()

    def _build_ui(self) -> None:
        top = ttk.Frame(self.root, padding=8)
        top.pack(fill=tk.BOTH, expand=True)

        # Connection frame
        conn = ttk.LabelFrame(top, text="Connection")
        conn.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(conn, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=(8, 4), pady=4)
        ttk.Entry(conn, textvariable=self.username_var, width=18).grid(row=0, column=1, sticky=tk.W, pady=4)

        ttk.Label(conn, text="Mode:").grid(row=0, column=2, sticky=tk.W, padx=(16, 4))
        mode_combo = ttk.Combobox(conn, textvariable=self.mode_var, values=["Listener", "Connect"], state="readonly", width=10)
        mode_combo.grid(row=0, column=3, sticky=tk.W)

        ttk.Label(conn, text="Host:").grid(row=0, column=4, sticky=tk.W, padx=(16, 4))
        ttk.Entry(conn, textvariable=self.host_var, width=16).grid(row=0, column=5, sticky=tk.W)

        ttk.Label(conn, text="Port:").grid(row=0, column=6, sticky=tk.W, padx=(16, 4))
        ttk.Entry(conn, textvariable=self.port_var, width=7).grid(row=0, column=7, sticky=tk.W)

        self.toggle_btn = ttk.Button(conn, text="Start Listening", command=self._on_toggle)
        self.toggle_btn.grid(row=0, column=8, padx=(16, 8))

        # Encryption controls
        ttk.Label(conn, text="Passphrase:").grid(row=1, column=0, sticky=tk.W, padx=(8, 4))
        self.passphrase_var = tk.StringVar()
        self.show_enc_var = tk.BooleanVar(value=False)
        self.encrypt_enabled_var = tk.BooleanVar(value=False)
        self.pass_entry = ttk.Entry(conn, textvariable=self.passphrase_var, width=24, show="*")
        self.pass_entry.grid(row=1, column=1, columnspan=2, sticky=tk.W)
        self.show_cb = ttk.Checkbutton(conn, text="Show", variable=self.show_enc_var, command=self._toggle_show_pass)
        self.show_cb.grid(row=1, column=3, sticky=tk.W)
        self.encrypt_cb = ttk.Checkbutton(conn, text="Encrypt messages/files", variable=self.encrypt_enabled_var)
        self.encrypt_cb.grid(row=1, column=4, columnspan=3, sticky=tk.W)

        # Chat frame
        chat = ttk.LabelFrame(top, text="Chat")
        chat.pack(fill=tk.BOTH, expand=True)

        self.text = tk.Text(chat, height=18, wrap=tk.WORD, state=tk.DISABLED)
        self.text.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Admin frame (Listener only controls for blocking and users)
        admin = ttk.LabelFrame(top, text="Admin (Listener only)")
        admin.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(admin, text="Block Username:").grid(row=0, column=0, sticky=tk.W, padx=(8,4))
        self.block_user_var = tk.StringVar()
        ttk.Entry(admin, textvariable=self.block_user_var, width=20).grid(row=0, column=1, sticky=tk.W)
        ttk.Button(admin, text="Block", command=self._block_username).grid(row=0, column=2, padx=(8,8))

        ttk.Label(admin, text="Block IP:").grid(row=1, column=0, sticky=tk.W, padx=(8,4))
        self.block_ip_var = tk.StringVar()
        ttk.Entry(admin, textvariable=self.block_ip_var, width=20).grid(row=1, column=1, sticky=tk.W)
        ttk.Button(admin, text="Block", command=self._block_ip).grid(row=1, column=2, padx=(8,8))

        ttk.Label(admin, text="Current Users:").grid(row=0, column=3, sticky=tk.W, padx=(24,4))
        self.user_listbox = tk.Listbox(admin, height=5, width=24)
        self.user_listbox.grid(row=0, column=4, rowspan=2, sticky=tk.N+tk.S+tk.W, padx=(0,8), pady=4)

        bottom = ttk.Frame(top)
        bottom.pack(fill=tk.X)

        self.entry_var = tk.StringVar()
        entry = ttk.Entry(bottom, textvariable=self.entry_var)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 4), pady=(0, 8))
        entry.bind("<Return>", lambda _e: self._on_send())

        send_btn = ttk.Button(bottom, text="Send", command=self._on_send)
        send_btn.pack(side=tk.RIGHT, padx=(4, 8), pady=(0, 8))

        file_btn = ttk.Button(bottom, text="Send File", command=self._on_send_file)
        file_btn.pack(side=tk.RIGHT, padx=(4, 0), pady=(0, 8))

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _get_default_host(self) -> str:
        try:
            # Try to get the LAN IP; fallback to 0.0.0.0
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            parts = ip.split(".")
            if len(parts) == 4:
                return ip
        except Exception:
            pass
        return "0.0.0.0"

    def _schedule_poll(self) -> None:
        self.root.after(100, self._poll_incoming)

    def _poll_incoming(self) -> None:
        while True:
            try:
                obj = self.incoming_queue.get_nowait()
            except queue.Empty:
                break
            self._handle_incoming(obj)
        self._schedule_poll()

    def _on_toggle(self) -> None:
        mode = self.mode_var.get()
        host = self.host_var.get().strip()
        port_str = self.port_var.get().strip()
        username = self.username_var.get().strip() or "User"
        try:
            port = int(port_str)
        except ValueError:
            messagebox.showerror("Invalid Port", "Port must be an integer")
            return

        if self.network_server or self.network_client:
            self._disconnect()
            return

        if mode == "Listener":
            try:
                self.network_server = ChatServer(host, port, on_message=self._on_network_message)
                # Ensure listener is shown in user list
                self.network_server.set_server_username(username)
                self.network_server.start()
                self.toggle_btn.config(text="Stop Listening")
                self._append_chat(f"[System] Listening on {host}:{port}")
            except Exception as e:
                self.network_server = None
                messagebox.showerror("Server Error", str(e))
        else:
            try:
                self.network_client = ChatClient(host, port, username=username, on_message=self._on_network_message)
                self.network_client.connect()
                self.toggle_btn.config(text="Disconnect")
                self._append_chat(f"[System] Connected to {host}:{port} as {username}")
            except Exception as e:
                self.network_client = None
                messagebox.showerror("Client Error", str(e))

    def _disconnect(self) -> None:
        if self.network_client:
            try:
                self.network_client.disconnect()
            except Exception:
                pass
            self.network_client = None
            self._append_chat("[System] Disconnected")
        if self.network_server:
            try:
                self.network_server.stop()
            except Exception:
                pass
            self.network_server = None
            self._append_chat("[System] Server stopped")
        # Reset UI button text based on mode
        self._update_toggle_text_for_mode()

    def _on_send(self) -> None:
        text = self.entry_var.get().strip()
        if not text:
            return
        username = self.username_var.get().strip() or "User"
        encrypt = bool(self.encrypt_enabled_var.get()) and bool(self.passphrase_var.get())
        passphrase = self.passphrase_var.get() if encrypt else None
        if self.network_server:
            self.network_server.send_from_server(username=username, message=text, encrypt=encrypt, passphrase=passphrase)
        elif self.network_client:
            self.network_client.send_message(text, username=username, encrypt=encrypt, passphrase=passphrase)
        else:
            self._append_chat("[System] Not connected")
        self.entry_var.set("")

    def _on_send_file(self) -> None:
        path = filedialog.askopenfilename(title="Select file to send")
        if not path:
            return
        username = self.username_var.get().strip() or "User"
        encrypt = bool(self.encrypt_enabled_var.get()) and bool(self.passphrase_var.get())
        passphrase = self.passphrase_var.get() if encrypt else None
        if self.network_server:
            try:
                self.network_server.send_file_from_server(username=username, file_path=path, encrypt=encrypt, passphrase=passphrase)
            except Exception as e:
                messagebox.showerror("File Send Error", str(e))
        elif self.network_client:
            try:
                self.network_client.send_file(path, username=username, encrypt=encrypt, passphrase=passphrase)
            except Exception as e:
                messagebox.showerror("File Send Error", str(e))
        else:
            self._append_chat("[System] Not connected")

    def _on_network_message(self, obj: Dict[str, object]) -> None:
        try:
            # Ensure JSON schema, then queue to UI thread
            payload: Dict[str, object] = {
                "username": str(obj.get("username", "")),
                "message": str(obj.get("message", "")),
            }
            if isinstance(obj.get("type"), str):
                payload["type"] = obj["type"]
            if payload.get("type") == "file":
                for key in ("filename", "filesize", "filedata_b64"):
                    if key in obj:
                        payload[key] = obj[key]
            if payload.get("type") == "userlist" and isinstance(obj.get("users"), list):
                payload["users"] = obj["users"]
            # Preserve encryption fields if present
            if bool(obj.get("enc")):
                payload["enc"] = True
                for key in ("enc_alg", "ciphertext_b64", "nonce_b64", "salt_b64"):
                    if key in obj:
                        payload[key] = obj[key]
        except Exception:
            return
        self.incoming_queue.put(payload)

    def _handle_incoming(self, obj: Dict[str, object]) -> None:
        msg_type = str(obj.get("type", "text"))
        if msg_type == "file":
            username = str(obj.get("username", ""))
            filename = str(obj.get("filename", "received_file"))
            filesize = int(obj.get("filesize", 0) or 0)
            b64 = obj.get("filedata_b64")
            save_dir = os.path.join(os.path.expanduser("~"), "Downloads")
            os.makedirs(save_dir, exist_ok=True)
            safe_name = filename or "received_file"
            is_encrypted = bool(obj.get("enc")) and obj.get("enc_alg") == ALG_IDENTIFIER
            dest_filename = safe_name
            dest_path = os.path.join(save_dir, dest_filename)
            try:
                if isinstance(b64, str):
                    data = base64.b64decode(b64)
                else:
                    data = b""
                # Attempt decryption if marked encrypted and we have a passphrase
                decrypted_ok = False
                if is_encrypted:
                    try:
                        passphrase = self.passphrase_var.get()
                        if passphrase:
                            nonce_b64 = str(obj.get("nonce_b64", ""))
                            salt_b64 = str(obj.get("salt_b64", ""))
                            plaintext = decrypt_bytes(base64.b64encode(data).decode("ascii"), nonce_b64, salt_b64, passphrase)
                            data = plaintext
                            decrypted_ok = True
                    except Exception:
                        pass
                if is_encrypted and not decrypted_ok:
                    # Save ciphertext with .enc suffix
                    dest_filename = f"{safe_name}.enc"
                    dest_path = os.path.join(save_dir, dest_filename)
                with open(dest_path, "wb") as f:
                    f.write(data)
                suffix_note = " (encrypted, .enc)" if (is_encrypted and not decrypted_ok) else ""
                self._append_chat(f"[File] {username} -> saved to {dest_path}{suffix_note} ({len(data)} bytes)")
            except Exception as e:
                self._append_chat(f"[File] Error saving file {safe_name}: {e}")
            return
        if msg_type == "userlist":
            try:
                users = obj.get("users") or []
                self.user_listbox.delete(0, tk.END)
                for u in users:
                    self.user_listbox.insert(tk.END, str(u))
                self._append_chat("[System] User list updated")
            except Exception:
                pass
            return
        # join/leave/text fallback with decryption
        message_text = str(obj.get("message", ""))
        if obj.get("enc") and obj.get("enc_alg") == ALG_IDENTIFIER:
            try:
                passphrase = self.passphrase_var.get()
                if passphrase:
                    ciphertext_b64 = str(obj.get("ciphertext_b64", ""))
                    nonce_b64 = str(obj.get("nonce_b64", ""))
                    salt_b64 = str(obj.get("salt_b64", ""))
                    plaintext = decrypt_bytes(ciphertext_b64, nonce_b64, salt_b64, passphrase)
                    message_text = plaintext.decode("utf-8", errors="replace")
            except Exception:
                pass
        self._append_chat(f"{obj.get('username', '')}: {message_text}")

    # Admin controls
    def _block_username(self) -> None:
        if not self.network_server:
            messagebox.showinfo("Info", "Blocking only works in Listener mode.")
            return
        username = self.block_user_var.get().strip()
        if not username:
            return
        try:
            self.network_server.add_block_username(username)
            self._append_chat(f"[Admin] Blocked username: {username}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _block_ip(self) -> None:
        if not self.network_server:
            messagebox.showinfo("Info", "Blocking only works in Listener mode.")
            return
        ip = self.block_ip_var.get().strip()
        if not ip:
            return
        try:
            self.network_server.add_block_ip(ip)
            self._append_chat(f"[Admin] Blocked IP: {ip}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _update_toggle_text_for_mode(self) -> None:
        mode = self.mode_var.get()
        if self.network_server or self.network_client:
            return
        if mode == "Listener":
            self.toggle_btn.config(text="Start Listening")
        else:
            self.toggle_btn.config(text="Connect")

    def _append_chat(self, line: str) -> None:
        self.text.configure(state=tk.NORMAL)
        self.text.insert(tk.END, line + "\n")
        self.text.see(tk.END)
        self.text.configure(state=tk.DISABLED)

    def _on_close(self) -> None:
        self._disconnect()
        self.root.destroy()

    def _toggle_show_pass(self) -> None:
        try:
            if self.show_enc_var.get():
                self.pass_entry.configure(show="")
            else:
                self.pass_entry.configure(show="*")
        except Exception:
            pass


def main() -> None:
    root = tk.Tk()
    # Tk on macOS looks better with ttk theme 'aqua' by default
    try:
        style = ttk.Style()
        if "aqua" in style.theme_names():
            style.theme_use("aqua")
    except Exception:
        pass
    app = ChatApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()


