import json
import os
import base64
import queue
import socket
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Dict, Optional
import time

from chat_network import ChatClient, ChatServer


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

        # Filters and stats columns
        # Column 3-6: users
        ttk.Label(admin, text="Current Users:").grid(row=0, column=3, sticky=tk.W, padx=(24,4))
        self.user_listbox = tk.Listbox(admin, height=5, width=24)
        self.user_listbox.grid(row=0, column=4, rowspan=3, sticky=tk.N+tk.S+tk.W, padx=(0,8), pady=4)

        # Column 6-10: filters
        ttk.Label(admin, text="Blocked Keywords (comma)").grid(row=0, column=5, sticky=tk.W, padx=(8,4))
        self.block_keywords_var = tk.StringVar()
        ttk.Entry(admin, textvariable=self.block_keywords_var, width=24).grid(row=0, column=6, sticky=tk.W)
        ttk.Button(admin, text="Apply", command=self._apply_block_keywords).grid(row=0, column=7, padx=(8,8))

        ttk.Label(admin, text="Allowed Types").grid(row=1, column=5, sticky=tk.W, padx=(8,4))
        self.allowed_types_var = tk.StringVar(value="text,file,join,leave,userlist")
        ttk.Entry(admin, textvariable=self.allowed_types_var, width=24).grid(row=1, column=6, sticky=tk.W)
        ttk.Button(admin, text="Apply", command=self._apply_allowed_types).grid(row=1, column=7, padx=(8,8))

        ttk.Label(admin, text="Max Msg Len").grid(row=2, column=5, sticky=tk.W, padx=(8,4))
        self.max_len_var = tk.StringVar(value="0")
        ttk.Entry(admin, textvariable=self.max_len_var, width=10).grid(row=2, column=6, sticky=tk.W)
        ttk.Button(admin, text="Apply", command=self._apply_max_len).grid(row=2, column=7, padx=(8,8))

        ttk.Label(admin, text="Max File KB").grid(row=2, column=8, sticky=tk.W, padx=(8,4))
        self.max_file_kb_var = tk.StringVar(value="0")
        ttk.Entry(admin, textvariable=self.max_file_kb_var, width=10).grid(row=2, column=9, sticky=tk.W)
        ttk.Button(admin, text="Apply", command=self._apply_max_file_kb).grid(row=2, column=10, padx=(8,8))

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

        # Stats footer
        stats = ttk.LabelFrame(top, text="Listener Stats")
        stats.pack(fill=tk.X, pady=(0, 8))
        self.stats_var = tk.StringVar(value="-")
        ttk.Label(stats, textvariable=self.stats_var).pack(side=tk.LEFT, padx=8, pady=(0,8))

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
        # Also schedule periodic stats refresh
        self.root.after(1000, self._refresh_stats)

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
        if self.network_server:
            self.network_server.send_from_server(username=username, message=text)
        elif self.network_client:
            self.network_client.send_message(text, username=username)
        else:
            self._append_chat("[System] Not connected")
        self.entry_var.set("")

    def _on_send_file(self) -> None:
        path = filedialog.askopenfilename(title="Select file to send")
        if not path:
            return
        username = self.username_var.get().strip() or "User"
        if self.network_server:
            try:
                self.network_server.send_file_from_server(username=username, file_path=path)
            except Exception as e:
                messagebox.showerror("File Send Error", str(e))
        elif self.network_client:
            try:
                self.network_client.send_file(path, username=username)
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
            dest_path = os.path.join(save_dir, safe_name)
            try:
                if isinstance(b64, str):
                    data = base64.b64decode(b64)
                else:
                    data = b""
                with open(dest_path, "wb") as f:
                    f.write(data)
                self._append_chat(f"[File] {username} -> saved to {dest_path} ({len(data)} bytes)")
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
        # join/leave/text fallback
        self._append_chat(f"{obj.get('username', '')}: {obj.get('message', '')}")

    # Filters UI actions
    def _apply_block_keywords(self) -> None:
        if not self.network_server:
            messagebox.showinfo("Info", "Filters only work in Listener mode.")
            return
        raw = self.block_keywords_var.get()
        keywords = [k.strip() for k in (raw.split(",") if raw else []) if k.strip()]
        try:
            self.network_server.set_blocked_keywords(keywords)
            self._append_chat(f"[Admin] Blocked keywords set: {', '.join(keywords) if keywords else '(none)'}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _apply_allowed_types(self) -> None:
        if not self.network_server:
            messagebox.showinfo("Info", "Filters only work in Listener mode.")
            return
        raw = self.allowed_types_var.get()
        types = [t.strip() for t in (raw.split(",") if raw else []) if t.strip()]
        try:
            self.network_server.set_allowed_message_types(types if types else None)
            self._append_chat(f"[Admin] Allowed types: {', '.join(types) if types else '(all)'}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _apply_max_len(self) -> None:
        if not self.network_server:
            messagebox.showinfo("Info", "Filters only work in Listener mode.")
            return
        raw = self.max_len_var.get().strip()
        try:
            max_len = int(raw)
        except Exception:
            messagebox.showerror("Error", "Max message length must be integer")
            return
        try:
            self.network_server.set_max_message_length(max_len if max_len > 0 else None)
            self._append_chat(f"[Admin] Max message length: {max_len if max_len > 0 else '(no limit)'}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _apply_max_file_kb(self) -> None:
        if not self.network_server:
            messagebox.showinfo("Info", "Filters only work in Listener mode.")
            return
        raw = self.max_file_kb_var.get().strip()
        try:
            max_kb = int(raw)
        except Exception:
            messagebox.showerror("Error", "Max file KB must be integer")
            return
        try:
            self.network_server.set_max_file_size_bytes(max_kb * 1024 if max_kb > 0 else None)
            self._append_chat(f"[Admin] Max file size: {max_kb if max_kb > 0 else '(no limit)'} KB")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # Stats display
    def _refresh_stats(self) -> None:
        try:
            if self.network_server:
                snap = self.network_server.get_metrics_snapshot()
                text = (
                    f"Msgs/s: {snap['messages_per_second']:.0f} (10s avg {snap['messages_per_second_10s_avg']:.1f})  "
                    f"KB/s: {snap['kilobytes_per_second']:.1f} (10s avg {snap['kilobytes_per_second_10s_avg']:.1f})  "
                    f"Total msgs: {snap['messages_total']}  Uptime: {snap['uptime_seconds']}s  "
                    f"Conns: {snap['active_connections']} Users: {snap['connected_users']}"
                )
                self.stats_var.set(text)
            else:
                self.stats_var.set("-")
        except Exception:
            self.stats_var.set("-")
        # Reschedule
        self.root.after(1000, self._refresh_stats)

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


