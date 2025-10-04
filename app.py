import json
import os
import base64
import queue
import socket
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Dict, Optional, List

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
        self.timestamps_var = tk.BooleanVar(value=True)
        self.sound_var = tk.BooleanVar(value=True)
        self.autoreconnect_var = tk.BooleanVar(value=True)

        self.network_server: Optional[ChatServer] = None
        self.network_client: Optional[ChatClient] = None

        self.incoming_queue: "queue.Queue[Dict[str, str]]" = queue.Queue()

        # Discovery and admin
        self.server_list: List[Dict[str, object]] = []
        self.server_list_var = tk.StringVar(value="")
        self.filters_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Ready")

        self._build_ui()
        self._schedule_poll()

    def _build_ui(self) -> None:
        top = ttk.Frame(self.root, padding=8)
        top.pack(fill=tk.BOTH, expand=True)

        # Menubar
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save Log", command=self._save_log)
        file_menu.add_command(label="Clear Log", command=self._clear_log)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_checkbutton(label="Show Timestamps", variable=self.timestamps_var)
        view_menu.add_checkbutton(label="Sound Notifications", variable=self.sound_var)
        view_menu.add_separator()
        view_menu.add_command(label="Theme...", command=self._open_theme_dialog)
        menubar.add_cascade(label="View", menu=view_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=lambda: messagebox.showinfo("About", "Local LAN Chat\nJSON over TCP + UDP discovery"))
        menubar.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=menubar)

        # Connection frame
        conn = ttk.LabelFrame(top, text="Connection")
        conn.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(conn, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=(8, 4), pady=4)
        ttk.Entry(conn, textvariable=self.username_var, width=18).grid(row=0, column=1, sticky=tk.W, pady=4)

        ttk.Label(conn, text="Mode:").grid(row=0, column=2, sticky=tk.W, padx=(16, 4))
        mode_combo = ttk.Combobox(conn, textvariable=self.mode_var, values=["Listener", "Connect"], state="readonly", width=10)
        mode_combo.grid(row=0, column=3, sticky=tk.W)
        mode_combo.bind("<<ComboboxSelected>>", lambda _e: self._update_toggle_text_for_mode())

        ttk.Label(conn, text="Host:").grid(row=0, column=4, sticky=tk.W, padx=(16, 4))
        ttk.Entry(conn, textvariable=self.host_var, width=16).grid(row=0, column=5, sticky=tk.W)

        ttk.Label(conn, text="Port:").grid(row=0, column=6, sticky=tk.W, padx=(16, 4))
        ttk.Entry(conn, textvariable=self.port_var, width=7).grid(row=0, column=7, sticky=tk.W)

        self.toggle_btn = ttk.Button(conn, text="Start Listening", command=self._on_toggle)
        self.toggle_btn.grid(row=0, column=8, padx=(16, 8))

        # Discovery + auto-reconnect (row 1)
        ttk.Label(conn, text="Servers:").grid(row=1, column=0, sticky=tk.W, padx=(8, 4))
        self.server_combo = ttk.Combobox(conn, textvariable=self.server_list_var, values=[], width=40, state="readonly")
        self.server_combo.grid(row=1, column=1, columnspan=5, sticky=tk.W+tk.E, pady=(4, 4))
        self.server_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_select_discovered())
        ttk.Button(conn, text="Discover", command=self._discover_servers).grid(row=1, column=6, sticky=tk.W, padx=(8, 4))
        ttk.Checkbutton(conn, text="Auto-Reconnect", variable=self.autoreconnect_var).grid(row=1, column=7, sticky=tk.W)

        # Chat frame
        chat = ttk.LabelFrame(top, text="Chat")
        chat.pack(fill=tk.BOTH, expand=True)

        self.text = tk.Text(chat, height=18, wrap=tk.WORD, state=tk.DISABLED)
        self.text.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Admin frame (Listener only controls for filters, blocking, users)
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

        ttk.Label(admin, text="Filters (comma-separated):").grid(row=0, column=3, sticky=tk.W, padx=(24,4))
        ttk.Entry(admin, textvariable=self.filters_var, width=30).grid(row=0, column=4, sticky=tk.W)
        ttk.Button(admin, text="Apply", command=self._apply_filters).grid(row=0, column=5, padx=(8,8))
        ttk.Button(admin, text="Clear", command=self._clear_filters).grid(row=0, column=6, padx=(0,8))

        ttk.Label(admin, text="Current Users:").grid(row=0, column=3, sticky=tk.W, padx=(24,4))
        self.user_listbox = tk.Listbox(admin, height=5, width=24)
        self.user_listbox.grid(row=0, column=7, rowspan=2, sticky=tk.N+tk.S+tk.W, padx=(0,8), pady=4)

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

        # Status bar
        status_frame = ttk.Frame(top)
        status_frame.pack(fill=tk.X)
        ttk.Label(status_frame, textvariable=self.status_var, anchor=tk.W).pack(side=tk.LEFT, padx=(8,8))

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
                self._update_status(f"Listening on {host}:{port}")
            except Exception as e:
                self.network_server = None
                messagebox.showerror("Server Error", str(e))
        else:
            try:
                self.network_client = ChatClient(host, port, username=username, on_message=self._on_network_message)
                self.network_client.connect()
                self.network_client.enable_auto_reconnect(self.autoreconnect_var.get())
                self.toggle_btn.config(text="Disconnect")
                self._append_chat(f"[System] Connected to {host}:{port} as {username}")
                self._update_status(f"Connected to {host}:{port}")
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
            self._update_status("Disconnected")
        if self.network_server:
            try:
                self.network_server.stop()
            except Exception:
                pass
            self.network_server = None
            self._append_chat("[System] Server stopped")
            self._update_status("Server stopped")
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
                # Sound notification for file received from others
                if self.sound_var.get() and (username or "") != (self.username_var.get().strip() or ""):
                    try:
                        self.root.bell()
                    except Exception:
                        pass
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
        user = str(obj.get('username', ''))
        self._append_chat(f"{user}: {obj.get('message', '')}")
        if self.sound_var.get() and user and user != (self.username_var.get().strip() or ""):
            try:
                self.root.bell()
            except Exception:
                pass

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
        if self.timestamps_var.get():
            timestamp = time.strftime("[%H:%M:%S] ")
        else:
            timestamp = ""
        self.text.configure(state=tk.NORMAL)
        self.text.insert(tk.END, timestamp + line + "\n")
        self.text.see(tk.END)
        self.text.configure(state=tk.DISABLED)

    def _on_close(self) -> None:
        self._disconnect()
        self.root.destroy()

    # Admin helpers
    def _apply_filters(self) -> None:
        if not self.network_server:
            messagebox.showinfo("Info", "Filters only work in Listener mode.")
            return
        filters_text = self.filters_var.get().strip()
        filters = [s.strip() for s in filters_text.split(",") if s.strip()]
        try:
            self.network_server.set_message_filters(filters)
            self._append_chat("[Admin] Message filters applied")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _clear_filters(self) -> None:
        self.filters_var.set("")
        if self.network_server:
            try:
                self.network_server.set_message_filters([])
                self._append_chat("[Admin] Message filters cleared")
            except Exception:
                pass

    # Discovery helpers
    def _discover_servers(self) -> None:
        def worker() -> None:
            try:
                results = ChatClient.discover_servers(timeout=1.5)
            except Exception:
                results = []
            def update_ui() -> None:
                self.server_list = results
                options = [f"{item['name']} @ {item['host']}:{item['port']}" for item in results]
                self.server_combo["values"] = options
                if options:
                    self.server_combo.current(0)
            self.root.after(0, update_ui)
        threading.Thread(target=worker, name="Discovery", daemon=True).start()

    def _on_select_discovered(self) -> None:
        idx = self.server_combo.current()
        if idx is None or idx < 0 or idx >= len(self.server_list):
            return
        item = self.server_list[idx]
        self.host_var.set(str(item.get("host", "")))
        self.port_var.set(str(item.get("port", "")))

    # Theme
    def _open_theme_dialog(self) -> None:
        dlg = tk.Toplevel(self.root)
        dlg.title("Select Theme")
        dlg.resizable(False, False)
        ttk.Label(dlg, text="Theme:").grid(row=0, column=0, padx=8, pady=8, sticky=tk.W)
        style = ttk.Style()
        themes = list(style.theme_names())
        theme_var = tk.StringVar(value=style.theme_use())
        combo = ttk.Combobox(dlg, textvariable=theme_var, values=themes, state="readonly", width=20)
        combo.grid(row=0, column=1, padx=8, pady=8)
        def apply_theme() -> None:
            try:
                style.theme_use(theme_var.get())
            except Exception as e:
                messagebox.showerror("Theme", str(e))
            dlg.destroy()
        ttk.Button(dlg, text="Apply", command=apply_theme).grid(row=1, column=0, columnspan=2, pady=(0,8))

    # Log helpers
    def _save_log(self) -> None:
        try:
            content = self.text.get("1.0", tk.END)
        except Exception:
            content = ""
        if not content.strip():
            messagebox.showinfo("Save Log", "Log is empty.")
            return
        path = filedialog.asksaveasfilename(title="Save chat log", defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            self._append_chat(f"[System] Log saved to {path}")
        except Exception as e:
            messagebox.showerror("Save Log", str(e))

    def _clear_log(self) -> None:
        try:
            self.text.configure(state=tk.NORMAL)
            self.text.delete("1.0", tk.END)
            self.text.configure(state=tk.DISABLED)
        except Exception:
            pass

    # Status helpers
    def _update_status(self, text: str) -> None:
        self.status_var.set(text)


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


