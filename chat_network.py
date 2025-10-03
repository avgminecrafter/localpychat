import json
import os
import base64
import socket
import threading
from typing import Callable, Dict, List, Optional, Tuple


def _safe_json_dumps(payload: Dict[str, object]) -> bytes:
    """Serialize payload to UTF-8 bytes with newline delimiter.

    Always includes required fields (username, message). Preserves optional
    fields such as type and file metadata when present.
    """
    data: Dict[str, object] = {
        "username": str(payload.get("username", "")),
        "message": str(payload.get("message", "")),
    }
    # Optional message type
    msg_type = payload.get("type")
    if isinstance(msg_type, str) and msg_type:
        data["type"] = msg_type
    # Optional file fields
    if data.get("type") == "file":
        for key in ("filename", "filesize", "filedata_b64"):
            if key in payload:
                data[key] = payload[key]
    # Optional user list broadcast
    if data.get("type") == "userlist":
        if "users" in payload:
            data["users"] = payload["users"]
    return (json.dumps(data, ensure_ascii=False) + "\n").encode("utf-8")


def _extract_json_lines_from_buffer(buffer: str) -> Tuple[List[Dict[str, object]], str]:
    """Extract complete JSON objects from a newline-delimited buffer.

    Returns a tuple of (list_of_parsed_objects, remaining_buffer)
    """
    messages: List[Dict[str, object]] = []
    while True:
        newline_index = buffer.find("\n")
        if newline_index == -1:
            break
        line = buffer[:newline_index].strip()
        buffer = buffer[newline_index + 1 :]
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict) and "username" in obj and "message" in obj:
                clean: Dict[str, object] = {
                    "username": str(obj.get("username", "")),
                    "message": str(obj.get("message", "")),
                }
                if isinstance(obj.get("type"), str):
                    clean["type"] = obj["type"]
                if clean.get("type") == "file":
                    for key in ("filename", "filesize", "filedata_b64"):
                        if key in obj:
                            clean[key] = obj[key]
                if clean.get("type") == "userlist" and isinstance(obj.get("users"), list):
                    clean["users"] = obj["users"]
                messages.append(clean)
        except json.JSONDecodeError:
            # Ignore malformed JSON lines
            continue
    return messages, buffer


class ChatServer:
    """TCP chat server broadcasting JSON messages to all connected clients.

    Network protocol: newline-delimited JSON per message.
    JSON schema: {"username": str, "message": str}
    """

    def __init__(self, host: str, port: int, on_message: Callable[[Dict[str, object]], None]):
        self.host = host
        self.port = port
        self._on_message = on_message

        self._server_socket: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._client_threads: List[threading.Thread] = []
        self._clients: List[socket.socket] = []
        self._clients_lock = threading.Lock()
        self._stop_event = threading.Event()
        # Track last known username per connection for disconnect messages
        self._conn_to_username: Dict[socket.socket, str] = {}
        # Track peer IP per connection for IP-based blocking and diagnostics
        self._conn_to_ip: Dict[socket.socket, str] = {}
        # Session-scoped controls
        self._blocked_ips: List[str] = []
        self._blocked_usernames: List[str] = []
        # Listener username (optional, set by UI)
        self._server_username: str = ""

    def start(self) -> None:
        if self._server_socket is not None:
            return
        self._stop_event.clear()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(20)
        server.settimeout(0.5)
        self._server_socket = server

        self._accept_thread = threading.Thread(target=self._accept_loop, name="ChatServerAccept", daemon=True)
        self._accept_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._server_socket is not None:
            try:
                self._server_socket.close()
            except Exception:
                pass
            self._server_socket = None

        # Close all client sockets
        with self._clients_lock:
            clients_snapshot = list(self._clients)
        for conn in clients_snapshot:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

        # Join threads
        if self._accept_thread is not None and self._accept_thread.is_alive():
            self._accept_thread.join(timeout=1.5)
        for t in list(self._client_threads):
            if t.is_alive():
                t.join(timeout=1.5)

        with self._clients_lock:
            self._clients.clear()
        self._client_threads.clear()

    def send_from_server(self, username: str, message: str) -> None:
        payload: Dict[str, object] = {"username": username, "message": message, "type": "text"}
        # Local UI callback
        try:
            self._on_message(payload)
        except Exception:
            pass
        # Broadcast to all clients
        self._broadcast(payload)

    def send_file_from_server(self, username: str, file_path: str) -> None:
        try:
            with open(file_path, "rb") as f:
                data_bytes = f.read()
        except Exception:
            return
        filename = os.path.basename(file_path)
        filesize = len(data_bytes)
        filedata_b64 = base64.b64encode(data_bytes).decode("ascii")
        payload: Dict[str, object] = {
            "type": "file",
            "username": username,
            "message": f"sent file: {filename} ({filesize} bytes)",
            "filename": filename,
            "filesize": filesize,
            "filedata_b64": filedata_b64,
        }
        try:
            self._on_message(payload)
        except Exception:
            pass
        self._broadcast(payload)

    # Internal methods
    def _accept_loop(self) -> None:
        assert self._server_socket is not None
        server = self._server_socket
        while not self._stop_event.is_set():
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                # Socket closed
                break
            except Exception:
                continue

            # IP blocking before accepting client
            try:
                peer_ip = addr[0]
            except Exception:
                peer_ip = ""
            if peer_ip and self._is_ip_blocked(peer_ip):
                try:
                    conn.close()
                except Exception:
                    pass
                continue

            conn.settimeout(0.5)
            with self._clients_lock:
                self._clients.append(conn)
                if peer_ip:
                    self._conn_to_ip[conn] = peer_ip

            t = threading.Thread(target=self._handle_client, args=(conn,), name="ChatServerClient", daemon=True)
            t.start()
            self._client_threads.append(t)

    def _handle_client(self, conn: socket.socket) -> None:
        buffer = ""
        try:
            while not self._stop_event.is_set():
                try:
                    data = conn.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break

                if not data:
                    break

                try:
                    chunk = data.decode("utf-8", errors="ignore")
                except Exception:
                    continue
                buffer += chunk
                messages, buffer = _extract_json_lines_from_buffer(buffer)
                for obj in messages:
                    # Track username for disconnect announcements and user list
                    try:
                        username = str(obj.get("username", ""))
                    except Exception:
                        username = ""
                    prev_username = self._conn_to_username.get(conn, "")
                    if username and username != prev_username:
                        with self._clients_lock:
                            self._conn_to_username[conn] = username
                        # After we learn a username, update user list for everyone
                        self._broadcast_userlist()

                    # Block by username
                    if username and self._is_username_blocked(username):
                        try:
                            conn.shutdown(socket.SHUT_RDWR)
                        except Exception:
                            pass
                        try:
                            conn.close()
                        except Exception:
                            pass
                        break

                    # Notify UI and broadcast to all clients (including sender)
                    try:
                        self._on_message(obj)
                    except Exception:
                        pass
                    self._broadcast(obj)
        finally:
            try:
                conn.close()
            except Exception:
                pass
            with self._clients_lock:
                if conn in self._clients:
                    self._clients.remove(conn)
                username_left = self._conn_to_username.pop(conn, "")
                self._conn_to_ip.pop(conn, None)
            # Broadcast disconnect message
            leave_payload: Dict[str, object] = {
                "type": "leave",
                "username": username_left or "System",
                "message": f"{username_left or 'A user'} left the chat",
            }
            try:
                self._on_message(leave_payload)
            except Exception:
                pass
            self._broadcast(leave_payload)
            # Update user list
            self._broadcast_userlist()

    def _broadcast(self, payload: Dict[str, object]) -> None:
        data = _safe_json_dumps(payload)
        with self._clients_lock:
            clients_snapshot = list(self._clients)
        for client in clients_snapshot:
            try:
                client.sendall(data)
            except Exception:
                # Drop broken connections
                try:
                    client.close()
                except Exception:
                    pass
                with self._clients_lock:
                    if client in self._clients:
                        self._clients.remove(client)

    # Session controls
    def set_blocked_ips(self, ips: List[str]) -> None:
        self._blocked_ips = [ip.strip() for ip in ips if ip and ip.strip()]
        self._kick_blocked_connections()

    def set_blocked_usernames(self, usernames: List[str]) -> None:
        self._blocked_usernames = [u.strip().lower() for u in usernames if u and u.strip()]
        self._kick_blocked_connections()

    def add_block_ip(self, ip: str) -> None:
        ip = (ip or "").strip()
        if not ip:
            return
        if ip not in self._blocked_ips:
            self._blocked_ips.append(ip)
        self._kick_blocked_connections()

    def add_block_username(self, username: str) -> None:
        username_l = (username or "").strip().lower()
        if not username_l:
            return
        if username_l not in self._blocked_usernames:
            self._blocked_usernames.append(username_l)
        self._kick_blocked_connections()

    def get_current_users(self) -> List[str]:
        with self._clients_lock:
            return list(self._conn_to_username.values())

    def _is_ip_blocked(self, ip: str) -> bool:
        ip_stripped = (ip or "").strip()
        return any(ip_stripped == blocked for blocked in self._blocked_ips)

    def _is_username_blocked(self, username: str) -> bool:
        return (username or "").strip().lower() in set(self._blocked_usernames)

    def set_server_username(self, username: str) -> None:
        self._server_username = (username or "").strip()

    def _kick_blocked_connections(self) -> None:
        with self._clients_lock:
            conns = list(self._clients)
        for c in conns:
            username = self._conn_to_username.get(c, "")
            ip = self._conn_to_ip.get(c, "")
            if (username and self._is_username_blocked(username)) or (ip and self._is_ip_blocked(ip)):
                try:
                    c.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    c.close()
                except Exception:
                    pass

    def _broadcast_userlist(self) -> None:
        users = sorted(self.get_current_users())
        payload: Dict[str, object] = {
            "type": "userlist",
            "username": "System",
            "message": "User list updated",
            "users": users,
        }
        try:
            self._on_message(payload)
        except Exception:
            pass
        self._broadcast(payload)


class ChatClient:
    """TCP chat client for sending/receiving newline-delimited JSON messages."""

    def __init__(self, host: str, port: int, username: str, on_message: Callable[[Dict[str, object]], None]):
        self.host = host
        self.port = port
        self.username = username
        self._on_message = on_message

        self._socket: Optional[socket.socket] = None
        self._recv_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def connect(self) -> None:
        if self._socket is not None:
            return
        self._stop_event.clear()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((self.host, self.port))
        s.settimeout(0.5)
        self._socket = s
        self._recv_thread = threading.Thread(target=self._recv_loop, name="ChatClientRecv", daemon=True)
        self._recv_thread.start()
        # Announce join
        self._send_payload({
            "type": "join",
            "username": self.username,
            "message": f"{self.username} joined the chat",
        })

    def disconnect(self) -> None:
        self._stop_event.set()
        if self._socket is not None:
            try:
                self._socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None
        if self._recv_thread is not None and self._recv_thread.is_alive():
            self._recv_thread.join(timeout=1.5)
        self._recv_thread = None

    def send_message(self, message: str, username: Optional[str] = None) -> None:
        if self._socket is None:
            return
        payload: Dict[str, object] = {"type": "text", "username": username or self.username, "message": message}
        self._send_payload(payload)

    def send_file(self, file_path: str, username: Optional[str] = None) -> None:
        if self._socket is None:
            return
        try:
            with open(file_path, "rb") as f:
                data_bytes = f.read()
        except Exception:
            return
        filename = os.path.basename(file_path)
        filesize = len(data_bytes)
        filedata_b64 = base64.b64encode(data_bytes).decode("ascii")
        payload: Dict[str, object] = {
            "type": "file",
            "username": username or self.username,
            "message": f"sent file: {filename} ({filesize} bytes)",
            "filename": filename,
            "filesize": filesize,
            "filedata_b64": filedata_b64,
        }
        self._send_payload(payload)

    # Internal
    def _recv_loop(self) -> None:
        assert self._socket is not None
        s = self._socket
        buffer = ""
        try:
            while not self._stop_event.is_set():
                try:
                    data = s.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not data:
                    break
                try:
                    chunk = data.decode("utf-8", errors="ignore")
                except Exception:
                    continue
                buffer += chunk
                messages, buffer = _extract_json_lines_from_buffer(buffer)
                for obj in messages:
                    try:
                        self._on_message(obj)
                    except Exception:
                        pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    def _send_payload(self, payload: Dict[str, object]) -> None:
        if self._socket is None:
            return
        try:
            self._socket.sendall(_safe_json_dumps(payload))
        except Exception:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None

