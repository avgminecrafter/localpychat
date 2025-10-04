## Local LAN Chat (Tkinter + JSON)

A simple local-network chat application with a Tkinter UI. Supports two modes:

- Listener: acts as a TCP server so others can connect to you
- Connect: acts as a TCP client connecting to a listener

Messages are newline-delimited JSON objects. Base schema remains:

```json
{
  "username": "(username)",
  "message": "(message itself)"
}
```

Extended fields:

- `type` (string): one of `text`, `join`, `leave`, `file` (default: `text`)
- `userlist` messages are broadcast by the server whenever users join/leave:
  ```json
  {
    "type": "userlist",
    "username": "System",
    "message": "User list updated",
    "users": ["alice", "bob"]
  }
  ```
- For `type: "file"` messages, additional fields are included:
  - `filename` (string)
  - `filesize` (integer, bytes)
  - `filedata_b64` (base64 encoded file contents)

### New features

- Auto-reconnect: the client automatically reconnects with backoff when enabled.
- LAN discovery: discover running listeners on the local network via UDP broadcast.
- Message filters: listener can drop messages containing configured substrings.
- UI improvements:
  - Menu bar with File and View menus
  - Theme chooser (ttk themes)
  - Optional timestamps and sound notifications
  - Status bar for connection status
  - Save/Clear chat log

### Requirements

- Python 3.8+

### Run

```bash
python3 app.py
```

### Usage

1. Enter a username.
2. Choose a mode:
   - Listener: set host (e.g., 0.0.0.0 or your LAN IP) and port, then Start Listening.
   - Connect: set the listener's host/IP and port, then Connect.
3. Type your message and press Enter or click Send.
4. To send a file, click "Send File" and choose a file. Receivers will save it to `~/Downloads`.
5. In Listener mode, use the Admin section to:
   - Apply message filters (comma-separated) to drop messages containing those substrings.
   - Block usernames or IPs for this session.
   - View current connected users.

Additional tips:

- Use the "Discover" button to find listeners on your LAN; pick one to auto-fill host/port.
- Enable "Auto-Reconnect" before connecting to retry on transient network loss.
- Toggle timestamps and sound notifications from the View menu.

Tips:
- On the listener, using host `0.0.0.0` listens on all interfaces. Share your LAN IP with others.
- Firewall rules may need to allow inbound/outbound traffic on the selected port.

### Notes

- The server broadcasts each message to all connected clients.
- Clients send a `join` message when connecting; the server emits a `leave` message when a client disconnects.
- File contents are sent inline as base64; for large files, consider size limits.
- The UI thread polls a queue to remain responsive.
- Newline-delimited JSON allows robust parsing across TCP frames.
 - UDP discovery uses broadcast on port 54545; some networks may block broadcast.


