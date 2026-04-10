# Anon Chat — Backend

A real-time anonymous chat backend built with **Node.js**, **Express**, and **Socket.io**.
Messages are AES-encrypted in transit. Users are stored in memory — no database required.

---

## 📁 Folder Structure

```
anon-chat-backend/
├── server.js               # Entry point — Express + Socket.io setup
├── users.js                # In-memory user registry & session management
├── utils/
│   └── encryption.js       # AES encrypt / decrypt helpers (crypto-js)
├── package.json
└── README.md
```

---

## ⚡ Quick Start

### 1. Install dependencies

```bash
cd anon-chat-backend
npm install
```

### 2. Start the server

```bash
npm start
```

Or with live-reload during development:

```bash
npm run dev
```

Server starts on **http://localhost:3000** by default.
Set a custom port with the `PORT` environment variable:

```bash
PORT=8080 npm start
```

---

## 🔐 Authentication Flow

Authentication is two-step: REST first, then Socket.

### Step 1 — Register (once)

```http
POST /auth/register
Content-Type: application/json

{ "username": "alice", "password": "secret123" }
```

Response `201`:
```json
{ "message": "User \"alice\" registered successfully." }
```

### Step 2 — Login

```http
POST /auth/login
Content-Type: application/json

{ "username": "alice", "password": "secret123" }
```

Response `200`:
```json
{
  "message": "Login successful.",
  "username": "alice",
  "socketAuth": { "username": "alice", "password": "secret123" }
}
```

### Step 3 — Connect to Socket

Pass `socketAuth` in the Socket.io handshake:

```js
const socket = io("http://localhost:3000", {
  auth: { username: "alice", password: "secret123" }
});
```

The server re-validates credentials on every socket connection — no session cookies or tokens.

---

## 📡 Socket.io Events

### Client → Server

| Event          | Payload                         | Description                         |
|----------------|---------------------------------|-------------------------------------|
| `join_room`    | `{ room: "general" }`           | Join (or switch to) a chat room     |
| `leave_room`   | *(none)*                        | Leave the current room              |
| `send_message` | `{ message: "<ciphertext>" }`   | Send an AES-encrypted message       |

All events accept an optional acknowledgement callback:

```js
socket.emit("join_room", { room: "general" }, (ack) => {
  console.log(ack); // { success: true, room: "general", users: ["alice"] }
                    // or { error: "..." }
});
```

### Server → Client

| Event            | Payload                                              | Description                         |
|------------------|------------------------------------------------------|-------------------------------------|
| `connected`      | `{ message }`                                        | Fired once on successful connect    |
| `user_joined`    | `{ username, room, users, timestamp }`               | A new user entered the room         |
| `user_left`      | `{ username, room, users, timestamp }`               | A user left or disconnected         |
| `receive_message`| `{ username, room, message (ciphertext), timestamp }`| Encrypted message broadcast         |

---

## 🔒 Message Encryption

Encrypt before sending, decrypt after receiving. Use **the same shared key** on the client.

```js
const CryptoJS = require("crypto-js");
const SECRET_KEY = "anon-chat-super-secret-key-2024"; // Must match server

// Send
const ciphertext = CryptoJS.AES.encrypt("Hello!", SECRET_KEY).toString();
socket.emit("send_message", { message: ciphertext });

// Receive
socket.on("receive_message", ({ message, username }) => {
  const bytes = CryptoJS.AES.decrypt(message, SECRET_KEY);
  const plaintext = bytes.toString(CryptoJS.enc.Utf8);
  console.log(`${username}: ${plaintext}`);
});
```

Override the key via environment variable (recommended for production):

```bash
CHAT_SECRET="my-production-key" npm start
```

---

## 🩺 Health Check

```http
GET /health
```

```json
{ "status": "ok", "rooms": { "general": 3, "dev": 1 } }
```

---

## ✅ Validation Rules

| Rule                             | Behaviour                          |
|----------------------------------|------------------------------------|
| Empty username                   | Rejected at register & login       |
| Duplicate username               | `409` error on register            |
| Wrong password                   | `401` error on login / socket kick |
| Message not encrypted correctly  | Error ack, not broadcast           |
| Empty message (after decrypt)    | Error ack, not broadcast           |
| Message > 500 characters         | Error ack, not broadcast           |
| Sending without joining a room   | Error ack, not broadcast           |
| Room name > 50 characters        | Error ack on join                  |

---

## 🧩 Architecture Notes

- **No database** — all state is in-memory; restarting the server clears all users and rooms.
- **No JWT** — credentials are re-validated on each socket handshake via `bcryptjs`.
- **Separation of concerns** — `users.js` owns all state; `encryption.js` owns all crypto; `server.js` owns only transport and event wiring.
- **Graceful cleanup** — disconnecting users are removed from their room and a `user_left` event is broadcast automatically.
