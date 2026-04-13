/**
 * server.js
 *
 * Entry point — Express + Socket.io with multi-room, soft-delete, and typing indicators.
 */

"use strict";

const express = require("express");
const cors    = require("cors");
const http    = require("http");
const { Server } = require("socket.io");

const {
  registerUser, loginUser,
  createSession, getSession, isUserInRoom, removeSession,
  joinRoom, leaveRoom, getUsersInRoom, getRoomSummary,
} = require("./users");

// FIX: encryption.js lives at the project root, not ./utils/encryption
const { encrypt, decrypt } = require("./encryption");

const {
  createRoom, verifyRoom, saveMessage, getRoomHistory,
  getMessageById, deleteMessageForEveryone, deleteMessageForMe,
} = require("./db");

const PORT               = process.env.PORT || 3000;
const MAX_MESSAGE_LENGTH = 500;
const MAX_ROOM_NAME_LENGTH = 50;

const app = express();
app.use(cors());
app.use(express.json());

app.get("/", (_req, res) =>
  res.sendFile(require("path").join(__dirname, "index.html"))
);

app.get("/health", (_req, res) =>
  res.json({ status: "ok", rooms: getRoomSummary() })
);

// ── REST: Auth ────────────────────────────────────────────────────────────────

app.post("/auth/register", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: "username and password required." });
  const result = await registerUser(username, password);
  if (!result.success) return res.status(409).json({ error: result.error });
  return res.status(201).json({ message: `User "${username.trim()}" registered successfully.` });
});

app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: "username and password required." });
  const result = await loginUser(username, password);
  if (!result.success) return res.status(401).json({ error: result.error });
  return res.json({
    message: "Login successful.",
    username: username.trim(),
    socketAuth: { username: username.trim(), password },
  });
});

// ── REST: Rooms ───────────────────────────────────────────────────────────────

app.post("/rooms/create", async (req, res) => {
  const { room, password } = req.body || {};
  if (!room || !password)
    return res.status(400).json({ error: "Room name and password are required." });
  if (room.trim().length > MAX_ROOM_NAME_LENGTH)
    return res.status(400).json({ error: `Room name must be ≤ ${MAX_ROOM_NAME_LENGTH} chars.` });
  const result = await createRoom(room.trim(), password);
  if (!result.success) return res.status(409).json({ error: result.error });
  return res.status(201).json({ message: "Room created successfully." });
});

app.post("/rooms/verify", async (req, res) => {
  const { room, password } = req.body || {};
  if (!room || !password)
    return res.status(400).json({ error: "Room name and password are required." });
  const result = await verifyRoom(room.trim(), password);
  if (!result.success) return res.status(401).json({ error: result.error });
  return res.json({ success: true });
});

// ── Socket.io ─────────────────────────────────────────────────────────────────

const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: "*", methods: ["GET", "POST"] } });

// Auth middleware — re-validates on every new socket connection
io.use(async (socket, next) => {
  const { username, password } = socket.handshake.auth || {};
  if (!username || !password) return next(new Error("AUTH_REQUIRED"));
  const result = await loginUser(username, password);
  if (!result.success) return next(new Error(`AUTH_FAILED: ${result.error}`));
  socket.username = username.trim();
  next();
});

io.on("connection", (socket) => {
  createSession(socket.id, socket.username);
  console.log(`[CONNECT]    ${socket.username} (${socket.id})`);
  socket.emit("connected", { message: `Welcome, ${socket.username}!` });

  // ── join_room ──────────────────────────────────────────────────────────────
  // Users can join multiple rooms; previous rooms are NOT left.
  socket.on("join_room", async (payload, ack) => {
    try {
      const roomName     = (payload?.room     || "").trim();
      const roomPassword =  payload?.password || "";

      if (!roomName) return safeAck(ack, { error: "Room name cannot be empty." });

      // Already a member — just return current state + history
      if (isUserInRoom(socket.id, roomName)) {
        return safeAck(ack, {
          success : true,
          room    : roomName,
          users   : getUsersInRoom(roomName),
          history : getRoomHistory(roomName),
        });
      }

      const verify = await verifyRoom(roomName, roomPassword);
      if (!verify.success) return safeAck(ack, { error: verify.error });

      joinRoom(socket.id, roomName);
      socket.join(roomName);

      socket.to(roomName).emit("user_joined", {
        username : socket.username,
        room     : roomName,
        users    : getUsersInRoom(roomName),
        timestamp: Date.now(),
      });

      console.log(`[JOIN]       ${socket.username} → "${roomName}"`);

      safeAck(ack, {
        success : true,
        room    : roomName,
        users   : getUsersInRoom(roomName),
        history : getRoomHistory(roomName),
      });
    } catch (err) {
      console.error("[join_room]", err.message);
      safeAck(ack, { error: "Failed to join room." });
    }
  });

  // ── leave_room ─────────────────────────────────────────────────────────────
  // Payload must now include the room name (multi-room support).
  socket.on("leave_room", (payload, ack) => {
    try {
      const roomName = (payload?.room || "").trim();
      if (!roomName)                          return safeAck(ack, { error: "Room name required." });
      if (!isUserInRoom(socket.id, roomName)) return safeAck(ack, { error: "Not in that room." });

      leaveRoom(socket.id, roomName);
      socket.leave(roomName);

      io.to(roomName).emit("user_left", {
        username : socket.username,
        room     : roomName,
        users    : getUsersInRoom(roomName),
        timestamp: Date.now(),
      });

      console.log(`[LEAVE]      ${socket.username} ← "${roomName}"`);
      safeAck(ack, { success: true, room: roomName });
    } catch (err) {
      safeAck(ack, { error: "Failed to leave room." });
    }
  });

  // ── send_message ───────────────────────────────────────────────────────────
  // Payload now requires `room` so the server knows which room to broadcast to.
  socket.on("send_message", (payload, ack) => {
    try {
      const roomName     = (payload?.room    || "").trim();
      const encryptedText =  payload?.message;

      if (!roomName)                          return safeAck(ack, { error: "Room name required." });
      if (!isUserInRoom(socket.id, roomName)) return safeAck(ack, { error: "Join the room first." });
      if (!encryptedText)                     return safeAck(ack, { error: "Message is required." });

      let plaintext;
      try { plaintext = decrypt(encryptedText); }
      catch { return safeAck(ack, { error: "Decryption failed — invalid key." }); }

      if (!plaintext.trim())                    return safeAck(ack, { error: "Message cannot be empty." });
      if (plaintext.length > MAX_MESSAGE_LENGTH) return safeAck(ack, { error: `Max ${MAX_MESSAGE_LENGTH} characters.` });

      const session   = getSession(socket.id);
      const timestamp = Date.now();
      const encrypted = encrypt(plaintext);
      const msgId     = saveMessage(roomName, session.username, encrypted, timestamp);

      io.to(roomName).emit("receive_message", {
        id        : msgId,
        username  : session.username,
        room      : roomName,
        message   : encrypted,
        timestamp,
        isDeleted : 0,
        deletedFor: "[]",
      });

      safeAck(ack, { success: true });
    } catch (err) {
      console.error("[send_message]", err.message);
      safeAck(ack, { error: "Failed to send message." });
    }
  });

  // ── delete_message ─────────────────────────────────────────────────────────
  // type = 'me'       → soft-delete for requesting user only (no broadcast)
  // type = 'everyone' → soft-delete globally, broadcasts message_deleted to room
  socket.on("delete_message", (payload, ack) => {
    try {
      const { id, room: roomName, type } = payload || {};
      if (!id || !roomName) return safeAck(ack, { error: "Message ID and room required." });
      if (!isUserInRoom(socket.id, roomName)) return safeAck(ack, { error: "Not in that room." });

      const msg = getMessageById(id);
      if (!msg)                  return safeAck(ack, { error: "Message not found." });
      if (msg.room !== roomName) return safeAck(ack, { error: "Message not in this room." });
      if (msg.isDeleted)         return safeAck(ack, { error: "Message already deleted for everyone." });

      const session = getSession(socket.id);

      if (type === "everyone") {
        if (msg.username !== session.username)
          return safeAck(ack, { error: "You can only delete your own messages for everyone." });
        deleteMessageForEveryone(id);
        io.to(roomName).emit("message_deleted", { id: Number(id), room: roomName });
      } else {
        // delete for me — no broadcast needed
        deleteMessageForMe(id, session.username);
      }

      safeAck(ack, { success: true });
    } catch (err) {
      console.error("[delete_message]", err.message);
      safeAck(ack, { error: "Failed to delete message." });
    }
  });

  // ── typing ─────────────────────────────────────────────────────────────────
  // Broadcasts to everyone in the room EXCEPT the sender.
  socket.on("typing", ({ room: roomName, isTyping }) => {
    if (!roomName || !isUserInRoom(socket.id, roomName)) return;
    socket.to(roomName).emit("typing", {
      username : socket.username,
      room     : roomName,
      isTyping : !!isTyping,
    });
  });

  // ── disconnect ─────────────────────────────────────────────────────────────
  socket.on("disconnect", () => {
    const removed = removeSession(socket.id);
    if (!removed) return;
    for (const room of removed.rooms) {
      io.to(room).emit("user_left", {
        username : removed.username,
        room,
        users    : getUsersInRoom(room),
        timestamp: Date.now(),
      });
    }
    console.log(`[DISCONNECT] ${removed.username} (${socket.id})`);
  });

  socket.on("error", (err) => console.error("[SOCKET ERROR]", err.message));
});

function safeAck(ack, data) {
  if (typeof ack === "function") ack(data);
}

server.listen(PORT, () => {
  console.log(`✓ Server on port ${PORT}  [multi-room | soft-delete | typing]`);
});