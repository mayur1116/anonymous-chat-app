/**
 * server.js
 *
 * Entry point for the anonymous real-time chat backend.
 */

"use strict";

const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

const {
  registerUser,
  loginUser,
  createSession,
  getSession,
  removeSession,
  joinRoom,
  leaveRoom,
  getUsersInRoom,
  getRoomSummary,
} = require("./users");

const { encrypt, decrypt } = require("./utils/encryption");

// Import our new database controller
const {
  createRoom,
  verifyRoom,
  saveMessage,
  getRoomHistory,
} = require("./db");

const PORT = process.env.PORT || 3000;
const MAX_MESSAGE_LENGTH = 500;
const MAX_ROOM_NAME_LENGTH = 50;

const app = express();
app.use(express.json());

app.get("/", (_req, res) => {
  res.sendFile(require("path").join(__dirname, "index.html"));
});

app.get("/health", (_req, res) => {
  res.json({ status: "ok", rooms: getRoomSummary() });
});

// ── REST: Register & Login ────────────────────────────────────────────────────
app.post("/auth/register", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "username and password required." });

  const result = await registerUser(username, password);
  if (!result.success) return res.status(409).json({ error: result.error });

  return res.status(201).json({ message: `User "${username.trim()}" registered successfully.` });
});

app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "username and password required." });

  const result = await loginUser(username, password);
  if (!result.success) return res.status(401).json({ error: result.error });

  return res.json({
    message: "Login successful.",
    username: username.trim(),
    socketAuth: { username: username.trim(), password },
  });
});

// ── REST: Create Room & Verify ────────────────────────────────────────────────
app.post("/rooms/create", async (req, res) => {
  const { room, password } = req.body || {};
  if (!room || !password) return res.status(400).json({ error: "Room name and password are required." });
  if (room.trim().length > MAX_ROOM_NAME_LENGTH) return res.status(400).json({ error: `Room name must be ≤ ${MAX_ROOM_NAME_LENGTH} chars.` });

  const result = await createRoom(room.trim(), password);
  if (!result.success) return res.status(409).json({ error: result.error });
  
  return res.status(201).json({ message: "Room created successfully." });
});

app.post("/rooms/verify", async (req, res) => {
  const { room, password } = req.body || {};
  if (!room || !password) return res.status(400).json({ error: "Room name and password are required." });

  const result = await verifyRoom(room.trim(), password);
  if (!result.success) return res.status(401).json({ error: result.error });
  
  return res.json({ success: true });
});

// ─── Socket.io Setup ──────────────────────────────────────────────────────────
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*", methods: ["GET", "POST"] } });

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
  console.log(`[CONNECT]  ${socket.username} (${socket.id})`);

  socket.emit("connected", { message: `Welcome, ${socket.username}!` });

  // ── join_room ────────────────────────────────────────────────────────────
  socket.on("join_room", async (payload, ack) => {
    try {
      const roomName = (payload?.room || "").trim();
      const roomPassword = payload?.password || "";

      if (!roomName) return safeAck(ack, { error: "Room name cannot be empty." });

      // Verify password against DB before joining
      const verify = await verifyRoom(roomName, roomPassword);
      if (!verify.success) return safeAck(ack, { error: verify.error });

      const { previousRoom, newRoom } = joinRoom(socket.id, roomName);

      if (previousRoom) {
        socket.leave(previousRoom);
        io.to(previousRoom).emit("user_left", {
          username: socket.username, room: previousRoom,
          users: getUsersInRoom(previousRoom), timestamp: Date.now(),
        });
      }

      socket.join(newRoom);
      socket.to(newRoom).emit("user_joined", {
        username: socket.username, room: newRoom,
        users: getUsersInRoom(newRoom), timestamp: Date.now(),
      });

      // Fetch history and send it back in the acknowledgement
      const history = getRoomHistory(newRoom);
      console.log(`[JOIN]     ${socket.username} joined "${newRoom}"`);
      
      safeAck(ack, {
        success: true,
        room: newRoom,
        users: getUsersInRoom(newRoom),
        history, 
      });
    } catch (err) {
      safeAck(ack, { error: "Failed to join room." });
    }
  });

  // ── leave_room ───────────────────────────────────────────────────────────
  socket.on("leave_room", (payload, ack) => {
    try {
      const session = getSession(socket.id);
      if (!session?.room) return safeAck(ack, { error: "You are not in any room." });

      const leftRoom = leaveRoom(socket.id);
      socket.leave(leftRoom);

      io.to(leftRoom).emit("user_left", {
        username: socket.username, room: leftRoom,
        users: getUsersInRoom(leftRoom), timestamp: Date.now(),
      });

      safeAck(ack, { success: true, room: leftRoom });
    } catch (err) {
      safeAck(ack, { error: "Failed to leave room." });
    }
  });

  // ── send_message ─────────────────────────────────────────────────────────
  socket.on("send_message", (payload, ack) => {
    try {
      const session = getSession(socket.id);
      if (!session?.room) return safeAck(ack, { error: "Join a room first." });

      const encryptedText = payload?.message;
      if (!encryptedText) return safeAck(ack, { error: "Message is required." });

      let plaintext;
      try {
        plaintext = decrypt(encryptedText);
      } catch {
        return safeAck(ack, { error: "Decryption failed. Invalid key." });
      }

      if (!plaintext.trim()) return safeAck(ack, { error: "Message cannot be empty." });
      if (plaintext.length > MAX_MESSAGE_LENGTH) return safeAck(ack, { error: `Max ${MAX_MESSAGE_LENGTH} characters.` });

      const broadcastPayload = {
        username: session.username,
        room: session.room,
        message: encrypt(plaintext),
        timestamp: Date.now(),
      };

      // Persist to DB
      saveMessage(session.room, session.username, broadcastPayload.message, broadcastPayload.timestamp);
      io.to(session.room).emit("receive_message", broadcastPayload);

      safeAck(ack, { success: true });
    } catch (err) {
      safeAck(ack, { error: "Failed to send message." });
    }
  });

  socket.on("disconnect", (reason) => {
    const removed = removeSession(socket.id);
    if (!removed) return;
    if (removed.room) {
      io.to(removed.room).emit("user_left", {
        username: removed.username, room: removed.room,
        users: getUsersInRoom(removed.room), timestamp: Date.now(),
      });
    }
  });

  socket.on("error", (err) => console.error(`[SOCKET ERROR]`, err.message));
});

function safeAck(ack, data) {
  if (typeof ack === "function") ack(data);
}

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT} with Secure Rooms enabled.`);
});