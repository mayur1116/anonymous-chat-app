/**
 * server.js
 *
 * Entry point for the anonymous real-time chat backend.
 */

"use strict";

const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");

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
  saveMessage,
  getMessages,
} = require("./users");

const { encrypt, decrypt } = require("./utils/encryption");

const PORT = process.env.PORT || 3000;
const MAX_MESSAGE_LENGTH = 500;
const MAX_ROOM_NAME_LENGTH = 50;

const app = express();
app.use(cors());
app.use(express.json());

app.get("/health", (_req, res) => {
  res.json({ status: "ok", rooms: getRoomSummary() });
});

app.post("/auth/register", async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: "username and password are required." });
  }

  const result = await registerUser(username, password);
  if (!result.success) {
    return res.status(409).json({ error: result.error });
  }

  return res.status(201).json({ message: `User "${username.trim()}" registered successfully.` });
});

app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: "username and password are required." });
  }

  const result = await loginUser(username, password);
  if (!result.success) {
    return res.status(401).json({ error: result.error });
  }

  return res.json({
    message: "Login successful.",
    username: username.trim(),
    socketAuth: { username: username.trim(), password },
  });
});

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*", 
    methods: ["GET", "POST"],
  },
});

io.use(async (socket, next) => {
  const { username, password } = socket.handshake.auth || {};

  if (!username || !password) {
    return next(new Error("AUTH_REQUIRED: Provide username and password in socket auth."));
  }

  const result = await loginUser(username, password);
  if (!result.success) {
    return next(new Error(`AUTH_FAILED: ${result.error}`));
  }

  socket.username = username.trim();
  next();
});

io.on("connection", (socket) => {
  createSession(socket.id, socket.username);
  console.log(`[CONNECT]  ${socket.username} (${socket.id})`);

  socket.emit("connected", {
    message: `Welcome, ${socket.username}! Join a room to start chatting.`,
  });

  // ── join_room ────────────────────────────────────────────────────────────
  socket.on("join_room", async (payload, ack) => {
    try {
      const roomName = (payload?.room || "").trim();
      const password = payload?.password || "";

      if (!roomName) {
        return safeAck(ack, { error: "Room name cannot be empty." });
      }
      if (roomName.length > MAX_ROOM_NAME_LENGTH) {
        return safeAck(ack, { error: `Room name must be ≤ ${MAX_ROOM_NAME_LENGTH} characters.` });
      }

      const { previousRoom, newRoom } = await joinRoom(socket.id, roomName, password);

      if (previousRoom) {
        socket.leave(previousRoom);
        io.to(previousRoom).emit("user_left", {
          username: socket.username,
          room: previousRoom,
          users: getUsersInRoom(previousRoom),
          timestamp: Date.now(),
        });
        console.log(`[LEAVE]    ${socket.username} left "${previousRoom}"`);
      }

      socket.join(newRoom);

      socket.to(newRoom).emit("user_joined", {
        username: socket.username,
        room: newRoom,
        users: getUsersInRoom(newRoom),
        timestamp: Date.now(),
      });

      console.log(`[JOIN]     ${socket.username} joined "${newRoom}"`);
      
      const history = getMessages(newRoom);

      safeAck(ack, {
        success: true,
        room: newRoom,
        users: getUsersInRoom(newRoom),
        history 
      });
    } catch (err) {
      console.error("[join_room error]", err.message);
      safeAck(ack, { error: err.message || "Failed to join room." });
    }
  });

  // ── leave_room ───────────────────────────────────────────────────────────
  socket.on("leave_room", (payload, ack) => {
    try {
      const session = getSession(socket.id);
      if (!session?.room) {
        return safeAck(ack, { error: "You are not in any room." });
      }

      const leftRoom = leaveRoom(socket.id);
      socket.leave(leftRoom);

      io.to(leftRoom).emit("user_left", {
        username: socket.username,
        room: leftRoom,
        users: getUsersInRoom(leftRoom),
        timestamp: Date.now(),
      });

      console.log(`[LEAVE]    ${socket.username} left "${leftRoom}"`);
      safeAck(ack, { success: true, room: leftRoom });
    } catch (err) {
      console.error("[leave_room error]", err.message);
      safeAck(ack, { error: "Failed to leave room." });
    }
  });

  // ── send_message ─────────────────────────────────────────────────────────
  socket.on("send_message", (payload, ack) => {
    try {
      const session = getSession(socket.id);

      if (!session?.room) {
        return safeAck(ack, { error: "Join a room before sending messages." });
      }

      const encryptedText = payload?.message;
      if (!encryptedText || typeof encryptedText !== "string") {
        return safeAck(ack, { error: "message field is required." });
      }

      let plaintext;
      try {
        plaintext = decrypt(encryptedText);
      } catch {
        return safeAck(ack, { error: "Message decryption failed. Use the correct encryption key." });
      }

      if (!plaintext.trim()) {
        return safeAck(ack, { error: "Message cannot be empty." });
      }
      if (plaintext.length > MAX_MESSAGE_LENGTH) {
        return safeAck(ack, {
          error: `Message exceeds the ${MAX_MESSAGE_LENGTH}-character limit.`,
        });
      }

      const broadcastPayload = {
        username: session.username,
        room: session.room,
        message: encrypt(plaintext), 
        timestamp: Date.now(),
      };

      saveMessage(session.room, broadcastPayload); 

      io.to(session.room).emit("receive_message", broadcastPayload);

      console.log(
        `[MESSAGE]  ${session.username} → "${session.room}" (${plaintext.length} chars)`
      );
      safeAck(ack, { success: true });
    } catch (err) {
      console.error("[send_message error]", err.message);
      safeAck(ack, { error: "Failed to send message." });
    }
  });

  socket.on("disconnect", (reason) => {
    const removed = removeSession(socket.id);
    if (!removed) return;

    if (removed.room) {
      io.to(removed.room).emit("user_left", {
        username: removed.username,
        room: removed.room,
        users: getUsersInRoom(removed.room),
        timestamp: Date.now(),
      });
    }

    console.log(`[DISCONNECT] ${removed.username} (${socket.id}) — ${reason}`);
  });

  socket.on("error", (err) => {
    console.error(`[SOCKET ERROR] ${socket.username}:`, err.message);
  });
});

function safeAck(ack, data) {
  if (typeof ack === "function") ack(data);
}

process.on("uncaughtException", (err) => {
  console.error("[UNCAUGHT EXCEPTION]", err);
});

process.on("unhandledRejection", (reason) => {
  console.error("[UNHANDLED REJECTION]", reason);
});

server.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════╗
║       Anon Chat Server — Running         ║
╠══════════════════════════════════════════╣
║  Port : ${PORT}                               ║
║  REST : POST /auth/register              ║
║        POST /auth/login                  ║
║        GET  /health                      ║
╚══════════════════════════════════════════╝
  `);
});

module.exports = { app, server, io };