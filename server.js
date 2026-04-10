/**
 * server.js
 *
 * Entry point for the anonymous real-time chat backend.
 *
 * Stack : Express + Socket.io + bcryptjs + crypto-js
 * Auth  : Username/password, validated before socket upgrade
 * Rooms : Users must join a room before messaging
 * Crypto: AES encryption on every message payload
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
} = require("./users");

const { encrypt, decrypt } = require("./utils/encryption");

// ─── Constants ────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
const MAX_MESSAGE_LENGTH = 500;
const MAX_ROOM_NAME_LENGTH = 50;

// ─── Express Setup ────────────────────────────────────────────────────────────

const app = express();
app.use(cors());
app.use(express.json());

// Health check
app.get("/health", (_req, res) => {
  res.json({ status: "ok", rooms: getRoomSummary() });
});

// ── REST: Register ────────────────────────────────────────────────────────────
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

// ── REST: Login ───────────────────────────────────────────────────────────────
// Returns a lightweight credential token the client re-sends during socket
// handshake (auth object). Because there is no JWT, we echo back the
// plaintext credentials so the socket middleware can re-verify them.
// In production you would issue a signed token here.
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
    // Clients include these in the Socket.io auth handshake
    socketAuth: { username: username.trim(), password },
  });
});

// ─── HTTP + Socket.io Server ──────────────────────────────────────────────────

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*", // Tighten in production
    methods: ["GET", "POST"],
  },
});

// ─── Socket.io Middleware: Authentication ─────────────────────────────────────

io.use(async (socket, next) => {
  const { username, password } = socket.handshake.auth || {};

  if (!username || !password) {
    return next(new Error("AUTH_REQUIRED: Provide username and password in socket auth."));
  }

  const result = await loginUser(username, password);
  if (!result.success) {
    return next(new Error(`AUTH_FAILED: ${result.error}`));
  }

  // Attach validated username to socket for downstream handlers
  socket.username = username.trim();
  next();
});

// ─── Socket.io Event Handlers ─────────────────────────────────────────────────

io.on("connection", (socket) => {
  createSession(socket.id, socket.username);
  console.log(`[CONNECT]  ${socket.username} (${socket.id})`);

  // Notify the client their connection was accepted
  socket.emit("connected", {
    message: `Welcome, ${socket.username}! Join a room to start chatting.`,
  });

  // ── join_room ────────────────────────────────────────────────────────────
  socket.on("join_room", (payload, ack) => {
    try {
      const roomName = (payload?.room || "").trim();

      if (!roomName) {
        return safeAck(ack, { error: "Room name cannot be empty." });
      }
      if (roomName.length > MAX_ROOM_NAME_LENGTH) {
        return safeAck(ack, { error: `Room name must be ≤ ${MAX_ROOM_NAME_LENGTH} characters.` });
      }

      const { previousRoom, newRoom } = joinRoom(socket.id, roomName);

      // Leave the Socket.io room for the old room
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

      // Join the Socket.io room
      socket.join(newRoom);

      // Broadcast to others in the room
      socket.to(newRoom).emit("user_joined", {
        username: socket.username,
        room: newRoom,
        users: getUsersInRoom(newRoom),
        timestamp: Date.now(),
      });

      console.log(`[JOIN]     ${socket.username} joined "${newRoom}"`);
      safeAck(ack, {
        success: true,
        room: newRoom,
        users: getUsersInRoom(newRoom),
      });
    } catch (err) {
      console.error("[join_room error]", err.message);
      safeAck(ack, { error: "Failed to join room." });
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

      // Guard: must be in a room
      if (!session?.room) {
        return safeAck(ack, { error: "Join a room before sending messages." });
      }

      // The client sends an already-encrypted message; we validate the
      // decrypted form server-side before re-broadcasting.
      const encryptedText = payload?.message;
      if (!encryptedText || typeof encryptedText !== "string") {
        return safeAck(ack, { error: "message field is required." });
      }

      // Decrypt to validate (not stored or logged)
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

      // Re-encrypt for broadcast (same ciphertext is fine; the key is shared)
      const broadcastPayload = {
        username: session.username,
        room: session.room,
        message: encrypt(plaintext), // fresh encryption
        timestamp: Date.now(),
      };

      // Broadcast to everyone in the room including sender
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

  // ── disconnect ───────────────────────────────────────────────────────────
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

  // ── error guard ──────────────────────────────────────────────────────────
  socket.on("error", (err) => {
    console.error(`[SOCKET ERROR] ${socket.username}:`, err.message);
  });
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Safely calls an acknowledgement callback if the client provided one.
 * Prevents crashes when clients don't pass ack functions.
 */
function safeAck(ack, data) {
  if (typeof ack === "function") ack(data);
}

// ─── Global Error Guards ──────────────────────────────────────────────────────

process.on("uncaughtException", (err) => {
  console.error("[UNCAUGHT EXCEPTION]", err);
});

process.on("unhandledRejection", (reason) => {
  console.error("[UNHANDLED REJECTION]", reason);
});

// ─── Start Server ─────────────────────────────────────────────────────────────

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

module.exports = { app, server, io }; // Exported for testing
