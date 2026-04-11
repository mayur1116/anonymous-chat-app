/**
 * users.js
 *
 * In-memory user registry and session management.
 */

const bcrypt = require("bcryptjs");

const SALT_ROUNDS = 10;

// ─── Registered Accounts ────────────────────────────────────────────────────
// { [username]: hashedPassword }
const accounts = {};

// ─── Active Sessions ─────────────────────────────────────────────────────────
// { [socketId]: { username, room } }
const sessions = {};

// ─── Room Membership ─────────────────────────────────────────────────────────
// { [roomName]: Set<username> }
const rooms = {};

// ─── Room Passwords & History ────────────────────────────────────────────────
// { [roomName]: hashedPassword }
const roomPasswords = {};

// { [roomName]: Array<{username, room, message, timestamp}> }
const roomMessages = {};

// ─── Account Operations ───────────────────────────────────────────────────────

async function registerUser(username, password) {
  const name = username.trim();

  if (!name) {
    return { success: false, error: "Username cannot be empty." };
  }
  if (!password || password.length < 3) {
    return { success: false, error: "Password must be at least 3 characters." };
  }
  if (accounts[name]) {
    return { success: false, error: `Username "${name}" is already taken.` };
  }

  accounts[name] = await bcrypt.hash(password, SALT_ROUNDS);
  return { success: true };
}

async function loginUser(username, password) {
  const name = username ? username.trim() : "";

  if (!name) {
    return { success: false, error: "Username cannot be empty." };
  }
  if (!accounts[name]) {
    return { success: false, error: "Invalid username or password." };
  }

  const match = await bcrypt.compare(password, accounts[name]);
  if (!match) {
    return { success: false, error: "Invalid username or password." };
  }

  return { success: true };
}

// ─── Session Operations ───────────────────────────────────────────────────────

function createSession(socketId, username) {
  sessions[socketId] = { username, room: null };
}

function getSession(socketId) {
  return sessions[socketId];
}

function removeSession(socketId) {
  const session = sessions[socketId];
  if (!session) return null;

  if (session.room) {
    leaveRoom(socketId);
  }

  delete sessions[socketId];
  return session;
}

// ─── Room Operations ──────────────────────────────────────────────────────────

/**
 * Adds a user to a room, checking/setting the password.
 */
async function joinRoom(socketId, roomName, password = "") {
  const session = sessions[socketId];
  if (!session) throw new Error("No session found for socket.");

  // Password Protection Logic
  if (roomPasswords[roomName]) {
    // Room exists: verify password
    const match = await bcrypt.compare(password, roomPasswords[roomName]);
    if (!match) throw new Error("Incorrect room password.");
  } else {
    // New room: set password
    if (!password) throw new Error("A password is required to create a new room.");
    roomPasswords[roomName] = await bcrypt.hash(password, SALT_ROUNDS);
    roomMessages[roomName] = []; // Initialize history
  }

  const previousRoom = session.room;

  // Leave current room if already in one
  if (previousRoom && previousRoom !== roomName) {
    leaveRoom(socketId);
  }

  // Add to new room
  if (!rooms[roomName]) {
    rooms[roomName] = new Set();
  }
  rooms[roomName].add(session.username);
  session.room = roomName;

  return { previousRoom, newRoom: roomName };
}

function leaveRoom(socketId) {
  const session = sessions[socketId];
  if (!session || !session.room) return null;

  const roomName = session.room;
  if (rooms[roomName]) {
    rooms[roomName].delete(session.username);
    if (rooms[roomName].size === 0) {
      delete rooms[roomName]; // Garbage-collect empty rooms
      // Note: We do NOT delete roomPasswords or roomMessages here so history persists even if empty
    }
  }

  session.room = null;
  return roomName;
}

function getUsersInRoom(roomName) {
  return rooms[roomName] ? [...rooms[roomName]] : [];
}

function getRoomSummary() {
  const summary = {};
  for (const [room, members] of Object.entries(rooms)) {
    summary[room] = members.size;
  }
  return summary;
}

// ─── Message History Operations ───────────────────────────────────────────────

/**
 * Saves a message to the room's history (capped at 200 messages).
 */
function saveMessage(roomName, messageObj) {
  if (!roomMessages[roomName]) roomMessages[roomName] = [];
  roomMessages[roomName].push(messageObj);
  
  if (roomMessages[roomName].length > 200) {
    roomMessages[roomName].shift();
  }
}

/**
 * Retrieves the message history for a room.
 */
function getMessages(roomName) {
  return roomMessages[roomName] || [];
}

module.exports = {
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
};