/**
 * users.js
 *
 * In-memory user registry and session management.
 *
 * Responsibilities:
 *   - Store registered accounts (username → hashed password)
 *   - Track active socket sessions (socketId → user object)
 *   - Track which users are in each room (room → Set<username>)
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

// ─── Account Operations ───────────────────────────────────────────────────────

/**
 * Registers a new user account.
 * @param {string} username
 * @param {string} password  Plaintext password — will be hashed.
 * @returns {{ success: boolean, error?: string }}
 */
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

/**
 * Validates login credentials.
 * @param {string} username
 * @param {string} password  Plaintext password to check.
 * @returns {{ success: boolean, error?: string }}
 */
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

/**
 * Creates a session for a connected socket.
 * @param {string} socketId
 * @param {string} username
 */
function createSession(socketId, username) {
  sessions[socketId] = { username, room: null };
}

/**
 * Retrieves the session object for a socket.
 * @param {string} socketId
 * @returns {{ username: string, room: string|null } | undefined}
 */
function getSession(socketId) {
  return sessions[socketId];
}

/**
 * Removes a session on disconnect and cleans up room membership.
 * @param {string} socketId
 * @returns {{ username: string, room: string|null } | null}  The removed session.
 */
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
 * Adds a user to a room, removing them from any previous room first.
 * @param {string} socketId
 * @param {string} roomName
 * @returns {{ previousRoom: string|null, newRoom: string }}
 */
function joinRoom(socketId, roomName) {
  const session = sessions[socketId];
  if (!session) throw new Error("No session found for socket.");

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

/**
 * Removes a user from their current room.
 * @param {string} socketId
 * @returns {string|null}  The room they were removed from.
 */
function leaveRoom(socketId) {
  const session = sessions[socketId];
  if (!session || !session.room) return null;

  const roomName = session.room;
  if (rooms[roomName]) {
    rooms[roomName].delete(session.username);
    if (rooms[roomName].size === 0) {
      delete rooms[roomName]; // Garbage-collect empty rooms
    }
  }

  session.room = null;
  return roomName;
}

/**
 * Returns a list of usernames in a given room.
 * @param {string} roomName
 * @returns {string[]}
 */
function getUsersInRoom(roomName) {
  return rooms[roomName] ? [...rooms[roomName]] : [];
}

/**
 * Returns a snapshot of all active rooms and their member counts.
 * @returns {{ [roomName]: number }}
 */
function getRoomSummary() {
  const summary = {};
  for (const [room, members] of Object.entries(rooms)) {
    summary[room] = members.size;
  }
  return summary;
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
};
