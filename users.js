/**
 * users.js
 *
 * In-memory user registry and session management.
 *
 * KEY CHANGE: sessions now track a *Set* of rooms instead of a single room,
 * enabling multi-room membership per socket.
 */

const bcrypt = require("bcryptjs");

const SALT_ROUNDS = 10;

// { [username]: hashedPassword }
const accounts = {};

// { [socketId]: { username: string, rooms: Set<string> } }
const sessions = {};

// { [roomName]: Set<username> }
const rooms = {};

// ── Account operations ────────────────────────────────────────────────────────

async function registerUser(username, password) {
  const name = username.trim();
  if (!name)                      return { success: false, error: "Username cannot be empty." };
  if (!password || password.length < 3)
                                  return { success: false, error: "Password must be at least 3 characters." };
  if (accounts[name])             return { success: false, error: `Username "${name}" is already taken.` };
  accounts[name] = await bcrypt.hash(password, SALT_ROUNDS);
  return { success: true };
}

async function loginUser(username, password) {
  const name = username ? username.trim() : "";
  if (!name)            return { success: false, error: "Username cannot be empty." };
  if (!accounts[name])  return { success: false, error: "Invalid username or password." };
  const match = await bcrypt.compare(password, accounts[name]);
  if (!match)           return { success: false, error: "Invalid username or password." };
  return { success: true };
}

// ── Session operations ────────────────────────────────────────────────────────

function createSession(socketId, username) {
  sessions[socketId] = { username, rooms: new Set() };
}

function getSession(socketId) {
  return sessions[socketId];
}

/**
 * Returns true if the socket is currently a member of roomName.
 */
function isUserInRoom(socketId, roomName) {
  return sessions[socketId]?.rooms?.has(roomName) ?? false;
}

/**
 * Removes a session and cleans up all its room memberships.
 * @returns {{ username, rooms: string[] } | null}
 */
function removeSession(socketId) {
  const session = sessions[socketId];
  if (!session) return null;

  const leftRooms = [...session.rooms];
  for (const room of leftRooms) leaveRoom(socketId, room);

  delete sessions[socketId];
  return { username: session.username, rooms: leftRooms };
}

// ── Room operations ───────────────────────────────────────────────────────────

/**
 * Adds a user to a room WITHOUT removing them from any existing rooms.
 */
function joinRoom(socketId, roomName) {
  const session = sessions[socketId];
  if (!session) throw new Error("No session found for socket.");

  if (!rooms[roomName]) rooms[roomName] = new Set();
  rooms[roomName].add(session.username);
  session.rooms.add(roomName);

  return { newRoom: roomName };
}

/**
 * Removes a user from a specific named room.
 * @param {string} socketId
 * @param {string} roomName  Must be provided explicitly.
 * @returns {string|null}  The room name, or null if they weren't in it.
 */
function leaveRoom(socketId, roomName) {
  const session = sessions[socketId];
  if (!session || !roomName || !session.rooms.has(roomName)) return null;

  session.rooms.delete(roomName);

  if (rooms[roomName]) {
    rooms[roomName].delete(session.username);
    if (rooms[roomName].size === 0) delete rooms[roomName];
  }

  return roomName;
}

function getUsersInRoom(roomName) {
  return rooms[roomName] ? [...rooms[roomName]] : [];
}

function getRoomSummary() {
  const summary = {};
  for (const [room, members] of Object.entries(rooms)) summary[room] = members.size;
  return summary;
}

module.exports = {
  registerUser,
  loginUser,
  createSession,
  getSession,
  isUserInRoom,
  removeSession,
  joinRoom,
  leaveRoom,
  getUsersInRoom,
  getRoomSummary,
};