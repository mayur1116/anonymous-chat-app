/**
 * db.js
 *
 * SQLite database — rooms, message history, soft-delete.
 */

const Database = require("better-sqlite3");
const bcrypt   = require("bcryptjs");
const path     = require("path");

const db = new Database(path.join(__dirname, "chat.db"));
db.pragma("journal_mode = WAL");

// ── Schema ────────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS rooms (
    name     TEXT PRIMARY KEY,
    password TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    room       TEXT    NOT NULL,
    username   TEXT    NOT NULL,
    message    TEXT    NOT NULL,
    timestamp  INTEGER NOT NULL,
    isDeleted  INTEGER DEFAULT 0,
    deletedFor TEXT    DEFAULT '[]',
    FOREIGN KEY (room) REFERENCES rooms(name) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_messages_room_ts
    ON messages (room, timestamp ASC);
`);

// ── Safe migrations for existing databases ────────────────────────────────────
for (const sql of [
  "ALTER TABLE messages ADD COLUMN isDeleted  INTEGER DEFAULT 0",
  "ALTER TABLE messages ADD COLUMN deletedFor TEXT    DEFAULT '[]'",
]) {
  try { db.exec(sql); } catch (_) { /* column already exists */ }
}

// ── Room helpers ──────────────────────────────────────────────────────────────

/**
 * Creates a new room with a bcrypt-hashed password.
 */
async function createRoom(room, password) {
  try {
    const existing = db.prepare("SELECT name FROM rooms WHERE name = ?").get(room);
    if (existing) return { success: false, error: `Room "${room}" already exists.` };
    const hash = await bcrypt.hash(password, 10);
    db.prepare("INSERT INTO rooms (name, password) VALUES (?, ?)").run(room, hash);
    return { success: true };
  } catch (err) {
    console.error("[DB ERROR] createRoom:", err.message);
    return { success: false, error: "Database error during room creation." };
  }
}

/**
 * Verifies a plaintext password against the stored hash.
 */
async function verifyRoom(room, password) {
  try {
    const row = db.prepare("SELECT password FROM rooms WHERE name = ?").get(room);
    if (!row) return { success: false, error: "Room not found. Please create it first." };
    const match = await bcrypt.compare(password, row.password);
    if (!match) return { success: false, error: "Incorrect room password." };
    return { success: true };
  } catch (err) {
    console.error("[DB ERROR] verifyRoom:", err.message);
    return { success: false, error: "Database error during verification." };
  }
}

// ── Message helpers ───────────────────────────────────────────────────────────

/**
 * Persists an encrypted message.
 * @returns {number|null}  The inserted row ID, or null on failure.
 */
function saveMessage(room, username, message, timestamp) {
  try {
    const result = db
      .prepare("INSERT INTO messages (room, username, message, timestamp) VALUES (?, ?, ?, ?)")
      .run(room, username, message, timestamp);
    return result.lastInsertRowid;
  } catch (err) {
    console.error("[DB ERROR] saveMessage:", err.message);
    return null;
  }
}

/**
 * Returns the last 100 messages for a room, including soft-delete metadata.
 */
function getRoomHistory(room) {
  try {
    return db
      .prepare(
        `SELECT id, username, message, timestamp, isDeleted, deletedFor
         FROM   messages
         WHERE  room = ?
         ORDER  BY timestamp ASC
         LIMIT  100`
      )
      .all(room);
  } catch (err) {
    console.error("[DB ERROR] getRoomHistory:", err.message);
    return [];
  }
}

/**
 * Fetches a single message by ID (used for delete authorisation).
 */
function getMessageById(id) {
  try {
    return db.prepare("SELECT * FROM messages WHERE id = ?").get(id) || null;
  } catch (err) {
    console.error("[DB ERROR] getMessageById:", err.message);
    return null;
  }
}

/**
 * Soft-deletes a message for ALL users (isDeleted = 1).
 */
function deleteMessageForEveryone(id) {
  try {
    db.prepare("UPDATE messages SET isDeleted = 1 WHERE id = ?").run(id);
    return true;
  } catch (err) {
    console.error("[DB ERROR] deleteMessageForEveryone:", err.message);
    return false;
  }
}

/**
 * Soft-deletes a message for ONE user by appending their username to deletedFor[].
 */
function deleteMessageForMe(id, username) {
  try {
    const row = db.prepare("SELECT deletedFor FROM messages WHERE id = ?").get(id);
    if (!row) return false;
    const arr = JSON.parse(row.deletedFor || "[]");
    if (!arr.includes(username)) arr.push(username);
    db.prepare("UPDATE messages SET deletedFor = ? WHERE id = ?").run(JSON.stringify(arr), id);
    return true;
  } catch (err) {
    console.error("[DB ERROR] deleteMessageForMe:", err.message);
    return false;
  }
}

module.exports = {
  createRoom,
  verifyRoom,
  saveMessage,
  getRoomHistory,
  getMessageById,
  deleteMessageForEveryone,
  deleteMessageForMe,
};