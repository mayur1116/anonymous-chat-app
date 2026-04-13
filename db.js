/**
 * db.js
 *
 * SQLite database integration for password-protected rooms and message history.
 * Uses bcryptjs to ensure room passwords are never stored in plaintext.
 */

const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const path = require("path");

const db = new Database(path.join(__dirname, "chat.db"));

// Enable WAL mode for better concurrent read performance
db.pragma("journal_mode = WAL");

// Initialize Database Tables
db.exec(`
  CREATE TABLE IF NOT EXISTS rooms (
    name TEXT PRIMARY KEY,
    password TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS messages (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    room      TEXT    NOT NULL,
    username  TEXT    NOT NULL,
    message   TEXT    NOT NULL,
    timestamp INTEGER NOT NULL,
    FOREIGN KEY (room) REFERENCES rooms(name) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_messages_room_ts
    ON messages (room, timestamp ASC);
`);

/**
 * Creates a new room with a hashed password.
 * @param {string} room
 * @param {string} password  Plaintext — hashed before storage.
 * @returns {{ success: boolean, error?: string }}
 */
async function createRoom(room, password) {
  try {
    const existing = db.prepare("SELECT name FROM rooms WHERE name = ?").get(room);
    if (existing) {
      return { success: false, error: `Room "${room}" already exists.` };
    }

    const hash = await bcrypt.hash(password, 10);
    db.prepare("INSERT INTO rooms (name, password) VALUES (?, ?)").run(room, hash);

    return { success: true };
  } catch (err) {
    console.error("[DB ERROR] createRoom:", err.message);
    return { success: false, error: "Database error during room creation." };
  }
}

/**
 * Verifies a room password before allowing entry.
 * @param {string} room
 * @param {string} password  Plaintext to compare against the stored hash.
 * @returns {{ success: boolean, error?: string }}
 */
async function verifyRoom(room, password) {
  try {
    const row = db.prepare("SELECT password FROM rooms WHERE name = ?").get(room);
    if (!row) {
      return { success: false, error: "Room not found. Please create it first." };
    }

    const match = await bcrypt.compare(password, row.password);
    if (!match) {
      return { success: false, error: "Incorrect room password." };
    }

    return { success: true };
  } catch (err) {
    console.error("[DB ERROR] verifyRoom:", err.message);
    return { success: false, error: "Database error during verification." };
  }
}

/**
 * Saves an encrypted message to the database.
 * @param {string} room
 * @param {string} username
 * @param {string} message    AES ciphertext string.
 * @param {number} timestamp  Unix ms timestamp.
 */
function saveMessage(room, username, message, timestamp) {
  try {
    db.prepare(
      "INSERT INTO messages (room, username, message, timestamp) VALUES (?, ?, ?, ?)"
    ).run(room, username, message, timestamp);
  } catch (err) {
    console.error("[DB ERROR] saveMessage:", err.message);
  }
}

/**
 * Retrieves the last 100 messages for a specific room, oldest first.
 *
 * FIX: `.all(room)` — the room argument was previously missing, causing the
 * prepared statement to run without its bound parameter and return no rows.
 *
 * @param {string} room
 * @returns {{ username: string, message: string, timestamp: number }[]}
 */
function getRoomHistory(room) {
  try {
    return db
      .prepare(
        `SELECT username, message, timestamp
         FROM   messages
         WHERE  room = ?
         ORDER  BY timestamp ASC
         LIMIT  100`
      )
      .all(room); // ← BUG WAS HERE: was `.all()` — room parameter was never passed
  } catch (err) {
    console.error("[DB ERROR] getRoomHistory:", err.message);
    return [];
  }
}

module.exports = {
  createRoom,
  verifyRoom,
  saveMessage,
  getRoomHistory,
};