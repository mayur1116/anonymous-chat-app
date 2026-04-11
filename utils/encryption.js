/**
 * utils/encryption.js
 *
 * AES encryption and decryption using crypto-js.
 * A shared secret key is used for all messages — both server and client
 * must use the same key to decrypt. In production, rotate this key and
 * deliver it securely (e.g., via environment variable).
 */

const CryptoJS = require("crypto-js");

// Shared secret — load from environment in production
const SECRET_KEY = process.env.CHAT_SECRET || "anon-chat-super-secret-key-2024";

/**
 * Encrypts a plaintext string using AES.
 * @param {string} plaintext - The message to encrypt.
 * @returns {string} Base64-encoded ciphertext.
 */
function encrypt(plaintext) {
  if (typeof plaintext !== "string" || plaintext.length === 0) {
    throw new Error("encrypt() requires a non-empty string");
  }
  return CryptoJS.AES.encrypt(plaintext, SECRET_KEY).toString();
}

/**
 * Decrypts an AES-encrypted ciphertext string.
 * @param {string} ciphertext - The Base64-encoded ciphertext.
 * @returns {string} Decrypted plaintext.
 */
function decrypt(ciphertext) {
  if (typeof ciphertext !== "string" || ciphertext.length === 0) {
    throw new Error("decrypt() requires a non-empty string");
  }
  const bytes = CryptoJS.AES.decrypt(ciphertext, SECRET_KEY);
  const plaintext = bytes.toString(CryptoJS.enc.Utf8);
  if (!plaintext) {
    throw new Error("Decryption failed — invalid ciphertext or wrong key");
  }
  return plaintext;
}

module.exports = { encrypt, decrypt };