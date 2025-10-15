/**
 * EmoCrypt - Emoji Obfuscator Library
 * 
 * A JavaScript library for encoding text into emoji using nibble mapping,
 * with optional passphrase shuffling and AES-GCM encryption.
 * 
 * Author: AssassinUKG (https://github.com/AssassinUKG)
 * License: MIT
 */

// Base emoji set (16 entries = 4-bit nibble)
const BASE_EMO = [..."😀😁😂🤣😃😄😅😆😉😊😋😎😍😘🥰😗"];

// Text encoder/decoder (for Node.js compatibility, you might need polyfills)
const te = typeof TextEncoder !== 'undefined' ? new TextEncoder() : require('util').TextEncoder;
const td = typeof TextDecoder !== 'undefined' ? new TextDecoder() : require('util').TextDecoder;

/**
 * Utility: create mapping and inverse map
 * @param {string[]} emojiArr - Array of emoji characters
 * @returns {Object} Object containing encMap and decMap
 */
function buildMaps(emojiArr) {
  const encMap = new Map();
  const decMap = new Map();
  for (let i = 0; i < emojiArr.length; i++) {
    encMap.set(i, emojiArr[i]);
    decMap.set(emojiArr[i], i);
  }
  return { encMap, decMap };
}

/**
 * Seeded RNG helpers (xmur3 + mulberry32)
 * Creates a hash function for seeding
 * @param {string} str - String to hash
 * @returns {Function} Hash function
 */
function xmur3(str) {
  for (var i = 0, h = 1779033703 ^ str.length; i < str.length; i++) {
    h = Math.imul(h ^ str.charCodeAt(i), 3432918353);
    h = (h << 13) | (h >>> 19);
  }
  return function() {
    h = Math.imul(h ^ (h >>> 16), 2246822507);
    h = Math.imul(h ^ (h >>> 13), 3266489909);
    return (h ^= h >>> 16) >>> 0;
  };
}

/**
 * Mulberry32 PRNG
 * @param {number} a - Seed value
 * @returns {Function} Random number generator
 */
function mulberry32(a) {
  return function() {
    var t = (a += 0x6D2B79F5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Shuffle array using seeded random number generator
 * @param {Array} array - Array to shuffle
 * @param {string} pass - Passphrase for seeding
 * @returns {Array} Shuffled array
 */
function seededShuffle(array, pass) {
  const seed = xmur3(pass)();
  const rnd = mulberry32(seed);
  const out = array.slice();
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rnd() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

/**
 * Core encode function - converts text to emoji using nibble mapping
 * @param {string} str - Text to encode
 * @param {string[]} emojiArr - Array of emoji characters (default: BASE_EMO)
 * @returns {string} Encoded emoji string
 */
function emojiEncode(str, emojiArr = BASE_EMO) {
  const { encMap } = buildMaps(emojiArr);
  const bytes = Array.from(te.encode(str));
  // map each byte into two emoji (high nibble, low nibble)
  return bytes.map(b => encMap.get(b >> 4) + encMap.get(b & 15)).join('');
}

/**
 * Core decode function - converts emoji back to text
 * @param {string} emojiStr - Emoji string to decode
 * @param {string[]} emojiArr - Array of emoji characters (default: BASE_EMO)
 * @returns {string} Decoded text
 */
function emojiDecode(emojiStr, emojiArr = BASE_EMO) {
  const { decMap } = buildMaps(emojiArr);
  const chars = [...emojiStr];
  const nibbles = chars.map(c => {
    const v = decMap.get(c);
    if (v === undefined) throw new Error('Unknown emoji encountered: ' + c);
    return v;
  });
  
  if (nibbles.length % 2 !== 0) {
    throw new Error('Invalid emoji string length - must be even number of emojis');
  }
  
  const out = new Uint8Array(nibbles.length / 2);
  for (let i = 0, j = 0; i < nibbles.length; i += 2) {
    out[j++] = (nibbles[i] << 4) | nibbles[i + 1];
  }
  return td.decode(out);
}

/**
 * Derive cryptographic key from password using PBKDF2
 * @param {string} pass - Password
 * @param {Uint8Array} salt - Salt bytes
 * @returns {Promise<CryptoKey>} Derived key
 */
async function deriveKeyFromPassword(pass, salt) {
  const pwUtf8 = new TextEncoder().encode(pass);
  const baseKey = await crypto.subtle.importKey('raw', pwUtf8, { name: 'PBKDF2' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt, iterations: 100_000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt plaintext using AES-GCM
 * @param {string} plaintext - Text to encrypt
 * @param {string} password - Password for encryption
 * @returns {Promise<string>} Base64 encoded encrypted data
 */
async function aesEncrypt(plaintext, password) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKeyFromPassword(password, salt);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
  
  // return base64 with iv+salt prefix
  const buf = new Uint8Array(salt.byteLength + iv.byteLength + ct.byteLength);
  buf.set(salt, 0);
  buf.set(iv, salt.byteLength);
  buf.set(new Uint8Array(ct), salt.byteLength + iv.byteLength);
  return btoa(String.fromCharCode(...buf));
}

/**
 * Decrypt AES-GCM encrypted data
 * @param {string} b64 - Base64 encoded encrypted data
 * @param {string} password - Password for decryption
 * @returns {Promise<string>} Decrypted plaintext
 */
async function aesDecrypt(b64, password) {
  const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const salt = raw.slice(0, 16);
  const iv = raw.slice(16, 28);
  const ct = raw.slice(28);
  const key = await deriveKeyFromPassword(password, salt);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(pt);
}

/**
 * Main EmoCrypt class
 */
class EmoCrypt {
  /**
   * Create a new EmoCrypt instance
   * @param {string|null} passphrase - Optional passphrase for emoji shuffling
   */
  constructor(passphrase = null) {
    this.emojiSet = passphrase ? seededShuffle(BASE_EMO, passphrase) : BASE_EMO.slice();
    this.passphrase = passphrase;
  }

  /**
   * Encode text to emojis
   * @param {string} text - Text to encode
   * @returns {string} Encoded emoji string
   */
  encode(text) {
    return emojiEncode(text, this.emojiSet);
  }

  /**
   * Decode emojis back to text
   * @param {string} emojiText - Emoji string to decode
   * @returns {string} Decoded text
   */
  decode(emojiText) {
    return emojiDecode(emojiText, this.emojiSet);
  }

  /**
   * Encrypt text and encode to emojis
   * @param {string} text - Text to encrypt and encode
   * @param {string} password - Password for AES encryption
   * @returns {Promise<string>} Encrypted and encoded string with AESv1: prefix
   */
  async encryptAndEncode(text, password) {
    const encoded = this.encode(text);
    const encrypted = await aesEncrypt(encoded, password);
    return `AESv1:${encrypted}`;
  }

  /**
   * Decrypt and decode text
   * @param {string} encryptedText - Encrypted text with AESv1: prefix
   * @param {string} password - Password for AES decryption
   * @returns {Promise<string>} Decrypted and decoded text
   */
  async decryptAndDecode(encryptedText, password) {
    if (!encryptedText.startsWith('AESv1:')) {
      throw new Error('Invalid encrypted format - must start with AESv1:');
    }
    const decrypted = await aesDecrypt(encryptedText.slice(6), password);
    return this.decode(decrypted);
  }

  /**
   * Get the current emoji set
   * @returns {string[]} Current emoji mapping
   */
  getEmojiSet() {
    return this.emojiSet.slice();
  }

  /**
   * Reset emoji set to default or shuffle with new passphrase
   * @param {string|null} newPassphrase - New passphrase or null for default
   */
  setPassphrase(newPassphrase) {
    this.passphrase = newPassphrase;
    this.emojiSet = newPassphrase ? seededShuffle(BASE_EMO, newPassphrase) : BASE_EMO.slice();
  }
}

// Export for both CommonJS and ES modules
if (typeof module !== 'undefined' && module.exports) {
  // CommonJS (Node.js)
  module.exports = {
    EmoCrypt,
    emojiEncode,
    emojiDecode,
    aesEncrypt,
    aesDecrypt,
    seededShuffle,
    BASE_EMO
  };
} else if (typeof window !== 'undefined') {
  // Browser global
  window.EmoCrypt = EmoCrypt;
  window.emojiEncode = emojiEncode;
  window.emojiDecode = emojiDecode;
  window.aesEncrypt = aesEncrypt;
  window.aesDecrypt = aesDecrypt;
  window.seededShuffle = seededShuffle;
  window.BASE_EMO = BASE_EMO;
}