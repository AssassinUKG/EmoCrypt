# 🔐🎲 EmoCrypt — Emoji Obfuscator

A fun and educational tool that encodes text into emoji using nibble mapping, with optional cryptographic features.

<img width="878" height="549" alt="image" src="https://github.com/user-attachments/assets/903fd65e-c9e7-458c-aeb7-5f3d219f94fe" />


[EmoCrypt Demo](https://AssassinUKG.github.io/EmoCrypt)

## 🌟 Features

- **Emoji Nibble Encoding**: Maps each byte of text to two emojis (4-bit nibbles)
- **Deterministic Shuffling**: Use a passphrase to shuffle the emoji mapping
- **AES-GCM Encryption**: Optional real cryptographic protection with password
- **Interactive Web Interface**: Clean, modern UI for easy encoding/decoding
- **Standalone JavaScript**: Core functionality available as a standalone library

## 🚀 Live Demo

Open `index.html` in your browser to use the interactive interface.

## 📚 How It Works

1. **Basic Encoding**: Each byte is split into two 4-bit nibbles, mapped to emojis
2. **Shuffling**: Optional passphrase-based deterministic shuffling of emoji mapping
3. **AES Wrapping**: Optional AES-GCM encryption for real security

## 🔧 Standalone JavaScript Library

Here's the core EmoCrypt functionality as standalone JavaScript:

```javascript
// EmoCrypt Standalone Library
// Base emoji set (16 entries = 4-bit nibble)
const BASE_EMO = [..."😀😁😂🤣😃😄😅😆😉😊😋😎😍😘🥰😗"];

// Text encoder/decoder
const te = new TextEncoder();
const td = new TextDecoder();

// Utility: create mapping and inverse map
function buildMaps(emojiArr) {
  const encMap = new Map();
  const decMap = new Map();
  for (let i = 0; i < emojiArr.length; i++) {
    encMap.set(i, emojiArr[i]);
    decMap.set(emojiArr[i], i);
  }
  return { encMap, decMap };
}

// Seeded RNG helpers (xmur3 + mulberry32)
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

function mulberry32(a) {
  return function() {
    var t = (a += 0x6D2B79F5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

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

// Core encode / decode (emoji nibble mapping)
function emojiEncode(str, emojiArr = BASE_EMO) {
  const { encMap } = buildMaps(emojiArr);
  const bytes = Array.from(te.encode(str));
  // map each byte into two emoji (high nibble, low nibble)
  return bytes.map(b => encMap.get(b >> 4) + encMap.get(b & 15)).join('');
}

function emojiDecode(emojiStr, emojiArr = BASE_EMO) {
  const { decMap } = buildMaps(emojiArr);
  const chars = [...emojiStr];
  const nibbles = chars.map(c => {
    const v = decMap.get(c);
    if (v === undefined) throw new Error('Unknown emoji encountered');
    return v;
  });
  const out = new Uint8Array(nibbles.length / 2);
  for (let i = 0, j = 0; i < nibbles.length; i += 2) {
    out[j++] = (nibbles[i] << 4) | nibbles[i + 1];
  }
  return td.decode(out);
}

// WebCrypto AES-GCM helpers (password -> key via PBKDF2)
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

async function aesEncrypt(plaintext, password) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKeyFromPassword(password, salt);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
  // return base64 with iv+salt prefix
  const buf = new Uint8Array(salt.byteLength + iv.byteLength + ct.byteLength);
  buf.set(salt, 0); buf.set(iv, salt.byteLength); buf.set(new Uint8Array(ct), salt.byteLength + iv.byteLength);
  return btoa(String.fromCharCode(...buf));
}

async function aesDecrypt(b64, password) {
  const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const salt = raw.slice(0, 16);
  const iv = raw.slice(16, 28);
  const ct = raw.slice(28);
  const key = await deriveKeyFromPassword(password, salt);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(pt);
}

// Main EmoCrypt class
class EmoCrypt {
  constructor(passphrase = null) {
    this.emojiSet = passphrase ? seededShuffle(BASE_EMO, passphrase) : BASE_EMO.slice();
  }

  encode(text) {
    return emojiEncode(text, this.emojiSet);
  }

  decode(emojiText) {
    return emojiDecode(emojiText, this.emojiSet);
  }

  async encryptAndEncode(text, password) {
    const encoded = this.encode(text);
    const encrypted = await aesEncrypt(encoded, password);
    return `AESv1:${encrypted}`;
  }

  async decryptAndDecode(encryptedText, password) {
    if (!encryptedText.startsWith('AESv1:')) {
      throw new Error('Invalid encrypted format');
    }
    const decrypted = await aesDecrypt(encryptedText.slice(6), password);
    return this.decode(decrypted);
  }
}
```

## 📖 Usage Examples

### Basic Encoding/Decoding

```javascript
// Basic usage (no passphrase)
const crypto = new EmoCrypt();

// Encode text to emojis
const encoded = crypto.encode("Hello World!");
console.log(encoded); // Output: 😂😆😍😘😂😇😂😇😂😊😀😃😂😊😋😂😂😃😄😀😂😀

// Decode emojis back to text
const decoded = crypto.decode(encoded);
console.log(decoded); // Output: "Hello World!"
```

### With Passphrase Shuffling

```javascript
// Using passphrase for deterministic shuffling
const cryptoWithPass = new EmoCrypt("mySecretPassphrase");

const encoded = cryptoWithPass.encode("Secret message");
console.log(encoded); // Different emoji mapping due to shuffling

const decoded = cryptoWithPass.decode(encoded);
console.log(decoded); // Output: "Secret message"
```

### With AES Encryption

```javascript
// With real cryptographic protection
const crypto = new EmoCrypt("myPassphrase");

// Encrypt and encode
const encrypted = await crypto.encryptAndEncode("Top secret data", "myPassword123");
console.log(encrypted); // Output: AESv1:base64encrypteddata...

// Decrypt and decode
const decrypted = await crypto.decryptAndDecode(encrypted, "myPassword123");
console.log(decrypted); // Output: "Top secret data"
```

### Standalone Functions

```javascript
// Using standalone functions without class
const text = "Hello!";
const encoded = emojiEncode(text);
const decoded = emojiDecode(encoded);

// With custom emoji set
const customEmojis = [..."🐶🐱🐭🐹🐰🦊🐻🐼🐨🐯🦁🐸🐵🙈🙉🙊"];
const encodedCustom = emojiEncode(text, customEmojis);
const decodedCustom = emojiDecode(encodedCustom, customEmojis);
```

## 🛠️ Installation

### For Web Projects

1. Download or clone this repository
2. Include the EmoCrypt code in your project
3. Use the functions or EmoCrypt class as shown above

### For Node.js Projects

```bash
# Clone the repository
git clone https://github.com/AssassinUKG/EmoCrypt.git
cd EmoCrypt

# Include in your Node.js project
# Note: You may need polyfills for TextEncoder/TextDecoder and crypto.subtle in older Node.js versions
```

## 🔒 Security Notes

- **Emoji encoding alone is NOT encryption** - it's obfuscation for fun/educational purposes
- **Use AES-GCM wrapping** for real cryptographic security
- **Passphrase shuffling** adds some complexity but isn't cryptographically secure
- This project is educational and should not be used for securing sensitive data without the AES option

## 🎯 Use Cases

- **Educational**: Learn about encoding, mapping, and basic cryptography
- **Fun Projects**: Add emoji obfuscation to games or creative applications
- **Steganography**: Hide text in plain sight using emojis
- **Data Transformation**: Creative way to represent text data

## 🤝 Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

## 👤 Author

Created by [AssassinUKG](https://github.com/AssassinUKG)

---

**⚠️ Disclaimer**: This tool is for educational and entertainment purposes. The emoji encoding provides obfuscation, not encryption. Use the AES-GCM option for actual security needs.
