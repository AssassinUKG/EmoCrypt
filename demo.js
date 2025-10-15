/**
 * EmoCrypt Demo Examples
 * 
 * Run with: node demo.js
 */

// For Node.js, you might need to install crypto polyfill or use Node 15.6+
// This demo assumes you have crypto.subtle available
const { EmoCrypt, emojiEncode, emojiDecode } = require('./emocrypt.js');

async function runDemo() {
  console.log('🔐🎲 EmoCrypt Demo\n');
  
  // Basic encoding example
  console.log('=== Basic Encoding ===');
  const text1 = "Hello World!";
  const encoded1 = emojiEncode(text1);
  const decoded1 = emojiDecode(encoded1);
  
  console.log(`Original: ${text1}`);
  console.log(`Encoded:  ${encoded1}`);
  console.log(`Decoded:  ${decoded1}`);
  console.log(`Match:    ${text1 === decoded1}\n`);
  
  // With passphrase shuffling
  console.log('=== With Passphrase Shuffling ===');
  const crypto1 = new EmoCrypt("mySecretPassphrase");
  const text2 = "Secret message";
  const encoded2 = crypto1.encode(text2);
  const decoded2 = crypto1.decode(encoded2);
  
  console.log(`Original: ${text2}`);
  console.log(`Encoded:  ${encoded2}`);
  console.log(`Decoded:  ${decoded2}`);
  console.log(`Match:    ${text2 === decoded2}\n`);
  
  // Different passphrase = different encoding
  console.log('=== Different Passphrase ===');
  const crypto2 = new EmoCrypt("differentPassphrase");
  const encoded3 = crypto2.encode(text2);
  
  console.log(`Same text with different passphrase: ${encoded3}`);
  console.log(`Different from previous: ${encoded2 !== encoded3}\n`);
  
  // AES encryption example (requires crypto.subtle)
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    console.log('=== AES Encryption ===');
    try {
      const crypto3 = new EmoCrypt("myPassphrase");
      const text3 = "Top secret data";
      const encrypted = await crypto3.encryptAndEncode(text3, "myPassword123");
      const decrypted = await crypto3.decryptAndDecode(encrypted, "myPassword123");
      
      console.log(`Original:  ${text3}`);
      console.log(`Encrypted: ${encrypted.substring(0, 50)}...`);
      console.log(`Decrypted: ${decrypted}`);
      console.log(`Match:     ${text3 === decrypted}\n`);
    } catch (error) {
      console.log(`AES demo failed: ${error.message}\n`);
    }
  } else {
    console.log('=== AES Encryption ===');
    console.log('crypto.subtle not available in this environment\n');
  }
  
  // Edge cases
  console.log('=== Edge Cases ===');
  const emptyString = "";
  const emptyEncoded = emojiEncode(emptyString);
  const emptyDecoded = emojiDecode(emptyEncoded);
  console.log(`Empty string: "${emptyString}" -> "${emptyEncoded}" -> "${emptyDecoded}"`);
  
  const unicodeText = "Hello 🌍 Unicode! 中文";
  const unicodeEncoded = emojiEncode(unicodeText);
  const unicodeDecoded = emojiDecode(unicodeEncoded);
  console.log(`Unicode: ${unicodeText}`);
  console.log(`Encoded: ${unicodeEncoded}`);
  console.log(`Decoded: ${unicodeDecoded}`);
  console.log(`Match:   ${unicodeText === unicodeDecoded}\n`);
  
  console.log('Demo complete! 🎉');
}

// Run the demo
runDemo().catch(console.error);