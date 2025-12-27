// Generate a new 16-byte salt
const salt = window.crypto.getRandomValues(new Uint8Array(16));

async function getBaseKey(pin) {
  const encoder = new TextEncoder();
  return window.crypto.subtle.importKey(
    "raw",
    encoder.encode(pin),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
}
async function deriveEncryptionKey(pin, salt) {
  const baseKey = await getBaseKey(pin);
  
  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt, // This must be a Uint8Array (16 bytes)
      iterations: 600000,
      hash: "SHA-256"
    },
    baseKey,
    { name: "AES-GCM", length: 256 }, // We want a 256-bit AES key
    false, // Key is not extractable (extra security)
    ["encrypt", "decrypt"]
  );
}