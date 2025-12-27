// Generate a new 16-byte salt
const salt = window.crypto.getRandomValues(new Uint8Array(16));
const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 12 bytes is standard for GCM
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
async function fileToBuffer(file) {
    return new Promise((resolve) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.readAsArrayBuffer(file);
    });
}
async function encryptFile(file, derivedKey) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // New IV for this file
    const fileBuffer = await fileToBuffer(file);
    const encryptedContent = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        derivedKey,
        fileBuffer
    );
    return {
        encryptedBlob: new Blob([encryptedContent]),
        fileIv: iv
    };
}
//for have i been pwned
async function sha1(string) {
    const encoder = new TextEncoder();
    const data = encoder.encode(string);
    const hashBuffer = await window.crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).toUpperCase().join('');
}
async function checkPinLeak(pin) {
    const fullHash = await sha1(pin);
    const prefix = fullHash.substring(0, 5);
    const suffix = fullHash.substring(5);

    // Call the HIBP Range API
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    const text = await response.text();

    // The API returns a list of suffixes and their leak counts: "SUFFIX:COUNT"
    const leaks = text.split('\n');
    const match = leaks.find(line => line.startsWith(suffix));

    if (match) {
        const count = match.split(':')[1];
        return { leaked: true, count: parseInt(count) };
    }

    return { leaked: false, count: 0 };
}