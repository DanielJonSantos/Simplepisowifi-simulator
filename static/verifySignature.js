// ==============================
// verifySignature.js
// ==============================

// Helper: Convert base64 string to ArrayBuffer
function str2ab(str) {
  const buf = new Uint8Array(str.length);
  for (let i = 0; i < str.length; ++i) {
    buf[i] = str.charCodeAt(i);
  }
  return buf.buffer;
}

// Canonicalize payload: JSON with sorted keys and compact formatting
function canonicalizePayload(payloadObj) {
  const sortedKeys = Object.keys(payloadObj).sort();
  const result = {};
  for (const key of sortedKeys) {
    result[key] = payloadObj[key];
  }
  return JSON.stringify(result); // Mimics Python’s sort_keys=True, separators=(",", ":")
}

// Load and parse the server's public key
async function loadPublicKey() {
  try {
    const keyPem = await fetch("/static/public_key.pem").then(res => res.text());
    const pemBody = keyPem
      .replace(/-----BEGIN PUBLIC KEY-----/, "")
      .replace(/-----END PUBLIC KEY-----/, "")
      .replace(/\s+/g, "");

    const binaryDer = str2ab(atob(pemBody));

    return crypto.subtle.importKey(
      "spki",
      binaryDer,
      { name: "RSA-PSS", hash: "SHA-256" },
      true,
      ["verify"]
    );
  } catch (err) {
    console.error("Failed to load public key:", err);
    throw err;
  }
}

// Verify RSA-PSS signature from the server
async function verifyQRSignature(payloadObj, signatureB64) {
  try {
    const publicKey = await loadPublicKey();
    const canonicalPayload = canonicalizePayload(payloadObj);
    const encodedPayload = new TextEncoder().encode(canonicalPayload);
    const signatureBytes = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));

    return await crypto.subtle.verify(
      { name: "RSA-PSS", saltLength: 32 },
      publicKey,
      signatureBytes,
      encodedPayload
    );
  } catch (err) {
    console.error("Signature verification error:", err);
    console.log("Canonical payload sent to verify:", canonicalPayload);
    console.log("Signature string:", signatureB64);

    return false;
  }
}
