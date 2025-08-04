// ==============================
// verifySignature.js - Fixed with debugging
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
  try {
    const sortedKeys = Object.keys(payloadObj).sort();
    const result = {};
    for (const key of sortedKeys) {
      result[key] = payloadObj[key];
    }
    const canonical = JSON.stringify(result);
    console.log('Canonicalized payload:', canonical);
    return canonical;
  } catch (err) {
    console.error('Error canonicalizing payload:', err);
    throw err;
  }
}

// Load and parse the server's public key
async function loadPublicKey() {
  try {
    console.log('Attempting to load public key from /static/public_key.pem');
    
    const response = await fetch("/static/public_key.pem");
    
    if (!response.ok) {
      throw new Error(`Failed to fetch public key: ${response.status} ${response.statusText}`);
    }
    
    const keyPem = await response.text();
    console.log('Loaded PEM key:', keyPem.substring(0, 100) + '...');
    
    // Clean up the PEM format
    const pemBody = keyPem
      .replace(/-----BEGIN PUBLIC KEY-----/, "")
      .replace(/-----END PUBLIC KEY-----/, "")
      .replace(/\s+/g, "");

    if (!pemBody) {
      throw new Error('Invalid PEM format - no key data found');
    }

    console.log('Cleaned PEM body length:', pemBody.length);

    let binaryDer;
    try {
      binaryDer = str2ab(atob(pemBody));
    } catch (err) {
      throw new Error('Failed to decode base64 PEM data: ' + err.message);
    }

    console.log('Binary DER length:', binaryDer.byteLength);

    const publicKey = await crypto.subtle.importKey(
      "spki",
      binaryDer,
      { name: "RSA-PSS", hash: "SHA-256" },
      true,
      ["verify"]
    );

    console.log('✅ Public key loaded successfully');
    return publicKey;

  } catch (err) {
    console.error("❌ Failed to load public key:", err);
    throw err;
  }
}

// Verify RSA-PSS signature from the server
async function verifyQRSignature(payloadObj, signatureB64) {
  console.log('🔍 Starting signature verification...');
  console.log('Payload object:', payloadObj);
  console.log('Signature (base64):', signatureB64);

  try {
    // Validate inputs
    if (!payloadObj) {
      throw new Error('Payload object is null or undefined');
    }
    
    if (!signatureB64) {
      throw new Error('Signature is null or undefined');
    }

    if (typeof signatureB64 !== 'string') {
      throw new Error('Signature must be a string');
    }

    // Load public key
    console.log('📋 Loading public key...');
    const publicKey = await loadPublicKey();

    // Canonicalize payload
    console.log('📋 Canonicalizing payload...');
    const canonicalPayload = canonicalizePayload(payloadObj);
    const encodedPayload = new TextEncoder().encode(canonicalPayload);
    
    console.log('Canonical payload bytes length:', encodedPayload.length);

    // Decode signature
    console.log('📋 Decoding signature...');
    let signatureBytes;
    try {
      signatureBytes = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));
    } catch (err) {
      throw new Error('Failed to decode base64 signature: ' + err.message);
    }
    
    console.log('Signature bytes length:', signatureBytes.length);

    // Verify signature
    console.log('📋 Verifying signature...');
    const isValid = await crypto.subtle.verify(
      { name: "RSA-PSS", saltLength: 32 },
      publicKey,
      signatureBytes,
      encodedPayload
    );

    console.log('🔍 Verification result:', isValid);
    
    if (isValid) {
      console.log('✅ Signature verification successful!');
    } else {
      console.log('❌ Signature verification failed');
      console.log('Debug info:');
      console.log('  - Canonical payload:', canonicalPayload);
      console.log('  - Signature base64:', signatureB64);
      console.log('  - Payload keys:', Object.keys(payloadObj));
    }

    return isValid;

  } catch (err) {
    console.error("❌ Signature verification error:", err);
    console.log('Debug information:');
    console.log('  - Error message:', err.message);
    console.log('  - Payload object:', payloadObj);
    console.log('  - Signature string:', signatureB64);
    
    // Additional debugging
    if (payloadObj) {
      console.log('  - Payload keys:', Object.keys(payloadObj));
      try {
        const canonical = canonicalizePayload(payloadObj);
        console.log('  - Canonical payload:', canonical);
      } catch (e) {
        console.log('  - Failed to canonicalize:', e.message);
      }
    }

    return false;
  }
}

// Test function to check if everything is working
async function testVerification() {
  console.log('🧪 Running verification test...');
  
  try {
    // Test if we can load the public key
    await loadPublicKey();
    console.log('✅ Public key test passed');
    return true;
  } catch (err) {
    console.error('❌ Public key test failed:', err);
    return false;
  }
}

// Make test function available globally for debugging
window.testVerification = testVerification;