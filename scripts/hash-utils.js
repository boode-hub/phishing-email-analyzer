// Hash utilities for attachment analysis
// Uses Web Crypto API for SHA-256 and a simple MD5 implementation

/**
 * Compute SHA-256 hash of a string
 * @param {string} str
 * @returns {Promise<string>}
 */
export async function sha256(str) {
  const encoder = new TextEncoder();
  return sha256Bytes(encoder.encode(str));
}

/**
 * Compute SHA-256 of raw bytes.
 *
 * Attachments must be hashed as bytes, never as a string. Decoding base64 with
 * atob() yields a binary string whose code units are 0-255; running that back
 * through TextEncoder UTF-8-encodes every byte above 0x7F into two bytes, so
 * the digest of any real image or executable came out wrong.
 *
 * @param {Uint8Array} bytes
 * @returns {Promise<string>}
 */
export async function sha256Bytes(bytes) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Compute MD5 of raw bytes.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function md5Bytes(bytes) {
  return md5Array(bytes);
}

/**
 * Compute MD5 hash of a string (synchronous, pure JS)
 * @param {string} str
 * @returns {string}
 */
export function md5(str) {
  const utf8 = new TextEncoder().encode(str);
  return md5Array(utf8);
}

function md5Array(input) {
  const s = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5,
    9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11,
    16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10,
    15, 21,
  ];
  const K = new Uint32Array(64);
  for (let i = 0; i < 64; i++) {
    K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296);
  }

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;

  const padded = new Uint8Array(Math.ceil((input.length + 9) / 64) * 64);
  padded.set(input);
  padded[input.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, input.length * 8, true);

  for (let i = 0; i < padded.length; i += 64) {
    const M = new Uint32Array(16);
    for (let j = 0; j < 16; j++) {
      M[j] = view.getUint32(i + j * 4, true);
    }

    let A = a0;
    let B = b0;
    let C = c0;
    let D = d0;

    for (let j = 0; j < 64; j++) {
      let F, g;
      if (j < 16) {
        F = (B & C) | (~B & D);
        g = j;
      } else if (j < 32) {
        F = (D & B) | (~D & C);
        g = (5 * j + 1) % 16;
      } else if (j < 48) {
        F = B ^ C ^ D;
        g = (3 * j + 5) % 16;
      } else {
        F = C ^ (B | ~D);
        g = (7 * j) % 16;
      }
      F = (F + A + K[j] + M[g]) >>> 0;
      A = D;
      D = C;
      C = B;
      B = (B + leftRotate(F, s[j])) >>> 0;
    }

    a0 = (a0 + A) >>> 0;
    b0 = (b0 + B) >>> 0;
    c0 = (c0 + C) >>> 0;
    d0 = (d0 + D) >>> 0;
  }

  return [a0, b0, c0, d0]
    .map((v) => {
      const bytes = new Uint8Array(4);
      new DataView(bytes.buffer).setUint32(0, v, true);
      return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    })
    .join("");
}

function leftRotate(x, c) {
  return ((x << c) | (x >>> (32 - c))) >>> 0;
}
