/**
 * server.js - Fast, Zero-Dependency Node.js Backend for FileCrypt
 *
 * Runs out-of-the-box on Windows, Linux, and macOS:
 *   node server.js [port]
 *
 * Provides full binary compatibility with server.c:
 *   - "FENC" magic header (4 bytes)
 *   - 8-byte cryptographic salt
 *   - 4-byte password verification checksum
 *   - 64-bit xorshift keystream XOR cipher
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = parseInt(process.argv[2] || process.env.PORT || '8080', 10);
const MAX_UPLOAD = 100 * 1024 * 1024; // 100 MB
const MAGIC = Buffer.from('FENC', 'ascii');
const ROUNDS = 100000;
const FNV_PRIME = 1099511628211n;
const FNV_INIT = 14695981039346656037n;
const MASK64 = 0xFFFFFFFFFFFFFFFFn;
const MULT = 2685821657736338717n;

// Find static public directory (supports running from root or nested directory)
let PUBLIC_DIR = path.join(__dirname, 'public');
if (!fs.existsSync(PUBLIC_DIR)) {
  const alt = path.join(__dirname, 'filecrypt-web', 'public');
  if (fs.existsSync(alt)) PUBLIC_DIR = alt;
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

/* ================= Crypto Core (Exact 64-bit parity with server.c) ================= */

function fnv1a(h, data) {
  for (let i = 0; i < data.length; i++) {
    h = ((h ^ BigInt(data[i])) * FNV_PRIME) & MASK64;
  }
  return h;
}

function deriveKey(password, salt) {
  const pwBytes = Buffer.from(password, 'utf8');
  let h = FNV_INIT;
  for (let i = 0; i < ROUNDS; i++) {
    h = fnv1a(h, pwBytes);
    h = fnv1a(h, salt);
  }
  return h === 0n ? 0x9E3779B97F4A7C15n : h;
}

function createKeystream(key) {
  let s = key;
  return function nextByte() {
    s = (s ^ (s >> 12n)) & MASK64;
    s = (s ^ ((s << 25n) & MASK64)) & MASK64;
    s = (s ^ (s >> 27n)) & MASK64;
    return Number(((s * MULT & MASK64) >> 56n) & 0xFFn);
  };
}

function passwordCheck(key) {
  let s = key ^ 0xA5A5A5A5A5A5A5A5n;
  const next = () => {
    s = (s ^ (s >> 12n)) & MASK64;
    s = (s ^ ((s << 25n) & MASK64)) & MASK64;
    s = (s ^ (s >> 27n)) & MASK64;
    return Number(((s * MULT & MASK64) >> 56n) & 0xFFn);
  };
  let v = 0;
  for (let i = 0; i < 4; i++) {
    v = ((v << 8) | next()) >>> 0;
  }
  return v;
}

function encryptBuffer(input, password) {
  const salt = crypto.randomBytes(8);
  const key = deriveKey(password, salt);
  const check = passwordCheck(key);

  const header = Buffer.alloc(16);
  MAGIC.copy(header, 0);
  salt.copy(header, 4);
  header.writeUInt32BE(check, 12);

  const output = Buffer.allocUnsafe(input.length);
  const next = createKeystream(key);
  for (let i = 0; i < input.length; i++) {
    output[i] = input[i] ^ next();
  }

  return Buffer.concat([header, output]);
}

function decryptBuffer(input, password) {
  if (input.length < 16) {
    throw { status: 422, message: 'This file is too small to be a valid FileCrypt archive.' };
  }
  if (!input.subarray(0, 4).equals(MAGIC)) {
    throw { status: 422, message: 'This is not a valid FileCrypt encrypted file.' };
  }

  const salt = input.subarray(4, 12);
  const storedCheck = input.readUInt32BE(12);
  const key = deriveKey(password, salt);

  if (passwordCheck(key) !== storedCheck) {
    throw { status: 401, message: 'Incorrect password. Decryption failed.' };
  }

  const ciphertext = input.subarray(16);
  const plaintext = Buffer.allocUnsafe(ciphertext.length);
  const next = createKeystream(key);
  for (let i = 0; i < ciphertext.length; i++) {
    plaintext[i] = ciphertext[i] ^ next();
  }

  return plaintext;
}

/* ================= HTTP Server ================= */

const server = http.createServer((req, res) => {
  // CORS support
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || '127.0.0.1'}`);
  const pathname = parsedUrl.pathname;

  // Health check endpoint
  if (pathname === '/api/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', engine: 'node', version: process.version }));
    return;
  }

  // API endpoints
  if (pathname === '/api/encrypt' || pathname === '/api/decrypt') {
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'text/plain' });
      res.end('Method Not Allowed');
      return;
    }

    const rawPw = req.headers['x-password'];
    if (!rawPw) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('A password is required in the X-Password header.');
      return;
    }

    let password = '';
    try {
      password = decodeURIComponent(rawPw);
    } catch {
      password = rawPw;
    }

    const chunks = [];
    let received = 0;

    req.on('data', chunk => {
      received += chunk.length;
      if (received > MAX_UPLOAD) {
        res.writeHead(413, { 'Content-Type': 'text/plain' });
        res.end('File exceeds 100 MB limit.');
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (res.writableEnded) return;
      const fullBuffer = Buffer.concat(chunks);
      if (fullBuffer.length === 0) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('The upload file is empty.');
        return;
      }

      try {
        const isEncrypt = pathname === '/api/encrypt';
        const result = isEncrypt
          ? encryptBuffer(fullBuffer, password)
          : decryptBuffer(fullBuffer, password);

        console.log(`[${isEncrypt ? 'Encrypt' : 'Decrypt'}] Processed ${fullBuffer.length} bytes -> ${result.length} bytes`);
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Content-Length': result.length,
          'Cache-Control': 'no-store'
        });
        res.end(result);
      } catch (err) {
        const status = err.status || 500;
        const msg = err.message || 'Server processing error.';
        res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(msg);
      }
    });

    return;
  }

  // Static file serving
  if (req.method === 'GET' || req.method === 'HEAD') {
    let relPath = pathname === '/' ? 'index.html' : pathname.replace(/^\//, '');
    const safePath = path.normalize(relPath).replace(/^(\.\.[\/\\])+/, '');
    const filePath = path.join(PUBLIC_DIR, safePath);

    fs.stat(filePath, (err, stats) => {
      if (err || !stats.isFile()) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('File not found');
        return;
      }

      const ext = path.extname(filePath).toLowerCase();
      const contentType = MIME_TYPES[ext] || 'application/octet-stream';

      res.writeHead(200, {
        'Content-Type': contentType,
        'Content-Length': stats.size,
        'Cache-Control': 'no-cache'
      });

      if (req.method === 'HEAD') {
        res.end();
      } else {
        fs.createReadStream(filePath).pipe(res);
      }
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('\n=======================================================');
  console.log(`   FileCrypt Server (Node.js) is ready!`);
  console.log(`   URL: http://127.0.0.1:${PORT}`);
  console.log(`   Serving files from: ${PUBLIC_DIR}`);
  console.log('   Press Ctrl+C to terminate.');
  console.log('=======================================================\n');
});
