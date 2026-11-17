#!/usr/bin/env python3
"""
server.py - Zero-Dependency Python Backend for FileCrypt

Runs out-of-the-box on Windows, Linux, and macOS:
    python server.py [port]

Binary compatible with server.c and server.js:
    - "FENC" 4-byte magic
    - 8-byte cryptographic salt
    - 4-byte check
    - 64-bit xorshift keystream
"""

import sys
import os
import struct
import secrets
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("PORT", 8080))
MAX_UPLOAD = 100 * 1024 * 1024  # 100 MB
MAGIC = b"FENC"
ROUNDS = 100000
FNV_PRIME = 1099511628211
FNV_INIT = 14695981039346656037
MASK64 = 0xFFFFFFFFFFFFFFFF
MULT = 2685821657736338717

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(BASE_DIR, "public")
if not os.path.exists(PUBLIC_DIR):
    alt = os.path.join(BASE_DIR, "filecrypt-web", "public")
    if os.path.exists(alt):
        PUBLIC_DIR = alt

MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon"
}

def fnv1a(h, data):
    for b in data:
        h = ((h ^ b) * FNV_PRIME) & MASK64
    return h

def derive_key(password, salt):
    pw_bytes = password.encode("utf-8")
    h = FNV_INIT
    for _ in range(ROUNDS):
        h = fnv1a(h, pw_bytes)
        h = fnv1a(h, salt)
    return 0x9E3779B97F4A7C15 if h == 0 else h

def create_keystream(key):
    s = key
    def next_byte():
        nonlocal s
        s = (s ^ (s >> 12)) & MASK64
        s = (s ^ ((s << 25) & MASK64)) & MASK64
        s = (s ^ (s >> 27)) & MASK64
        return ((s * MULT & MASK64) >> 56) & 0xFF
    return next_byte

def password_check(key):
    s = key ^ 0xA5A5A5A5A5A5A5A5
    def next_byte():
        nonlocal s
        s = (s ^ (s >> 12)) & MASK64
        s = (s ^ ((s << 25) & MASK64)) & MASK64
        s = (s ^ (s >> 27)) & MASK64
        return ((s * MULT & MASK64) >> 56) & 0xFF
    v = 0
    for _ in range(4):
        v = ((v << 8) | next_byte()) & 0xFFFFFFFF
    return v

def encrypt_bytes(data, password):
    salt = secrets.token_bytes(8)
    key = derive_key(password, salt)
    check = password_check(key)
    header = MAGIC + salt + struct.pack(">I", check)
    next_byte = create_keystream(key)
    ciphertext = bytearray(len(data))
    for i, b in enumerate(data):
        ciphertext[i] = b ^ next_byte()
    return header + bytes(ciphertext)

def decrypt_bytes(data, password):
    if len(data) < 16:
        raise ValueError("File is too small to be a FileCrypt file.")
    if data[:4] != MAGIC:
        raise ValueError("This is not a valid FileCrypt encrypted file.")
    salt = data[4:12]
    stored_check = struct.unpack(">I", data[12:16])[0]
    key = derive_key(password, salt)
    if password_check(key) != stored_check:
        raise PermissionError("Incorrect password.")
    next_byte = create_keystream(key)
    ciphertext = data[16:]
    plaintext = bytearray(len(ciphertext))
    for i, b in enumerate(ciphertext):
        plaintext[i] = b ^ next_byte()
    return bytes(plaintext)

class FileCryptHandler(BaseHTTPRequestHandler):
    def end_headers_with_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers_with_cors()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers_with_cors()
            self.wfile.write(b'{"status":"ok","engine":"python"}')
            return

        rel = "index.html" if path == "/" else path.lstrip("/")
        safe = os.path.normpath(rel)
        if safe.startswith("..") or os.path.isabs(safe):
            self.send_error(403, "Access Denied")
            return

        full_path = os.path.join(PUBLIC_DIR, safe)
        if not os.path.isfile(full_path):
            self.send_error(404, "File Not Found")
            return

        ext = os.path.splitext(full_path)[1].lower()
        ctype = MIME_TYPES.get(ext, "application/octet-stream")
        size = os.path.getsize(full_path)

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(size))
        self.end_headers_with_cors()

        with open(full_path, "rb") as f:
            self.wfile.write(f.read())

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path not in ("/api/encrypt", "/api/decrypt"):
            self.send_error(404, "Endpoint Not Found")
            return

        pw_raw = self.headers.get("X-Password", "")
        if not pw_raw:
            self.send_response(400)
            self.send_header("Content-Type", "text/plain")
            self.end_headers_with_cors()
            self.wfile.write(b"A password is required in the X-Password header.")
            return

        password = urllib.parse.unquote(pw_raw)
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0

        if length == 0:
            self.send_response(400)
            self.send_header("Content-Type", "text/plain")
            self.end_headers_with_cors()
            self.wfile.write(b"The upload file is empty.")
            return

        if length > MAX_UPLOAD:
            self.send_response(413)
            self.send_header("Content-Type", "text/plain")
            self.end_headers_with_cors()
            self.wfile.write(b"File exceeds 100 MB limit.")
            return

        data = self.rfile.read(length)

        try:
            if path == "/api/encrypt":
                result = encrypt_bytes(data, password)
            else:
                result = decrypt_bytes(data, password)

            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(result)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers_with_cors()
            self.wfile.write(result)
        except PermissionError:
            self.send_response(401)
            self.send_header("Content-Type", "text/plain")
            self.end_headers_with_cors()
            self.wfile.write(b"Incorrect password.")
        except ValueError as e:
            self.send_response(422)
            self.send_header("Content-Type", "text/plain")
            self.end_headers_with_cors()
            self.wfile.write(str(e).encode("utf-8"))
        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers_with_cors()
            self.wfile.write(f"Server error: {e}".encode("utf-8"))

def run():
    server_address = ("127.0.0.1", PORT)
    httpd = HTTPServer(server_address, FileCryptHandler)
    print("\n=======================================================")
    print(f"   FileCrypt Server (Python) is ready!")
    print(f"   URL: http://127.0.0.1:{PORT}")
    print(f"   Serving files from: {PUBLIC_DIR}")
    print("   Press Ctrl+C to stop.")
    print("=======================================================\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.server_close()

if __name__ == "__main__":
    run()
