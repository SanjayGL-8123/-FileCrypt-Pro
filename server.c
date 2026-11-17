/*
 * server.c - Cross-platform C Back end for FileCrypt
 *
 * Supports Windows (Winsock2) and Linux / macOS (POSIX sockets).
 *
 * Compilation:
 *   Windows (GCC/MinGW):  gcc -Wall -Wextra -O2 -o filecrypt-server.exe server.c -lws2_32
 *   Windows (MSVC):       cl /O2 /Fe:filecrypt-server.exe server.c ws2_32.lib
 *   Linux / macOS:        gcc -Wall -Wextra -O2 -o filecrypt-server server.c
 *
 * NOTE: If no C compiler is installed on Windows, run with zero setup:
 *   node server.js   (Recommended)
 *   python server.py (Alternative)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>

#if defined(_WIN32) || defined(_WIN64)
    #define PLATFORM_WINDOWS 1
    #ifndef _WIN32_WINNT
        #define _WIN32_WINNT 0x0600
    #endif
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <io.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef SOCKET socket_t;
    #define CLOSE_SOCKET(s) closesocket(s)
    #define IS_INVALID_SOCKET(s) ((s) == INVALID_SOCKET)
    #define SEND_FLAGS 0
    #define strncasecmp _strnicmp
#else
    #define PLATFORM_WINDOWS 0
    #define _GNU_SOURCE
    #include <unistd.h>
    #include <strings.h>
    #include <sys/socket.h>
    #include <sys/time.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    typedef int socket_t;
    #define CLOSE_SOCKET(s) close(s)
    #define IS_INVALID_SOCKET(s) ((s) < 0)
    #if defined(MSG_NOSIGNAL)
        #define SEND_FLAGS MSG_NOSIGNAL
    #else
        #define SEND_FLAGS 0
    #endif
#endif

#define PORT_DEFAULT 8080
#define MAX_UPLOAD   (100ULL * 1024 * 1024)
#define HDR_CAP      16384
#define IO_BUF       65536
#define MAGIC        "FENC"
#define MAGIC_LEN    4
#define SALT_LEN     8
#define CHECK_LEN    4
#define ROUNDS       100000

enum { RC_OK = 0, RC_IO, RC_FORMAT, RC_BADPW };

/* ================= Crypto Core ================= */

static uint64_t fnv1a(uint64_t h, const unsigned char *d, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        h ^= d[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static uint64_t derive_key(const char *pw, const unsigned char *salt)
{
    uint64_t h = 14695981039346656037ULL;
    size_t pw_len = strlen(pw);
    for (int i = 0; i < ROUNDS; i++) {
        h = fnv1a(h, (const unsigned char *)pw, pw_len);
        h = fnv1a(h, salt, SALT_LEN);
    }
    return h ? h : 0x9E3779B97F4A7C15ULL;
}

static unsigned char next_byte(uint64_t *s)
{
    *s ^= *s >> 12;
    *s ^= *s << 25;
    *s ^= *s >> 27;
    return (unsigned char)((*s * 2685821657736338717ULL) >> 56);
}

static uint32_t password_check(uint64_t key)
{
    uint64_t s = key ^ 0xA5A5A5A5A5A5A5A5ULL;
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        v = (v << 8) | next_byte(&s);
    }
    return v;
}

static void random_salt(unsigned char *salt)
{
#if PLATFORM_WINDOWS
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        if (CryptGenRandom(hProv, SALT_LEN, salt)) {
            CryptReleaseContext(hProv, 0);
            return;
        }
        CryptReleaseContext(hProv, 0);
    }
    srand((unsigned)(time(NULL) ^ clock()));
    for (int i = 0; i < SALT_LEN; i++) {
        salt[i] = (unsigned char)(rand() & 0xFF);
    }
#else
    FILE *r = fopen("/dev/urandom", "rb");
    if (r) {
        size_t n = fread(salt, 1, SALT_LEN, r);
        fclose(r);
        if (n == SALT_LEN) return;
    }
    srand((unsigned)(time(NULL) ^ clock()));
    for (int i = 0; i < SALT_LEN; i++) {
        salt[i] = (unsigned char)(rand() & 0xFF);
    }
#endif
}

static int stream_xor(FILE *in, FILE *out, uint64_t key)
{
    static unsigned char buf[IO_BUF];
    uint64_t s = key;
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        for (size_t i = 0; i < n; i++) {
            buf[i] ^= next_byte(&s);
        }
        if (fwrite(buf, 1, n, out) != n) return 0;
    }
    return !ferror(in);
}

static int encrypt_stream(FILE *in, FILE *out, const char *pw)
{
    unsigned char salt[SALT_LEN];
    random_salt(salt);
    uint64_t key = derive_key(pw, salt);
    uint32_t c = password_check(key);
    unsigned char cb[CHECK_LEN] = {
        (unsigned char)(c >> 24),
        (unsigned char)(c >> 16),
        (unsigned char)(c >> 8),
        (unsigned char)c
    };

    if (fwrite(MAGIC, 1, MAGIC_LEN, out) != MAGIC_LEN ||
        fwrite(salt, 1, SALT_LEN, out) != SALT_LEN ||
        fwrite(cb, 1, CHECK_LEN, out) != CHECK_LEN) {
        return RC_IO;
    }
    return stream_xor(in, out, key) ? RC_OK : RC_IO;
}

static int decrypt_stream(FILE *in, FILE *out, const char *pw)
{
    unsigned char magic[MAGIC_LEN], salt[SALT_LEN], cb[CHECK_LEN];
    if (fread(magic, 1, MAGIC_LEN, in) != MAGIC_LEN ||
        memcmp(magic, MAGIC, MAGIC_LEN) != 0 ||
        fread(salt, 1, SALT_LEN, in) != SALT_LEN ||
        fread(cb, 1, CHECK_LEN, in) != CHECK_LEN) {
        return RC_FORMAT;
    }
    uint64_t key = derive_key(pw, salt);
    uint32_t stored = ((uint32_t)cb[0] << 24) | ((uint32_t)cb[1] << 16) |
                      ((uint32_t)cb[2] << 8)  | cb[3];
    if (password_check(key) != stored) return RC_BADPW;
    return stream_xor(in, out, key) ? RC_OK : RC_IO;
}

/* ================= HTTP Helpers ================= */

static int send_all(socket_t fd, const void *p, size_t n)
{
    const char *c = (const char *)p;
    while (n > 0) {
        int to_send = (n > 65536) ? 65536 : (int)n;
        int w = send(fd, c, to_send, SEND_FLAGS);
        if (w <= 0) return 0;
        c += w;
        n -= (size_t)w;
    }
    return 1;
}

static void send_text(socket_t fd, int code, const char *reason, const char *msg)
{
    char h[512];
    size_t ml = strlen(msg);
    int n = snprintf(h, sizeof(h),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Connection: close\r\n\r\n", code, reason, ml);
    send_all(fd, h, (size_t)n);
    if (ml > 0) send_all(fd, msg, ml);
}

static void send_file(socket_t fd, FILE *f, const char *ctype)
{
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    char h[512];
    int n = snprintf(h, sizeof(h),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n", ctype, size);
    if (!send_all(fd, h, (size_t)n)) return;

    static char buf[IO_BUF];
    size_t r;
    while ((r = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (!send_all(fd, buf, r)) return;
    }
}

static int get_header(const char *hdrs, const char *name, char *out, size_t sz)
{
    size_t nl = strlen(name);
    const char *p = strstr(hdrs, "\r\n");
    while (p) {
        p += 2;
        if (strncasecmp(p, name, nl) == 0 && p[nl] == ':') {
            p += nl + 1;
            while (*p == ' ' || *p == '\t') p++;
            size_t i = 0;
            while (*p && *p != '\r' && *p != '\n' && i < sz - 1) {
                out[i++] = *p++;
            }
            out[i] = '\0';
            return 1;
        }
        p = strstr(p, "\r\n");
    }
    return 0;
}

static void url_decode(char *s)
{
    char *o = s;
    while (*s) {
        if (*s == '%' && isxdigit((unsigned char)s[1]) && isxdigit((unsigned char)s[2])) {
            char h[3] = { s[1], s[2], 0 };
            *o++ = (char)strtol(h, NULL, 16);
            s += 3;
        } else if (*s == '+') {
            *o++ = ' ';
            s++;
        } else {
            *o++ = *s++;
        }
    }
    *o = '\0';
}

static const struct { const char *url, *file, *type; } routes[] = {
    { "/",           "public/index.html", "text/html; charset=utf-8" },
    { "/index.html", "public/index.html", "text/html; charset=utf-8" },
    { "/style.css",  "public/style.css",  "text/css; charset=utf-8" },
    { "/app.js",     "public/app.js",     "application/javascript; charset=utf-8" },
};

static void serve_static(socket_t fd, const char *path)
{
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        if (strcmp(path, routes[i].url) == 0) {
            FILE *f = fopen(routes[i].file, "rb");
            if (!f) {
                char alt[128];
                snprintf(alt, sizeof(alt), "filecrypt-web/%s", routes[i].file);
                f = fopen(alt, "rb");
            }
            if (!f) {
                send_text(fd, 500, "Internal Server Error", "Missing static file in public/ directory.");
                return;
            }
            send_file(fd, f, routes[i].type);
            fclose(f);
            return;
        }
    }
    send_text(fd, 404, "Not Found", "Resource not found.");
}

/* ================= Client Request Handler ================= */

static void handle_client(socket_t fd)
{
#if PLATFORM_WINDOWS
    DWORD tv = 30000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
#else
    struct timeval tv = { 30, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    char buf[HDR_CAP + 1];
    size_t n = 0;
    char *end = NULL;

    while (!end && n < HDR_CAP) {
        int r = recv(fd, buf + n, (int)(HDR_CAP - n), 0);
        if (r <= 0) return;
        n += (size_t)r;
        buf[n] = '\0';
        end = strstr(buf, "\r\n\r\n");
    }
    if (!end) {
        send_text(fd, 431, "Header Too Large", "HTTP headers exceed capacity.");
        return;
    }

    char *body = end + 4;
    size_t have = n - (size_t)(body - buf);
    *end = '\0';

    char method[16], path[256];
    if (sscanf(buf, "%15s %255s", method, path) != 2) {
        send_text(fd, 400, "Bad Request", "Malformed request line.");
        return;
    }
    char *q = strchr(path, '?');
    if (q) *q = '\0';

    if (strcmp(method, "OPTIONS") == 0) {
        send_text(fd, 204, "No Content", "");
        return;
    }

    if (strcmp(path, "/api/health") == 0) {
        send_text(fd, 200, "OK", "{\"status\":\"ok\",\"backend\":\"c\"}");
        return;
    }

    if (strcmp(method, "GET") == 0) {
        serve_static(fd, path);
        return;
    }

    int enc = (strcmp(path, "/api/encrypt") == 0);
    int dec = (strcmp(path, "/api/decrypt") == 0);
    if (strcmp(method, "POST") != 0 || (!enc && !dec)) {
        send_text(fd, 404, "Not Found", "Endpoint not found.");
        return;
    }

    char tmp[64], pw[512];
    if (!get_header(buf, "Content-Length", tmp, sizeof(tmp))) {
        send_text(fd, 411, "Length Required", "Content-Length header is required.");
        return;
    }
    unsigned long long len = strtoull(tmp, NULL, 10);
    if (len > MAX_UPLOAD) {
        send_text(fd, 413, "Payload Too Large", "File exceeds 100 MB limit.");
        return;
    }
    if (len == 0) {
        send_text(fd, 400, "Bad Request", "The upload file is empty.");
        return;
    }
    if (!get_header(buf, "X-Password", pw, sizeof(pw)) || !*pw) {
        send_text(fd, 400, "Bad Request", "X-Password header is required.");
        return;
    }
    url_decode(pw);

    FILE *in = tmpfile();
    FILE *out = tmpfile();
    if (!in || !out) {
        send_text(fd, 500, "Internal Server Error", "Could not allocate temporary storage.");
        goto cleanup;
    }

    if (have > len) have = (size_t)len;
    if (have && fwrite(body, 1, have, in) != have) goto io_error;

    unsigned long long left = len - have;
    static char chunk[IO_BUF];
    while (left > 0) {
        size_t want = left < sizeof(chunk) ? (size_t)left : sizeof(chunk);
        int r = recv(fd, chunk, (int)want, 0);
        if (r <= 0) {
            send_text(fd, 400, "Bad Request", "Upload interrupted.");
            goto cleanup;
        }
        if (fwrite(chunk, 1, (size_t)r, in) != (size_t)r) goto io_error;
        left -= (unsigned long long)r;
    }
    fflush(in);
    rewind(in);

    int rc = enc ? encrypt_stream(in, out, pw) : decrypt_stream(in, out, pw);
    switch (rc) {
    case RC_OK:
        fflush(out);
        send_file(fd, out, "application/octet-stream");
        fprintf(stdout, "[%s] Processed %llu bytes successfully\n", enc ? "Encrypt" : "Decrypt", len);
        break;
    case RC_FORMAT:
        send_text(fd, 422, "Unprocessable Entity", "This is not a valid FileCrypt encrypted file.");
        break;
    case RC_BADPW:
        send_text(fd, 401, "Unauthorized", "Incorrect password.");
        break;
    default:
        goto io_error;
    }
    goto cleanup;

io_error:
    send_text(fd, 500, "Internal Server Error", "File I/O error on server.");
cleanup:
    if (in)  fclose(in);
    if (out) fclose(out);
}

int main(int argc, char *argv[])
{
    int port = argc > 1 ? atoi(argv[1]) : PORT_DEFAULT;
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port specified.\n");
        return 1;
    }

#if PLATFORM_WINDOWS
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    socket_t srv = socket(AF_INET, SOCK_STREAM, 0);
    if (IS_INVALID_SOCKET(srv)) {
        perror("socket");
        return 1;
    }

    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons((uint16_t)port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        CLOSE_SOCKET(srv);
#if PLATFORM_WINDOWS
        WSACleanup();
#endif
        return 1;
    }

    if (listen(srv, 16) != 0) {
        perror("listen");
        CLOSE_SOCKET(srv);
#if PLATFORM_WINDOWS
        WSACleanup();
#endif
        return 1;
    }

    printf("\n=======================================================\n");
    printf("   FileCrypt Server running at: http://127.0.0.1:%d\n", port);
    printf("   Press Ctrl+C to stop the server\n");
    printf("=======================================================\n\n");

    for (;;) {
        socket_t c = accept(srv, NULL, NULL);
        if (IS_INVALID_SOCKET(c)) continue;
        handle_client(c);
        CLOSE_SOCKET(c);
    }

    CLOSE_SOCKET(srv);
#if PLATFORM_WINDOWS
    WSACleanup();
#endif
    return 0;
}
