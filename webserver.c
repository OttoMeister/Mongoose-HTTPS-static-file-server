/*
webserver.c  –  Mongoose HTTPS static-file server

Compile and run:
sudo -u webserver gcc /home/webserver/mongoose/webserver.c /home/webserver/mongoose/mongoose.c -I/home/webserver/mongoose -DMG_TLS=MG_TLS_OPENSSL -DMG_MAX_RECV_BUF_SIZE=1048576 -lssl -lcrypto -O2 -o /home/webserver/mongoose/mongoose-server && sudo setcap CAP_NET_BIND_SERVICE=+eip /home/webserver/mongoose/mongoose-server && sudo -u webserver /home/webserver/mongoose/mongoose-server -c /etc/letsencrypt/live/xxxx.xxxx.xxxx.dev/fullchain.pem -k /etc/letsencrypt/live/xxxx.xxxx.xxxx.dev/privkey.pem -d /home/webserver/mongoose/web_root/ -f /home/webserver/mongoose/passwd  -l https://0.0.0.0:443  -v 3
Set password for user admin:
echo admin | python3 -c "import sys,getpass,hashlib,os;u=sys.stdin.read().strip();p=getpass.getpass();s=os.urandom(32);print(f'{u}:{s.hex()}:{hashlib.pbkdf2_hmac(\"sha256\",p.encode(),s,10**5,64).hex()}')" >> /home/webserver/mongoose/passwd
*/

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include "mongoose.h"

#define MAX_USERS          8
#define MAX_LOGIN_ATTEMPTS 5
#define LOGIN_WINDOW       60
#define TOKEN_BYTES        32
#define MAX_SESSIONS       128
#define MAX_SESSION_AGE    86400
#define PBKDF2_ITER        100000
#define HASH_LEN           64
#define SALT_LEN           32
#define BIND_SESSION_TO_IP 1

static int         s_signo;
static int         s_debug      = MG_LL_INFO;
static const char *s_root       = ".";
static const char *s_addr       = "https://0.0.0.0:443";
static const char *s_crt_path, *s_key_path, *s_passwd_path;
static struct mg_str s_crt, s_key;
struct user { char name[64]; unsigned char hash[HASH_LEN]; unsigned char salt[SALT_LEN]; };
static struct user  s_users[MAX_USERS];
static int          s_nusers;
struct limit  { char key[64]; int cnt; time_t t; };
static struct limit s_lim[64];
struct session { char tok[65]; char user[64]; time_t created;
#if BIND_SESSION_TO_IP
char ip[48];
#endif
};

static struct session s_sessions[MAX_SESSIONS];
static void sig(int s) { s_signo = s; }
static const char *get_key(struct mg_connection *c) {
    static char buf[64];
    mg_snprintf(buf, sizeof(buf), "%M", mg_print_ip, &c->rem);
    return buf;
}

static int do_pbkdf2(const char *pass, const unsigned char *salt, unsigned char *out) {
    return PKCS5_PBKDF2_HMAC(pass, (int)strlen(pass), salt, SALT_LEN, PBKDF2_ITER, EVP_sha256(), HASH_LEN, out) == 1;
}

static int rate_limit(const char *key) {
    time_t now = time(NULL);
    struct limit *l = NULL;
    for (int i = 0; i < 64; i++) if (s_lim[i].key[0] && !strcmp(s_lim[i].key, key)) { l = &s_lim[i]; break; }
    if (!l) for (int i = 0; i < 64; i++) if (!s_lim[i].key[0]) { l = &s_lim[i]; break; }
    if (!l) { int oi = 0; for (int i = 1; i < 64; i++) if (s_lim[i].t < s_lim[oi].t) oi = i; l = &s_lim[oi]; }
    strncpy(l->key, key, 63); l->key[63] = '\0';
    if (now - l->t > LOGIN_WINDOW) { l->cnt = 0; l->t = now; }
    return ++l->cnt > MAX_LOGIN_ATTEMPTS;
}

static int hex2bin(const char *hex, unsigned char *bin, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned int b = 0;
        if (sscanf(hex + i * 2, "%02x", &b) != 1) return 0;
        bin[i] = (unsigned char)b;
    }
    return 1;
}


static void load_passwd(const char *path) {
    // PBKDF2-SHA256, 100 000 Iterationen, 32 Byte Salt, 64 Byte Key.
    FILE *f = fopen(path, "r");
    if (!f) { MG_ERROR(("Cannot read passwd file: %s", path)); exit(EXIT_FAILURE); }
    char line[320];
    while (fgets(line, sizeof(line), f)) {
        size_t ll = strlen(line);
        if (ll == sizeof(line) - 1 && line[ll - 1] != '\n') {
            MG_ERROR(("Line too long in passwd, skipped"));
            int ch; while ((ch = fgetc(f)) != '\n' && ch != EOF);
            OPENSSL_cleanse(line, sizeof(line)); continue;
        }
        line[strcspn(line, "\r\n")] = '\0';
        if (!line[0] || line[0] == '#') continue;
        if (s_nusers >= MAX_USERS) { MG_ERROR(("Maximum users reached")); break; }
        char *p1 = strchr(line, ':');
        if (!p1 || p1 == line) { MG_ERROR(("Invalid entry (missing first colon)")); OPENSSL_cleanse(line, sizeof(line)); continue; }
        *p1 = '\0';
        char *hex_salt = p1 + 1;
        char *p2 = strchr(hex_salt, ':');
        if (!p2) { MG_ERROR(("Invalid entry (missing second colon)")); OPENSSL_cleanse(line, sizeof(line)); continue; }
        *p2 = '\0';
        char *hex_hash = p2 + 1;
        if (strlen(line)     >= 64)           { MG_ERROR(("Username too long: %s",   line)); OPENSSL_cleanse(line, sizeof(line)); continue; }
        if (strlen(hex_salt) != SALT_LEN * 2) { MG_ERROR(("Bad salt length for: %s", line)); OPENSSL_cleanse(line, sizeof(line)); continue; }
        if (strlen(hex_hash) != HASH_LEN * 2) { MG_ERROR(("Bad hash length for: %s", line)); OPENSSL_cleanse(line, sizeof(line)); continue; }
        struct user *u = &s_users[s_nusers];
        strncpy(u->name, line, 63); u->name[63] = '\0';
        if (!hex2bin(hex_salt, u->salt, SALT_LEN)) { MG_ERROR(("Hex decode failed (salt): %s", u->name)); OPENSSL_cleanse(line, sizeof(line)); continue; }
        if (!hex2bin(hex_hash, u->hash, HASH_LEN)) { MG_ERROR(("Hex decode failed (hash): %s", u->name)); OPENSSL_cleanse(line, sizeof(line)); continue; }
        s_nusers++;
    }
    fclose(f);
    OPENSSL_cleanse(line, sizeof(line));
    if (s_nusers == 0) { MG_ERROR(("No users loaded")); exit(EXIT_FAILURE); }
    MG_INFO(("%d users loaded from %s", s_nusers, path));
}

static const char *api_hdrs(void) {
    return "Content-Type: application/json\r\nCache-Control: no-cache\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'none'\r\n";
}

static const char *web_hdrs(void) {
    return "Cache-Control: no-cache, no-store, must-revalidate\r\nPragma: no-cache\r\nExpires: 0\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; frame-ancestors 'none'\r\n";
}

static void json_escape(char *dst, size_t dst_sz, const char *src) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 2 < dst_sz; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') { if (j + 3 > dst_sz) break; dst[j++] = '\\'; dst[j++] = c; }
        else if (c < 0x20) { if (j + 7 > dst_sz) break; snprintf(dst + j, dst_sz - j, "\\u%04x", c); j += 6; }
        else { dst[j++] = c; }
    }
    dst[j] = '\0';
}

static int parse_cookie(struct mg_str *cv, const char *name, char *out, size_t out_sz) {
    if (!cv || !cv->buf || cv->len == 0) return 0;
    const char *s = cv->buf, *end = s + cv->len;
    size_t name_len = strlen(name);
    while (s < end) {
        while (s < end && (*s == ' ' || *s == ';' || *s == '\t')) s++;
        if (s >= end) break;
        if (s + name_len < end && strncmp(s, name, name_len) == 0 && s[name_len] == '=') {
            s += name_len + 1;
            const char *e = s;
            while (e < end && *e != ';' && *e != ' ' && *e != '\t') e++;
            size_t l = (size_t)(e - s);
            if (l >= out_sz) l = out_sz - 1;
            memcpy(out, s, l); out[l] = '\0';
            return 1;
        }
        while (s < end && *s != ';') s++;
    }
    return 0;
}

static struct session *alloc_session(void) {
    time_t now = time(NULL);
    for (int i = 0; i < MAX_SESSIONS; i++) if (!s_sessions[i].tok[0]) return &s_sessions[i];
    for (int i = 0; i < MAX_SESSIONS; i++) if (now - s_sessions[i].created > MAX_SESSION_AGE) return &s_sessions[i];
    int oi = 0; for (int i = 1; i < MAX_SESSIONS; i++) if (s_sessions[i].created < s_sessions[oi].created) oi = i;
    MG_INFO(("Session table full – evicting: user=%s", s_sessions[oi].user));
    return &s_sessions[oi];
}

static struct user *auth(struct mg_connection *c, struct mg_http_message *hm) {
    char u[64] = {0}, p[64] = {0};
    mg_http_creds(hm, u, sizeof(u), p, sizeof(p));
    if (u[0] && p[0]) {
        const char *ip = get_key(c);
        if (rate_limit(ip)) {
            MG_INFO(("Rate-Limit (PBKDF2 blocked): ip=%s", ip));
            return NULL;
        }
    }
    if (u[0] && p[0]) {
        for (int i = 0; i < s_nusers; i++) {
            if (strcmp(u, s_users[i].name) != 0) continue;
            unsigned char h[HASH_LEN];
            if (!do_pbkdf2(p, s_users[i].salt, h)) return NULL;
            if (CRYPTO_memcmp(h, s_users[i].hash, HASH_LEN) == 0) return &s_users[i];
            return NULL;
        }
        return NULL;
    }
    struct mg_str *cv = mg_http_get_header(hm, "Cookie");
    char t[65] = {0};
    if (!parse_cookie(cv, "access_token", t, sizeof(t))) return NULL;
    time_t now = time(NULL);
    const char *ip = get_key(c);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!s_sessions[i].tok[0] || strcmp(s_sessions[i].tok, t) != 0) continue;
        if (now - s_sessions[i].created > MAX_SESSION_AGE) { MG_INFO(("Session expired: user=%s", s_sessions[i].user));
          memset(&s_sessions[i], 0, sizeof(s_sessions[i])); return NULL; }
#if BIND_SESSION_TO_IP
        if (strcmp(s_sessions[i].ip, ip) != 0) { MG_INFO(("Session IP mismatch: user=%s", s_sessions[i].user)); return NULL; }
#endif
        for (int j = 0; j < s_nusers; j++) if (strcmp(s_users[j].name, s_sessions[i].user) == 0) return &s_users[j];
    }
    return NULL;
}

static void cb(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_ACCEPT && c->is_tls) { struct mg_tls_opts opts = {.cert = s_crt, .key = s_key}; mg_tls_init(c, &opts); return; }
    if (ev != MG_EV_HTTP_MSG) return;
    struct mg_http_message *hm = (struct mg_http_message *)ev_data;
    const char *ip = get_key(c);
    if (mg_match(hm->uri, mg_str("/api/login"), NULL)) {
        char u_name[64] = {0}, p_pass[64] = {0};
        mg_http_creds(hm, u_name, sizeof(u_name), p_pass, sizeof(p_pass));
        int has_creds = (u_name[0] && p_pass[0]);
        if (has_creds && rate_limit(ip)) { MG_INFO(("Rate-Limit: ip=%s", ip));
          mg_http_reply(c, 429, api_hdrs(), "{\"error\":\"Too many attempts\"}\n"); return; }
        struct user *u = auth(c, hm);
        if (u) {
            char hdrs[1024], safe_user[128];
            json_escape(safe_user, sizeof(safe_user), u->name);
            if (has_creds) {
                unsigned char r[TOKEN_BYTES]; mg_random(r, sizeof(r)); char tok[65] = {0};
                for (int j = 0; j < TOKEN_BYTES; j++) snprintf(tok + j*2, 3, "%02x", r[j]);
                struct session *s = alloc_session();
                memset(s, 0, sizeof(*s));
                memcpy(s->tok, tok, 64);
                strncpy(s->user, u->name, 63);
                s->created = time(NULL);
#if BIND_SESSION_TO_IP
                strncpy(s->ip, ip, sizeof(s->ip)-1); s->ip[sizeof(s->ip)-1] = '\0';
#endif
                snprintf(hdrs, sizeof(hdrs), "%sSet-Cookie: access_token=%s; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=%d\r\n", api_hdrs(), tok, MAX_SESSION_AGE);
                MG_INFO(("Login OK: user=%s ip=%s", u->name, ip));
            } else { snprintf(hdrs, sizeof(hdrs), "%s", api_hdrs()); }
            mg_http_reply(c, 200, hdrs, "{\"user\":\"%s\"}\n", safe_user);
        } else { MG_INFO(("Login FAIL: user=%s ip=%s", u_name[0] ? u_name : "(empty)", ip)); mg_http_reply(c, 401, api_hdrs(), "{\"error\":\"Unauthorized\"}\n"); }
        return;
    }
    if (mg_match(hm->uri, mg_str("/api/logout"), NULL)) {
        struct mg_str *cv = mg_http_get_header(hm, "Cookie");
        char t[65] = {0};
        if (parse_cookie(cv, "access_token", t, sizeof(t))) {
            for (int i = 0; i < MAX_SESSIONS; i++) {
                if (s_sessions[i].tok[0] && strcmp(s_sessions[i].tok, t) == 0) {
                  MG_INFO(("Logout: user=%s ip=%s", s_sessions[i].user, ip));
                  memset(&s_sessions[i], 0, sizeof(s_sessions[i])); break; }
            }
        }
        char hdrs[512];
        snprintf(hdrs, sizeof(hdrs), "%sSet-Cookie: access_token=; Path=/; Secure; HttpOnly; Max-Age=0\r\n", api_hdrs());
        mg_http_reply(c, 200, hdrs, "true\n");
        return;
    }
    if (mg_match(hm->uri, mg_str("/api/#"), NULL)) {
        struct user *u = auth(c, hm);
        MG_INFO(("%.*s %.*s user=%s ip=%s", (int)hm->method.len, hm->method.buf, (int)hm->uri.len, hm->uri.buf, u ? u->name : "(anon)", ip));
        mg_http_reply(c, u ? 200 : 403, api_hdrs(), u ? "{\"status\":\"ok\"}\n" : "{\"error\":\"Forbidden\"}\n");
        return;
    }
    int is_public = (mg_match(hm->uri, mg_str("/login.html"), NULL) || mg_match(hm->uri, mg_str("/login.js"), NULL)
        || mg_match(hm->uri, mg_str("/style.css"), NULL) || mg_match(hm->uri, mg_str("/auth.js"), NULL)
        || mg_match(hm->uri, mg_str("/favicon.ico"), NULL));
    if (!is_public) {
        struct user *u = auth(c, hm);
        if (!u) { MG_INFO(("Auth required: %.*s ip=%s", (int)hm->uri.len, hm->uri.buf, ip));
        mg_http_reply(c, 302, "Location: /login.html\r\nCache-Control: no-cache\r\n", ""); return; }
    }
    MG_INFO(("%.*s %.*s ip=%s", (int)hm->method.len, hm->method.buf, (int)hm->uri.len, hm->uri.buf, ip));
    struct mg_http_serve_opts opts = {.root_dir = s_root, .extra_headers = web_hdrs()};
    mg_http_serve_dir(c, hm, &opts);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: %s -c cert.pem -k key.pem -d root -f passwd [-l addr] [-v 0-4]\n", argv[0]); exit(EXIT_FAILURE); }
    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "-d")) { if (i+1 >= argc)
          { MG_ERROR(("Missing argument for -d")); exit(EXIT_FAILURE); } s_root = argv[++i]; }
        else if (!strcmp(argv[i], "-l")) { if (i+1 >= argc)
          { MG_ERROR(("Missing argument for -l")); exit(EXIT_FAILURE); } s_addr = argv[++i]; }
        else if (!strcmp(argv[i], "-c")) { if (i+1 >= argc)
          { MG_ERROR(("Missing argument for -c")); exit(EXIT_FAILURE); } s_crt_path = argv[++i]; }
        else if (!strcmp(argv[i], "-k")) { if (i+1 >= argc)
          { MG_ERROR(("Missing argument for -k")); exit(EXIT_FAILURE); } s_key_path = argv[++i]; }
        else if (!strcmp(argv[i], "-f")) { if (i+1 >= argc)
          { MG_ERROR(("Missing argument for -f")); exit(EXIT_FAILURE); } s_passwd_path = argv[++i]; }
        else if (!strcmp(argv[i], "-v")) { if (i+1 >= argc)
          { MG_ERROR(("Missing argument for -v")); exit(EXIT_FAILURE); } s_debug = atoi(argv[++i]); }
    }
    if (!s_crt_path || !s_key_path) { MG_ERROR(("FATAL: -c and -k required")); exit(EXIT_FAILURE); }
    if (!s_passwd_path) { MG_ERROR(("FATAL: -f passwd required")); exit(EXIT_FAILURE); }
    load_passwd(s_passwd_path);
    s_crt = mg_file_read(&mg_fs_posix, s_crt_path);
    s_key = mg_file_read(&mg_fs_posix, s_key_path);
    if (!s_crt.len || !s_key.len) { MG_ERROR(("TLS certificate/key missing")); exit(EXIT_FAILURE); }
    MG_INFO(("TLS cert path    : %s", s_crt_path));
    MG_INFO(("TLS key path     : %s", s_key_path));
    MG_INFO(("Cert size        : %lu bytes", (unsigned long)s_crt.len));
    MG_INFO(("Key size         : %lu bytes", (unsigned long)s_key.len));
    MG_INFO(("TLS backend      : OpenSSL (MG_TLS_OPENSSL)"));
    BIO *bio = BIO_new_mem_buf(s_crt.buf, (int)s_crt.len);
    if (bio) {
        X509 *x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (x) {
            BIO *b = BIO_new(BIO_s_mem());
            ASN1_TIME_print(b, X509_get0_notBefore(x));
            char from[64] = {0}; int n = BIO_read(b, from, sizeof(from)-1); from[n>0?n:0] = '\0';
            BIO_reset(b);
            ASN1_TIME_print(b, X509_get0_notAfter(x));
            char to[64] = {0}; n = BIO_read(b, to, sizeof(to)-1); to[n>0?n:0] = '\0';
            BIO_free(b);
            MG_INFO(("Cert valid       : %s -> %s", from, to));
            X509_free(x);
        } else {
            MG_ERROR(("Failed to parse X509 from PEM"));
        }
        BIO_free(bio);
    }
    signal(SIGINT, sig); signal(SIGTERM, sig);
    mg_log_set(s_debug);
    struct mg_mgr mgr; mg_mgr_init(&mgr);
    struct mg_connection *cn = mg_http_listen(&mgr, s_addr, cb, NULL);
    if (!cn) { MG_ERROR(("Listen failed: %s", s_addr)); exit(EXIT_FAILURE); }
    MG_INFO(("Listening on     : %s", s_addr));
    MG_INFO(("Web root         : %s", s_root));
    MG_INFO(("PWD file         : %s", s_passwd_path));
    MG_INFO(("Users            : %d", s_nusers));
    MG_INFO(("Mongoose version : v%s", MG_VERSION));
    MG_INFO(("OpenSSL version  : %s", OpenSSL_version(OPENSSL_VERSION)));
    MG_INFO(("Compiled         : %s %s", __DATE__, __TIME__));
    while (!s_signo) mg_mgr_poll(&mgr, 1000);
    mg_mgr_free(&mgr);
    MG_INFO(("Shutdown"));
    return 0;
}

/*

#!/bin/bash
set -e
WR=~/mongoose/web_root
mkdir -p "$WR"

# ---------- passwd ----------
PASSWD=~/mongoose/passwd
# Keine Klartextpasswörter speichern.
# Einträge erzeugen mit:  
# echo admin | python3 -c "import sys,getpass,hashlib,os;u=sys.stdin.read().strip();p=getpass.getpass();s=os.urandom(32);print(f'{u}:{s.hex()}:{hashlib.pbkdf2_hmac(\"sha256\",p.encode(),s,10**5,64).hex()}')" >> "$PASSWD"
if [ ! -f "$PASSWD" ]; then
    touch "$PASSWD"
    chown webserver:webserver "$PASSWD"
    chmod 600 "$PASSWD"
    echo "# Format: username:hex_salt(64 chars):hex_hash(128 chars)" > "$PASSWD"
    echo "WARNING: Add users with mkpasswd.py before starting the server!"
fi

# ---------- auth.js ----------
cat > "$WR/auth.js" << 'EOF'
(async function () {
  var r = await fetch('/api/login', { credentials: 'include' });
  if (!r.ok) { window.location.href = '/login.html'; return; }
  var d = await r.json();
  var el = document.getElementById('nav-user');
  if (el) el.textContent = d.user;
  var lo = document.getElementById('nav-logout');
  if (lo) lo.addEventListener('click', async function (e) {
    e.preventDefault();
    await fetch('/api/logout', { credentials: 'include' });
    window.location.href = '/login.html';
  });
})();
EOF

# ---------- login.js ----------
cat > "$WR/login.js" << 'EOF'
document.getElementById('btn').addEventListener('click', async function () {
  var u = document.getElementById('u').value;
  var p = document.getElementById('p').value;
  var r = await fetch('/api/login', {
    credentials: 'include',
    headers: { 'Authorization': 'Basic ' + btoa(u + ':' + p) }
  });
  if (r.ok) { window.location.href = '/'; }
  else { document.getElementById('err').style.display = 'block'; }
});
document.getElementById('p').addEventListener('keydown', function (e) {
  if (e.key === 'Enter') document.getElementById('btn').click();
});
EOF

# ---------- login.html  ----------
cat > "$WR/login.html" << 'EOF'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Login</title><link rel="stylesheet" href="style.css"></head>
<body><h1>Login</h1><div class="login-box">
<label>Username<input id="u" type="text" autocomplete="username"></label>
<label>Password<input id="p" type="password" autocomplete="current-password"></label>
<button id="btn">Sign in</button>
<div id="err" class="err" style="display:none">Invalid username or password.</div>
</div>
<script src="login.js"></script></body></html>
EOF

# ---------- index.html ----------
cat > "$WR/index.html" << 'EOF'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Server</title><link rel="stylesheet" href="style.css"></head>
<body><nav><span>Logged in as: <strong id="nav-user"></strong></span>
<a href="#" id="nav-logout">Logout</a></nav>
<h1>Welcome</h1><p>Server running at <strong>xxxx.xxxx.xxxx.dev</strong>.</p>
<ul><li><a href="info.html">System Information</a></li></ul>
<script src="auth.js"></script></body></html>
EOF

# ---------- info.html ----------
cat > "$WR/info.html" << 'EOF'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Info</title><link rel="stylesheet" href="style.css"></head>
<body><nav><span>Logged in as: <strong id="nav-user"></strong></span>
<a href="#" id="nav-logout">Logout</a></nav>
<h1>Info</h1><p>Webserver: Mongoose</p><p>TLS: Let's Encrypt</p>
<a href="index.html">Back</a><script src="auth.js"></script></body></html>
EOF

# ---------- style.css ----------
cat > "$WR/style.css" << 'EOF'
body{font-family:monospace;max-width:800px;margin:2em auto;padding:0 1em}
h1{border-bottom:1px solid #ccc;padding-bottom:0.3em}
a{color:#0066cc}
nav{text-align:right;padding:0.4em 0;border-bottom:1px solid #eee;margin-bottom:1em}
nav a{margin-left:1em}
.login-box{display:flex;flex-direction:column;gap:0.8em;max-width:280px}
.login-box label{display:flex;flex-direction:column;gap:0.2em}
.login-box input{padding:0.4em;font-family:inherit}
.login-box button{padding:0.4em;cursor:pointer}
.err{color:red}
EOF

# ---------- Set web_root permissions ----------
chown -R webserver:webserver "$WR"
find "$WR" -type f -exec chmod 644 {} \;
find "$WR" -type d -exec chmod 755 {} \;
echo "web_root set up at $WR"
*/
