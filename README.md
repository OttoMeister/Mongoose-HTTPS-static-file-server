# Mongoose-HTTPS-static-file-server

```bash
## Mini https Webserver mongoose
# open port 80 and 443 for webserver
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp

## get Let's Encrypt 
sudo apt install  certbot
sudo certbot certonly --standalone -d xxxx.xxxx.xxxx.dev
# Successfully received certificate.
# Certificate is saved at: /etc/letsencrypt/live/xxxx.xxxx.xxxx.dev/fullchain.pem
# Key is saved at:         /etc/letsencrypt/live/xxxx.xxxx.xxxx.dev/privkey.pem

# erstelle webserver user
sudo useradd -m -r webserver
sudo passwd webserver
# set rights
sudo chgrp -R webserver /etc/letsencrypt/live/ /etc/letsencrypt/archive/
sudo chmod -R g+rX      /etc/letsencrypt/live/ /etc/letsencrypt/archive/

# Als webserver-User:
sudo -u webserver -H -s
git clone https://github.com/cesanta/mongoose
cd mongoose
gcc server.c mongoose.c -I. -DMG_TLS=MG_TLS_OPENSSL -lssl -lcrypto -o mongoose-server

# Wieder als root: (port 443 erlauben für server)
sudo setcap CAP_NET_BIND_SERVICE=+eip /home/webserver/mongoose/mongoose-server
# start web server as user webserver
/home/webserver/mongoose/mongoose-server

# test web server on other ip
curl -v https://xxxx.xxxx.xxxx.dev

## Systemd-Service to auto start server
# /etc/systemd/system/mongoose-server.service
[Unit]
Description=Mongoose HTTPS Server
After=network.target
[Service]
User=webserver
ExecStart=/home/webserver/mongoose/mongoose-server
Restart=on-failure
[Install]
WantedBy=multi-user.target
# END mongoose-server.service
# tart service
sudo systemctl enable --now mongoose-server
## Certbot Renewal Hooks 
bashsudo tee /etc/letsencrypt/renewal-hooks/pre/stop.sh  <<'EOF'
#!/bin/sh
systemctl stop mongoose-server
EOF
sudo tee /etc/letsencrypt/renewal-hooks/post/start.sh <<'EOF'
#!/bin/sh
systemctl start mongoose-server
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/pre/stop.sh
sudo chmod +x /etc/letsencrypt/renewal-hooks/post/start.sh
sudo certbot renew --dry-run
```

# minimal source code für mini webserver
server.c
``` c
#include "mongoose.h"
#define PORT     "https://0.0.0.0:443"
#define SSL_CERT "/etc/letsencrypt/live/xxxx.xxxx.xxxx.dev/fullchain.pem"
#define SSL_KEY  "/etc/letsencrypt/live/xxxx.xxxx.xxxx.dev/privkey.pem"
static struct mg_str s_cert, s_key;
static void fn(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_ACCEPT) {
    struct mg_tls_opts opts = {.cert = s_cert, .key = s_key};
    mg_tls_init(c, &opts);
  } else if (ev == MG_EV_HTTP_MSG) {
    mg_http_reply(c, 200, "", "Secure Mongoose connection successful!\n");
  }}
int main(void) {
  s_cert = mg_file_read(&mg_fs_posix, SSL_CERT);
  s_key  = mg_file_read(&mg_fs_posix, SSL_KEY);
  if (s_cert.buf == NULL || s_key.buf == NULL) {
    fprintf(stderr, "Fehler: Zertifikat oder Key nicht lesbar\n");
    return 1;  }
  mg_log_set(4);
  struct mg_mgr mgr;
  mg_mgr_init(&mgr);
  mg_http_listen(&mgr, PORT, fn, NULL);
  printf("Starting HTTPS server on %s\n", PORT);
  for (;;) mg_mgr_poll(&mgr, 1000);
  mg_mgr_free(&mgr);
  return 0; }
```
