# Deployment Guide

## Running the Server

### Local development

```bash
cd server
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8765 --reload
```

`--host 0.0.0.0` means listen on all interfaces (so other devices on your network can reach it). `--reload` restarts on code changes.

### Local network (LAN only)

If you want phones / laptops on the same Wi-Fi to access:

1. Find your desktop's LAN IP: `ipconfig` (Windows) / `ifconfig` (macOS/Linux).
   Example: `192.168.1.42`.
2. Start the server with `--host 0.0.0.0`.
3. From the client device's browser, point at `http://192.168.1.42:8765`.
4. Set `VITE_API_URL=http://192.168.1.42:8765` when building the client.

### Internet-accessible (with ngrok)

```bash
# Terminal 1: server
cd server && uvicorn app.main:app --host 127.0.0.1 --port 8765

# Terminal 2: ngrok tunnel
ngrok http 8765
# Note the https://abc-xyz.ngrok-free.app URL

# Build client pointing at the public URL
cd client
VITE_API_URL=https://abc-xyz.ngrok-free.app npm run build
# Now serve dist/ anywhere (or `npx serve dist`)
```

For the WebSocket signaling, ngrok automatically upgrades `https://` to `wss://` — no config needed.

### Production deployment

For a permanent install:

1. Get a domain (e.g. `zerodday.example.com`)
2. DNS A record → your home IP (or use a VPS)
3. Port forward 443 → desktop:8765 if behind NAT
4. Use nginx + certbot for HTTPS:

```nginx
server {
    listen 443 ssl;
    server_name zerodday.example.com;

    ssl_certificate /etc/letsencrypt/live/zerodday.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/zerodday.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400;
    }
}
```

5. Build client with `VITE_API_URL=https://zerodday.example.com`
6. Deploy `client/dist` to any static host (Netlify, Vercel, GitHub Pages, S3, your server)

### Running as a systemd service (Linux desktop)

`/etc/systemd/system/zerodday.service`:

```ini
[Unit]
Description=ZeroDay Blockchain Server
After=network.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/home/youruser/zerodday-system/server
ExecStart=/usr/bin/python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8765
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now zerodday
sudo systemctl status zerodday
```

## Backing Up the Blockchain

The chain is a single SQLite file at `server/data/blockchain.db`. To back up:

```bash
cp server/data/blockchain.db server/data/blockchain.db.backup
```

To validate integrity:

```bash
curl http://localhost:8765/api/chain/stats
# valid: true
```

## Hardening Checklist (production)

- [ ] Lock CORS to your client's origin (`allow_origins=["https://your-client.com"]`)
- [ ] Add rate limiting (slowapi or nginx)
- [ ] Run behind HTTPS (terminate at nginx/cloudflare)
- [ ] Add log rotation
- [ ] Run server as non-root user
- [ ] Set up monitoring (uptime, error rate)
- [ ] Add a TURN server for WebRTC users behind symmetric NATs
- [ ] Database backups (cron job to copy the SQLite file)

## Troubleshooting

**Server won't start: "Address already in use"**
Another process owns port 8765. Find and kill it: `lsof -i :8765` then `kill <PID>`. Or pick a different port.

**Client says "Server unreachable"**
- Is the server actually running? `curl http://localhost:8765/api/health`
- Is `VITE_API_URL` correct in the client?
- Is CORS allowing the origin?

**Two browsers won't connect via WebRTC**
- Both browsers need to reach the signaling server.
- Behind symmetric NAT (some ISPs, corporate networks), STUN alone isn't enough — you need a TURN server. Add to `RTC_CONFIG` in `client/src/lib/peer.js`:
  ```js
  iceServers: [
    { urls: "stun:stun.l.google.com:19302" },
    { urls: "turn:your-turn-server.com:3478", username: "...", credential: "..." }
  ]
  ```

**WebSocket disconnects randomly**
- Check timeouts on any reverse proxy (nginx default is 60s; bump `proxy_read_timeout`).
- Check for cloud LB idle timeouts.

**Browser shows "MITM detected"**
- This is intentional. The peer's identity key from the WebRTC handshake didn't match what's on the blockchain. Either someone is actually MITM-ing, or the user re-registered after you cached their key. Reload to refresh.
