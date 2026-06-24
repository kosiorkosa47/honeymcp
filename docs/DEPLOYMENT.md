# Deploying honeymcp

> **Safety note:** honeymcp is a honeypot. It is intentionally attractive to attackers and will accept and store arbitrary request payloads. Run it on a **dedicated VPS** — never on shared infra, a developer laptop you care about, or anything that has credentials for your real systems. See [`SECURITY.md`](../SECURITY.md) for the full operational-safety guidance and the legal note on responsible use.

## Prerequisites

- A VPS you control (any Linux distro with Docker support: Debian 12, Ubuntu 22.04/24.04, etc.)
- **Docker Engine** 24+ and the Compose v2 plugin (`docker compose`)
- A domain name (optional, but recommended if you want HTTPS)
- Outbound firewall egress (most clouds default-allow; no extra config needed)

## Deploy to a VPS in 5 minutes

```bash
# 1. SSH to your VPS
ssh you@your-vps.example.com

# 2. Clone and enter the repo
git clone https://github.com/kosiorkosa47/honeymcp.git
cd honeymcp

# 3. Bring it up
docker compose up -d

# 4. Confirm it's listening
curl -s http://127.0.0.1:8080/healthz
# → ok

# 5. Inspect captured events as they arrive
docker exec -it honeymcp sqlite3 /var/lib/honeymcp/hive.db \
    'SELECT timestamp_ms, remote_addr, user_agent, method FROM events ORDER BY id DESC LIMIT 20;'
```

Captured data lives in `./data/hive.db` (SQLite) and `./data/hive.jsonl` (append-only log) on the host — both survive container restarts.

### Swapping persona

The compose file mounts `./personas` read-only. Edit the `CMD` in the Dockerfile, or override at runtime:

```yaml
# docker-compose.override.yml
services:
  honeymcp:
    command:
      - --transport=http
      - --http-addr=0.0.0.0:8080
      - --persona=/opt/honeymcp/personas/postgres-admin.yaml
      - --db=/var/lib/honeymcp/hive.db
      - --jsonl=/var/lib/honeymcp/hive.jsonl
```

Then `docker compose up -d --force-recreate`. Keep the compose port publish
bound to `127.0.0.1:8080`; Caddy is the only internet-facing entry point.

## Putting it on the internet

The container publishes `127.0.0.1:8080` on the host. To expose the honeypot
on port 80/443, put [Caddy](https://caddyserver.com/) in front of it and keep
operator endpoints behind Basic Auth.

### `/etc/caddy/Caddyfile`

```
{
    servers {
        trusted_proxies static private_ranges
    }
}

honeymcp.example.com {
    @operator path /dashboard /dashboard/* /stats /healthz /version
    basic_auth @operator {
        import /etc/honeymcp/dashboard-basic-auth
    }

    reverse_proxy 127.0.0.1:8080

    log {
        output file /var/log/caddy/honeymcp.log
        format json
    }
}
```

Install Caddy (Debian/Ubuntu):

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
  | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
  | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install -y caddy
sudo systemctl reload caddy
```

Caddy provisions a Let's Encrypt certificate for `honeymcp.example.com`
automatically on first request. Keep the Basic Auth hash outside git:

```bash
sudo install -d -m 0755 /etc/honeymcp
caddy hash-password
# paste the hash, not the plaintext password:
echo 'admin <hash>' | sudo tee /etc/honeymcp/dashboard-basic-auth >/dev/null
sudo chmod 0640 /etc/honeymcp/dashboard-basic-auth
sudo chown root:caddy /etc/honeymcp/dashboard-basic-auth
```

### Firewall / `ufw`

Assuming ufw is your firewall, allow SSH plus HTTP/HTTPS for Caddy. Do not
allow direct access to 8080; the backend is loopback-only and should stay
reachable only through Caddy.

```bash
sudo ufw allow 22/tcp     # SSH
sudo ufw allow 80/tcp     # Caddy ACME challenge
sudo ufw allow 443/tcp    # HTTPS
sudo ufw enable
```

### `iptables` equivalent

```bash
sudo iptables -A INPUT -p tcp --dport 80  -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 ! -i lo -j DROP
```

### Block container access to IMDS

The honeypot container should not be able to reach cloud instance metadata
services. Install the versioned unit from `deploy/`:

```bash
sudo cp deploy/honeymcp-imds-block.sh /usr/local/sbin/honeymcp-imds-block.sh
sudo chmod 0755 /usr/local/sbin/honeymcp-imds-block.sh
sudo cp deploy/honeymcp-imds-block.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now honeymcp-imds-block.service

docker exec honeymcp curl -sS --connect-timeout 2 --max-time 3 \
  http://169.254.169.254/latest/meta-data/
# expected: connection timeout / no response
```

## Making the honeypot discoverable

To actually collect intel you need traffic. Options:

- Announce the endpoint as an MCP server in places attackers crawl (registries, GitHub READMEs, public directories). Use a persona and server name that matches something plausible.
- Publish on a subdomain of an organization name that suggests an attractive target (internal-api.acme-corp.example, etc.).
- Cross-link from decoy repos. Use with intent and **do not impersonate real organizations you don't control**.

## Observability

```bash
# Live container logs (tracing goes to stderr)
docker compose logs -f

# Event count, by method
docker exec honeymcp sqlite3 /var/lib/honeymcp/hive.db \
    'SELECT method, COUNT(*) FROM events GROUP BY method ORDER BY 2 DESC;'

# Most-active attacker IPs
docker exec honeymcp sqlite3 /var/lib/honeymcp/hive.db \
    "SELECT remote_addr, COUNT(*) FROM events GROUP BY remote_addr ORDER BY 2 DESC LIMIT 20;"

# Tail the JSONL stream through jq
tail -f ./data/hive.jsonl | jq 'select(.method=="tools/call")'
```

## Updating

```bash
cd honeymcp
git pull
docker compose build --pull
docker compose up -d
```

SQLite migrations are applied automatically on startup (see [`src/logger/mod.rs`](../src/logger/mod.rs) — `ALTER TABLE ... ADD COLUMN` only runs for columns that are missing, so existing data is preserved).

## Legal

Running a honeypot on infrastructure you do not control or have explicit authorization for may violate computer-misuse laws in your jurisdiction. **You are responsible for compliance.** See [`SECURITY.md`](../SECURITY.md) for more.
