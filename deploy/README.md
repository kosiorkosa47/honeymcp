# Box auto-deploy (continuous deployment)

The live honeypot box pulls, rebuilds, and restarts itself whenever `main`
advances **and** every CI check-run on that commit is green. This directory is
the canonical, versioned source of the box-side machinery so it can be restored
if the box is ever rebuilt.

## How it works

A systemd timer polls every 3 minutes and runs `auto-deploy.sh`, which:

1. `git fetch` and compares `HEAD` to `origin/main`. If unchanged, exits.
2. If `main` advanced, queries the public GitHub REST API
   (`/commits/<sha>/check-runs`) for that commit:
   - any failed/cancelled/timed-out check → **skip** (do not deploy),
   - any check still running → **wait** (re-check next cycle),
   - all green → **deploy**.
3. On deploy: `git reset --hard origin/main`, `docker compose build honeymcp`,
   `docker compose up -d --force-recreate honeymcp`, then a `/healthz` check.

`flock` prevents overlapping runs; the `./data` bind mount means the SQLite
event store survives every recreate. The build runs on the box, which needs
swap — see "Prerequisites".

## Prerequisites

- The repo cloned at `/home/ubuntu/honeymcp`, on `main`, tracking `origin/main`.
- Docker Engine + Compose v2, with the `ubuntu` user in the `docker` group.
- Caddy installed on the host, terminating public HTTP/HTTPS and proxying to
  `127.0.0.1:8080`.
- Swap (the build needs more than the box's RAM). Example, persisted:
  ```bash
  sudo fallocate -l 6G /swapfile && sudo chmod 600 /swapfile
  sudo mkswap /swapfile && sudo swapon /swapfile
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
  ```
- `canaries.yaml` present in the repo root (gitignored) for real canary tokens.

## Install

```bash
# 1. Stable wrapper -> versioned script in the checked-out repo.
cat > /home/ubuntu/honeymcp-autodeploy.sh <<'EOF'
#!/bin/sh
set -eu
cd /home/ubuntu/honeymcp
exec ./deploy/auto-deploy.sh
EOF
chmod +x /home/ubuntu/honeymcp-autodeploy.sh

# 2. systemd units.
sudo cp deploy/honeymcp-deploy.service deploy/honeymcp-deploy.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now honeymcp-deploy.timer
```

Bootstrap the one local secret the repo must not carry:

```bash
sudo install -d -m 0755 /etc/honeymcp
caddy hash-password
# paste the hash, not the plaintext password:
echo 'admin <hash>' | sudo tee /etc/honeymcp/dashboard-basic-auth >/dev/null
sudo chmod 0640 /etc/honeymcp/dashboard-basic-auth
sudo chown root:caddy /etc/honeymcp/dashboard-basic-auth
```

Create the operator source allowlist locally on the host. Keep the real address
out of git:

```bash
echo 'remote_ip <operator-ip-or-cidr>' | sudo tee /etc/honeymcp/operator-allowlist >/dev/null
sudo chmod 0640 /etc/honeymcp/operator-allowlist
sudo chown root:caddy /etc/honeymcp/operator-allowlist
```

Install the host-side hardening units as part of a rebuild. The auto-deploy
script also runs this on every successful `main` deploy so the live box
converges back to the versioned host configuration.

```bash
./deploy/apply-host-hardening.sh
```

## Operate

```bash
# Watch deploy cycles live
journalctl -u honeymcp-deploy.service -f

# Next scheduled run
systemctl list-timers honeymcp-deploy.timer

# Pause / resume auto-deploy
sudo systemctl disable --now honeymcp-deploy.timer
sudo systemctl enable  --now honeymcp-deploy.timer

# Force a check now
sudo systemctl start honeymcp-deploy.service
```

`/home/ubuntu/honeymcp-autodeploy.sh` is intentionally only a stable wrapper.
The deploy logic lives in `deploy/auto-deploy.sh`, so changes to deploy
behaviour go through GitHub and are picked up from the checked-out repo.
