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
- Swap (the build needs more than the box's RAM). Example, persisted:
  ```bash
  sudo fallocate -l 6G /swapfile && sudo chmod 600 /swapfile
  sudo mkswap /swapfile && sudo swapon /swapfile
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
  ```
- `canaries.yaml` present in the repo root (gitignored) for real canary tokens.

## Install

```bash
# 1. Canonical script -> installed copy the service runs.
cp deploy/auto-deploy.sh /home/ubuntu/honeymcp-autodeploy.sh
chmod +x /home/ubuntu/honeymcp-autodeploy.sh

# 2. systemd units.
sudo cp deploy/honeymcp-deploy.service deploy/honeymcp-deploy.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now honeymcp-deploy.timer
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

After changing `auto-deploy.sh` in the repo, re-copy it to
`/home/ubuntu/honeymcp-autodeploy.sh` (the service runs the installed copy, not
the in-repo file, so a mid-deploy `git reset` can't rewrite the running script).
