#!/usr/bin/env bash
# honeymcp box auto-deploy. Polled by honeymcp-deploy.timer.
#
# Deploys origin/main ONLY when it has advanced AND every CI check-run on that
# commit is green (no failures, none pending). The CI gate uses the public
# GitHub REST API (no token needed for a public repo). The build happens on the
# box; the ./data volume is preserved across the recreate.
#
# Install: see deploy/README.md. The box runs an installed copy of this script
# at /home/ubuntu/honeymcp-autodeploy.sh — this file is the canonical source.
set -uo pipefail
REPO=/home/ubuntu/honeymcp
SLUG=kosiorkosa47/honeymcp
BRANCH=main
exec 9>/tmp/honeymcp-deploy.lock
flock -n 9 || { echo "$(date -Is) deploy already running, skip"; exit 0; }

cd "$REPO" || exit 1
git fetch --quiet origin "$BRANCH" || { echo "$(date -Is) git fetch failed"; exit 0; }
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse "origin/$BRANCH")
[ "$LOCAL" = "$REMOTE" ] && exit 0

echo "$(date -Is) main advanced ${LOCAL:0:7} -> ${REMOTE:0:7}; checking CI"
verdict=$(curl -fsSL -H 'Accept: application/vnd.github+json' \
  "https://api.github.com/repos/$SLUG/commits/$REMOTE/check-runs?per_page=100" 2>/dev/null \
  | python3 -c '
import sys, json
try: d = json.load(sys.stdin)
except Exception: print("WAIT no-json"); raise SystemExit
runs = d.get("check_runs", [])
if not runs: print("WAIT no-checks"); raise SystemExit
bad = [r["name"] for r in runs if r.get("conclusion") in ("failure","cancelled","timed_out","action_required","startup_failure")]
pending = [r["name"] for r in runs if r.get("status") != "completed"]
if bad: print("SKIP failed: "+", ".join(bad)); raise SystemExit
if pending: print("WAIT pending: "+", ".join(pending)); raise SystemExit
print("DEPLOY")
')
echo "$(date -Is) verdict: $verdict"
[ "${verdict%% *}" = "DEPLOY" ] || exit 0

echo "$(date -Is) deploying ${REMOTE:0:7}"
git reset --hard "origin/$BRANCH" >/dev/null 2>&1
if docker compose build honeymcp >/tmp/honeymcp-deploy-build.log 2>&1 \
   && docker compose up -d --force-recreate honeymcp >/dev/null 2>&1; then
  sleep 6
  if curl -fsS --max-time 5 http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
    echo "$(date -Is) DEPLOYED ${REMOTE:0:7} OK (healthz green)"
  else
    echo "$(date -Is) WARNING ${REMOTE:0:7} deployed but healthz failed"
  fi
else
  echo "$(date -Is) ERROR build/up failed for ${REMOTE:0:7} (see /tmp/honeymcp-deploy-build.log)"
fi
