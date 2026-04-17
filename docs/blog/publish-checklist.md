# Publish checklist - tomorrow morning

Run in this order, 08:30-11:00 CET.

## 1. Verify infrastructure is healthy (5 min)

```bash
curl -s http://54.169.235.208:8080/healthz
# -> ok

curl -s http://54.169.235.208:8080/stats | jq .
# -> valid JSON, uptime > 12h, events may or may not have grown

open http://54.169.235.208:8080/dashboard
# -> browser loads the terminal-themed dashboard
```

If dashboard or stats is broken, fix first, publish later.

## 2. Publish blog to dev.to (10 min)

1. Log into https://dev.to
2. Click "Write a post"
3. Click "... Switch to preview" three-dots menu -> "Markdown"
4. Paste contents of `docs/blog/day-3-retrospective.md`
5. Title auto-populates from frontmatter
6. Change `published: false` to `published: true` at the top
7. Preview the rendered output. If cover image is missing, leave as-is (dev.to auto-generates).
8. Click "Publish"
9. Copy the published URL (e.g. `https://dev.to/kosiorkosa47/how-i-built-an-mcp-honeypot-in-72-hours-xxx`)

## 3. Update the announce thread with the blog URL (2 min)

Open `docs/blog/announce-thread.md`, replace every occurrence of `<LINK_TO_BLOG>` with the dev.to URL from step 2.

## 4. Post the X thread (5 min)

Target window: 09:00-11:00 CET.

1. Go to the pinned launch tweet: https://x.com/0xAlpha/status/2045109578614935588
2. Click Reply
3. Paste tweet 1/5 from the announce thread
4. Post
5. On the tweet you just posted, click Reply again, paste 2/5, post
6. Repeat for 3/5, 4/5, 5/5

the assistant can drive this via playwright if you prefer — just say "post the announce thread." Reminder: verify each tweet lands on `/with_replies` before the next.

## 5. Pin the new thread (1 min)

On the first tweet (1/5), click kebab -> "Pin to your profile". Confirms the pin slot. Previous pinned launch becomes just history.

## 6. LinkedIn post (3 min)

1. Go to https://linkedin.com
2. "Start a post"
3. Paste LinkedIn body from the bottom of `docs/blog/announce-thread.md`
4. Replace `<LINK_TO_BLOG>` with the dev.to URL
5. Post (no cover image - LinkedIn text-only posts have higher reach)

## 7. Hacker News submission (optional)

If you want to try the HN lottery:
- Go to https://news.ycombinator.com/submit
- Title: `honeymcp: Open-source standalone honeypot for MCP servers (Rust)`
- URL: the GitHub repo (not the blog post - Show HN expects a product)
- Category: Show HN

Best window for HN: 08:00-10:00 Pacific (17:00-19:00 CET). If you want to try the HN front page, wait and post in the afternoon CET block. If you don't care, skip or submit the blog URL instead.

## 8. Retro - end of day

1. Run X daily reply agent tomorrow (cron scheduled for 09:07 CET, will fire if this the session is still alive)
2. Check the honeypot `/stats` at 20:00 CET. If `total_events` > 20, there's a "what honeymcp saw on day 4" post waiting.
3. Update blog post frontmatter `published: true` if it wasn't already (dev.to sometimes reverts).

## Notes for the assistant when resumed tomorrow

- blog path: `docs/blog/day-3-retrospective.md`
- thread path: `docs/blog/announce-thread.md`
- reply log dir: `/tmp/prep/projects/-Users-anetaopilowska-Michal-Projects-honeycomb/x_replies/`
- today's (Day 3) reply log already has 13 entries
- cron id: `3e1e7436` (session-only; may not fire if Claude exited overnight)
