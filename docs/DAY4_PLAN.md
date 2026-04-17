# Day 4 plan - publish day

Day 4 is primarily a **distribution** day. Code work is secondary. The goal is to convert the three days of build into reach, and to set up the first real data-drop post later in the week.

## Morning - publish (08:30-11:00 CET)

Follow `docs/blog/publish-checklist.md` step by step.

- [ ] Verify dashboard at `http://54.169.235.208/dashboard` is live and `/stats` returns valid JSON
- [ ] Publish blog on dev.to
- [ ] Post X announce thread as reply chain under the pinned launch
- [ ] Unpin launch, pin the new 1/5 tweet
- [ ] LinkedIn post
- [ ] (optional) Hacker News "Show HN" submission

## Midday - first reply run on fresh content (11:00-13:00 CET)

- [ ] If the Day 3 scheduled cron (`3e1e7436`) fired overnight, it ran the morning reply agent already. If not, trigger manually: "run morning reply agent with the handles in the Day 3 scheduled prompt."
- [ ] Review the Day 4 reply log at `/tmp/prep/projects/-Users-anetaopilowska-Michal-Projects-honeycomb/x_replies/2026-04-18.jsonl`.
- [ ] If the announce thread gets any replies/quote-tweets, reply to them with substance within an hour - the algorithm strongly rewards fast in-thread interaction.

## Afternoon - code work (14:00-17:00 CET)

Only if morning didn't drag. Pick ONE of these based on the first signal the honeypot captured:

**Track A - new persona based on captured intent**
- If honeypot logs show attackers probing for Slack/Notion/Linear/etc., write that persona next
- Requires at least 20-30 tool_call events to infer demand
- If there's no meaningful capture yet, skip this track

**Track B - harden what exists**
- Add more secret patterns to `secret_exfil_targets` based on what captured payloads reveal
- Lower false-positive noise in `prompt_injection_markers`
- Add `MCP-Session-Id` enforcement (or lack of it - log the absence)

**Track C - discovery**
- Submit honeymcp repo to 1-2 public awesome-mcp-servers lists via PR
- Write a short reply under the X announce thread that specifically names the capture status ("N events, M detections since this morning")

## Evening - first data-drop post (20:00 CET)

Only if total_events > 10 and at least ONE detection fired.

Format:
```
honeymcp — first 24h.

<N> events captured.
<M> unique remote addresses.
<K> detections across <categories>.

Most common probe: <tool_name> with <top param pattern>.

Full dashboard: http://54.169.235.208/dashboard
```

No links in the tweet body - dashboard URL is the link. Single post, not a thread.

## Success criteria for Day 4

- Blog published, visible, ≥ 500 views by midnight
- Announce thread posted, pinned
- LinkedIn post live
- X account has ≥ 100 new followers OR 5 meaningful engagements (replies, not likes) from target-tier accounts
- honeymcp captures ANY organic traffic (even one port scan counts)

## Anti-patterns to avoid today specifically

- No new major features. Day 4 is for distribution, not architecture.
- No changing the pinned post more than twice.
- No replying to small-account followers just to drive their counts; prioritize Tier 2 engagement.
- No "I'm so grateful for <N> followers" posts ever.
- No screenshot of the dashboard with zero rows. If dashboard is empty when someone visits, that's the story to fix first (by getting it some traffic via engagement), not to apologize for.

## Day 5 preview

If Day 4 lands the publish cleanly and honeypot captures real traffic:

- First long data post ("what honeymcp caught this week")
- Slack/Notion/Linear persona depending on demand
- Second blog post on dev.to focused on the telemetry

If honeypot is still empty on Day 5:

- Active discovery push: submit to Shodan, post in r/netsec, ping 2-3 Tier 2 accounts directly
- Consider adding a DNS name (cheap domain + Caddy for HTTPS)
