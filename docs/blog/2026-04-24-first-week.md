# Week one of running a $7 MCP honeypot, an honest report

**Date:** 2026-04-24
**Honeymcp version:** 0.6.0-rc.1
**Deploy:** one Lightsail box in Singapore, AWS cheapest tier
**Persona:** `github-admin` (advertises GitHub repo admin tools)

---

## What I expected to publish

A breakdown of what attackers send to a fresh MCP honeypot. Top tool
names, top detector categories, sample payloads, the usual shape. I
had a draft that said "146 requests, 162 detections, top tool name
`read_file` with 21 calls". That draft was wrong.

## What actually showed up

In 5.6 days, the box logged **5 requests from the open internet** from
**3 unique remote sources**. None of them were targeted attackers.
None of them invoked `tools/call`. None of them tripped a detector.

The breakdown:

| Source | Events | Methods | Notes |
|---|---|---|---|
| `66.132.195.122` (CensysInspect/1.1) | 3 | initialize, notifications/initialized, tools/list | Internet-wide recon scanner |
| `79.191.150.130` (curl/8.7.1) | 1 | initialize | One handshake, no follow-up |
| `198.51.100.42` (xff-direct) | 1 | initialize | One handshake, no follow-up |

That is the entire external corpus. The other 145 events in the
SQLite log are mine: 87 from local `curl` validating endpoints, 52
from `honeymcp-probes` exercising every detector, the rest from
deployment smoke tests.

## Why my first draft said "21 read_file calls"

The `/stats` endpoint counts every event in the database, our own
included. When I queried it for the draft post, the top tool list was
dominated by `read_file`, `note`, `run`, `auth`. Those are the names
`honeymcp-probes` fires when it audits an MCP server. I read the
result as "what attackers sent". It was "what I sent the day before".

The fix in the corpus: filter by `user_agent NOT LIKE 'honeymcp-probes%'`
and by remote IP not in the operator's known set. The fix in the post:
publish what actually arrived from the internet, which is what you are
reading now.

## What this tells me about a fresh public MCP honeypot

A 5-event week means the box exists on the internet but is not yet
**discovered**. Singapore IP space, AWS Lightsail, no DNS name pointing
at it, no posts linking to it, no bug-bounty listing. A targeted
attacker does not stumble onto a freshly minted MCP server. Censys
will index it within a week, which is what happened here. From there,
discovery scales with whatever puts the IP in front of someone:
search, mention, dataset.

So week one is a calibration period, not a corpus. The interesting
question is week six.

## What I am changing about the methodology

1. The `/stats` endpoint now needs an option to exclude the operator's
   own traffic. Until then, every public number cites the operator-
   filtered count.
2. A scheduled job will tag every event with `is_operator: bool` at
   write time based on a configurable allowlist (UA, source IP).
3. The next data-drop will not happen until the external-only corpus
   is large enough that filtering it does not produce noise. My rough
   threshold is 200 external events from at least 30 unique sources.
4. Until then, this blog will only publish observations that are true
   even at small N: which scanners find the box, what they ask for in
   `initialize`, how long until the first non-scanner.

## What I am keeping

`honeymcp-probes` is still the fastest way to audit an MCP server you
operate. It fires the same payloads the detectors are tuned for, runs
in CI, and produces a JSON report. That part of the pitch is real.
The change is that probe traffic and attacker traffic are now strictly
separated in the corpus, and only one of them is honeypot data.

## What I learned about writing this kind of post

If your honeypot has been live for less than a month, your first
instinct will be to dress up small numbers. Don't. The interesting
finding from week one is that no targeted attacker found a fresh
public MCP server in Singapore. That is a real, useful, operator-
relevant fact. "21 read_file calls" was prettier and false.

The repo is at https://github.com/kosiorkosa47/honeymcp. If you run an
MCP server publicly and want to compare notes, the contact is in
[`SECURITY.md`](https://github.com/kosiorkosa47/honeymcp/blob/main/SECURITY.md).
