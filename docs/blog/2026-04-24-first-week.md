# What a $7 MCP honeypot caught in its first week

**Date:** 2026-04-24
**Honeymcp version:** 0.6.0-rc.1
**Deploy:** one Lightsail box in Singapore, AWS cheapest tier
**Persona:** `github-admin` (advertises GitHub repo admin tools)

---

## The numbers

5.6 days of uptime. 146 requests from the open internet. Seven detectors
running on every request. 162 tagged detections (events can match more
than one category).

Request methods:

| Method | Count |
|---|---|
| `tools/list` | 79 |
| `tools/call` | 59 |
| `initialize` | 8 |

Detector categories:

| Detector | Hits |
|---|---|
| `recon` | 103 |
| `secret_exfil` | 25 |
| `command_injection` | 13 |
| `prompt_injection` | 9 |
| `unicode_anomaly` | 8 |
| `supply_chain` | 4 |

## The interesting bit

The persona serves a `github-admin` MCP server. Its advertised tools are
things like `list_repositories`, `create_issue`, `review_pr`. None of
those are in the top 10 of what attackers actually called.

Top called tool names, top 10:

| Tool name requested | Calls |
|---|---|
| `read_file` | 21 |
| `note` | 8 |
| `run` | 5 |
| `auth` | 5 |
| `write_file` | 4 |
| `search` | 4 |
| `login` | 4 |
| `echo` | 4 |
| `whoami` | 3 |
| `search_code` | 1 |

Not one of those is in the persona's tool list. The honeypot's whole
trick is a convincing `tools/list` response — if the attacker actually
read it they would call `list_repositories`. They did not. They called
`read_file`, `run`, `auth`, `write_file`. They called what they thought
the server *might* have, regardless of the actual catalogue.

That matches the detector pattern too. `recon` fired 103 times because
most sessions opened with a `tools/list`, then moved straight into
`tools/call` on a guessed name, ignored the real tool list, and
moved on.

## What I think this means for people running real MCP servers

Your tool catalogue is advisory for attackers, not load-bearing. If
you rely on "we don't expose `read_file`, so attackers won't call it",
they will try it anyway and you will see 21 `read_file` attempts per
week per box. Your server decides what to do when `tools/call` names
an unknown tool, and that decision is what actually matters.

Current MCP SDKs default to a JSON-RPC method-not-found response. That
is correct. Stay on that. Do not add a "helpful" fallback that tries to
execute the tool name as a shell command because someone wrote a Stack
Overflow answer saying it was clever.

## Redacted examples

I will not paste live payloads in this post. A later write-up will,
once I have a sampling routine I am comfortable publishing. What I will
say:

- The `secret_exfil` hits were almost all attempts to get `auth` /
  `login` / `whoami` responses that would include tokens.
- The `command_injection` hits were shell-escape patterns inside the
  `arguments` of a `run` call. Standard fare.
- The `prompt_injection` hits targeted the persona's `instructions`
  field, trying to flip the assistant's behaviour.
- The `unicode_anomaly` hits were mostly zero-width joiners inside
  tool arguments. Classic evasion, not sophisticated.
- The `supply_chain` hits were requests to install a package from a
  suspicious index. Interesting. Will dig deeper.

## Why I am writing this

I am building honeymcp as a single-operator sensor for the MCP
ecosystem because I could not find a public corpus of what attackers
actually send to MCP servers. A week in, that corpus has started to
exist. This is the first write-up pulled from it.

- Repository: https://github.com/kosiorkosa47/honeymcp
- You can audit your own MCP server with `honeymcp-probes`, the
  second binary in the crate. Same attack taxonomy as the honeypot.
- If you run an MCP server publicly and want to compare notes, my
  contact is in the SECURITY.md of the repo.
