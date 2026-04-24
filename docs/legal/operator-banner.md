# Operator banner

This is the template served at `GET /` by a honeymcp instance. It documents
that the endpoint is a research honeypot, explains what data is captured,
and points at a contact channel for takedown / opt-out requests.

The intent is twofold:

1. **Notice obligation.** Under GDPR Art. 13/14 the data subject must be
   informed of the processing. A serverside banner is not a perfect vehicle
   (many clients never request the root) but it is the best we can do for
   unsolicited scanners.
2. **Deterrence + attribution clarity.** If the instance is ever mistaken
   for a production service (penetration test, incident response, threat
   report), the banner makes it trivial to distinguish.

Operators are expected to edit the `{{CONTROLLER}}` / `{{CONTACT}}` / `{{ABUSE_EMAIL}}`
placeholders to reflect their own entity. The banner text is intentionally
plain - not marketing copy, not clever.

---

## Plain-text version (served as `content-type: text/plain`)

```
honeymcp - research honeypot
============================

You are talking to a honeypot that simulates the Model Context Protocol
(MCP). This is not a production MCP server. No model is running on the
other side, no real tools are connected, and no data you send will reach
any downstream system other than the research log of this operator.

What we capture
---------------

Every request to this endpoint is logged for the purpose of security
research against the MCP attack class. Captured fields:

  - timestamp
  - source IP (may be truncated before long-term storage)
  - HTTP headers (User-Agent, X-Forwarded-For, MCP-Protocol-Version, Accept)
  - full JSON-RPC body as sent

Sensitive substrings (API keys, private key blocks, JWT-shaped tokens,
Slack tokens) are redacted in any response we echo back to you and in any
derived outputs we publish.

Why
---

We study how attackers target MCP servers so that defenders can build
better mitigations. See docs/legal/privacy-gdpr-lia.md in this repository
for the GDPR Legitimate Interest Assessment.

Contact
-------

Controller:   {{CONTROLLER}}
Abuse / data requests: {{ABUSE_EMAIL}}
Project:      https://github.com/kosiorkosa47/honeymcp

To request that your IP be removed from retained logs, email
{{ABUSE_EMAIL}} with the IP in the subject. We will comply within 30
days per GDPR Art. 17 unless the record is part of an active incident
investigation, in which case we will respond with the reason for the
delay.

Nothing on this endpoint is a live service, a honeytoken, or bait
for law enforcement interaction. It exists to collect a corpus of
real attacker behaviour against MCP, nothing more.
```

---

## HTML version (served as `content-type: text/html` for curious humans)

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>honeymcp - research honeypot</title>
<meta name="robots" content="noindex, nofollow">
<style>
  body { font: 15px/1.5 -apple-system, system-ui, sans-serif; max-width: 680px;
         margin: 40px auto; padding: 0 16px; color: #111; background: #faf7f0; }
  h1 { font-size: 22px; margin: 0 0 8px; }
  h2 { font-size: 16px; margin: 24px 0 4px; color: #555; text-transform: uppercase;
       letter-spacing: 0.05em; }
  p, li { margin: 6px 0; }
  code { background: #eee; padding: 0 4px; border-radius: 2px; font-size: 13px; }
  a { color: #0a58ca; }
  .meta { color: #666; font-size: 13px; margin-top: 24px; border-top: 1px solid #ddd;
          padding-top: 12px; }
</style>
</head>
<body>

<h1>honeymcp - research honeypot</h1>

<p>You are talking to a honeypot that simulates the
<a href="https://spec.modelcontextprotocol.io/">Model Context Protocol</a>
(MCP). This is <strong>not</strong> a production MCP server. No model is
running on the other side, no real tools are connected, and no data you
send will reach any downstream system other than the research log of this
operator.</p>

<h2>What we capture</h2>

<ul>
  <li>timestamp</li>
  <li>source IP (may be truncated before long-term storage)</li>
  <li>HTTP headers: <code>User-Agent</code>, <code>X-Forwarded-For</code>,
      <code>MCP-Protocol-Version</code>, <code>Accept</code></li>
  <li>full JSON-RPC body as sent</li>
</ul>

<p>Sensitive substrings (API keys, private key blocks, JWT-shaped tokens,
Slack tokens) are redacted in any response we echo back to you and in any
derived outputs we publish.</p>

<h2>Why</h2>

<p>We study how attackers target MCP servers so that defenders can build
better mitigations. The GDPR Legitimate Interest Assessment is in
<code>docs/legal/privacy-gdpr-lia.md</code> of the project repository.</p>

<h2>Contact</h2>

<p>Controller: {{CONTROLLER}}<br>
Abuse / data-subject requests: <a href="mailto:{{ABUSE_EMAIL}}">{{ABUSE_EMAIL}}</a><br>
Project: <a href="https://github.com/kosiorkosa47/honeymcp">github.com/kosiorkosa47/honeymcp</a></p>

<p>To request that your IP be removed from retained logs, email
<a href="mailto:{{ABUSE_EMAIL}}">{{ABUSE_EMAIL}}</a> with the IP in the
subject. We will comply within 30 days per GDPR Art. 17 unless the record
is part of an active incident investigation.</p>

<p class="meta">Nothing on this endpoint is a live service, a honeytoken, or
bait for law enforcement interaction. It exists to collect a corpus of real
attacker behaviour against MCP, nothing more.</p>

</body>
</html>
```

---

## Substitutions

| Placeholder | What to put here |
|---|---|
| `{{CONTROLLER}}` | Natural / legal person responsible under GDPR. For solo research: your name. For a company: the registered entity name. |
| `{{CONTACT}}` | Human name of the person handling abuse / data-subject requests. Optional. |
| `{{ABUSE_EMAIL}}` | Real monitored mailbox. Not a web form. |

## What NOT to change

- The description of what is captured. If your deployment captures more,
  say so here. Do not capture more and omit the disclosure.
- The 30-day GDPR Art. 17 commitment. If you need longer for active
  incidents, say so on reply - do not quietly miss the deadline.
- The `noindex, nofollow` meta in the HTML version. The banner is not
  for SEO; indexing it would poison the honeypot signal.
