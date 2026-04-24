# Privacy + GDPR Legitimate Interest Assessment

This document explains why running a honeymcp instance is, in the author's
view, lawful under the General Data Protection Regulation (GDPR / Regulation
(EU) 2016/679), and what the operator's obligations are.

It is not legal advice. It is the reasoning an operator should be prepared
to give if a data-protection authority or a data subject asks.

---

## 0. Scope

- Applies to: operators running honeymcp inside the EEA or with data
  subjects located in the EEA.
- Controller: the natural or legal person who runs the honeymcp instance.
  This is the operator, not the honeymcp project.
- Legal basis claimed: **legitimate interests** under GDPR Art. 6(1)(f),
  supported by Recital 49.

## 1. What personal data is processed

The following fields are captured per request:

| Field | Category |
|---|---|
| Source IP address | Personal data (GDPR Recital 30) |
| HTTP User-Agent | Personal data in combination with IP |
| `X-Forwarded-For` chain | Personal data in combination with IP |
| `MCP-Protocol-Version`, `Accept` | Not personal data on its own |
| JSON-RPC method and params | May contain personal data if the attacker included their own; typically contains synthetic payloads |
| Session ID (header or query) | Pseudonymous identifier |
| Timestamp | Metadata |

No cookies. No third-party trackers. No cloud analytics.

## 2. Purpose and necessity (the Art. 6(1)(f) test)

### 2.1 Purpose

To collect a corpus of real attacker behaviour against MCP
(Model Context Protocol) servers, so that defenders can build
better detectors, better guidance, and better mitigations.

### 2.2 Necessity

The purpose cannot be achieved without:

1. Running something that attackers will actually target (a honeypot).
2. Recording what they send (the request).
3. Retaining enough metadata to correlate and attribute (timestamp,
   session, source IP, user-agent).

Synthetic attack generation (e.g. running the included `honeymcp-probes`
CLI against oneself) is not a substitute - the research value is in
**what attackers choose to do unprompted**, which synthetic data cannot
produce.

### 2.3 Recital 49 alignment

Recital 49 explicitly contemplates "processing of personal data to the
extent strictly necessary and proportionate for the purposes of ensuring
network and information security" as a legitimate interest. It names
prevention of unauthorised access, malicious code propagation, and
attacks on computer and electronic communication systems.

A honeypot that captures attempted MCP attacks is within this frame.

## 3. Balancing test

For the legitimate-interests lawful basis to apply, the operator's
interest must not be overridden by the data subject's rights and
freedoms.

| Factor | Our position |
|---|---|
| Reasonable expectations | An entity that sends a prompt-injection payload or a shell-injection string to a randomly-discovered MCP endpoint has no reasonable expectation that the recipient will not log it. |
| Data minimisation | We capture only what is needed to correlate attacks. No tracking cookies, no fingerprinting, no content that was not voluntarily sent by the client. |
| Retention | Default retention: 90 days for the raw event row, 13 months for derived / aggregated threat intel. Operators may tighten but should not loosen without re-running this assessment. |
| IP truncation | Not applied by default to raw rows because attribution suffers. Operators with a lower appetite MAY run with an IP-truncation post-processing step before sharing derived datasets. |
| Special categories | We do not intentionally collect Art. 9 special-category data. If an attacker includes such data in a payload, it is incidental; honeymcp does not index or surface it. |
| Children | MCP is a machine protocol. There is no expected child-user surface. |
| Public interest | Threat-intel corpora benefit downstream defenders and end users. |

## 4. Data subject rights

Operators must be prepared to honour:

- **Art. 13 / 14 - notice.** Served via `docs/legal/operator-banner.md`
  at `GET /`.
- **Art. 15 - access.** If a data subject identifies themselves by IP,
  operator returns the matching rows or confirms absence.
- **Art. 17 - erasure.** Default commitment in the banner is 30 days to
  comply unless the record is part of an active investigation.
- **Art. 21 - objection.** Because the lawful basis is Art. 6(1)(f), the
  data subject has the right to object. The operator must assess whether
  continued processing is justified by compelling legitimate grounds; in
  practice, for a non-targeted honeypot, honouring a specific-IP erasure
  request is the cleanest outcome.
- **Art. 77 - complaint.** Data subjects may complain to their supervisory
  authority. The operator should not obstruct this.

## 5. Technical and organisational measures

| Measure | Status |
|---|---|
| Encryption at rest | Operator chooses disk encryption (FDE recommended). honeymcp does not separately encrypt the SQLite file. |
| Encryption in transit | TLS terminated at the reverse proxy (Caddy / nginx / Cloudflare). honeymcp does not terminate TLS itself. |
| Access controls | OS-level. Dashboard is unauthenticated; operator must restrict via VPN / reverse-proxy auth if desired. |
| Secret redaction in outputs | Automatic for known patterns (GitHub PAT, AWS keys, JWTs, PEM blocks, Slack tokens). See `src/bin/probes.rs::redact_secrets`. |
| Logging integrity | Append-only DB row pattern. Operator-side tampering is out of the threat model. |
| Backups | Operator choice. Any backup is subject to the same retention policy. |

## 6. International transfers

honeymcp itself does not transfer captured data anywhere. If the operator
uses cloud storage or a remote log sink, the operator is responsible for
the transfer mechanism (SCCs, adequacy decision, etc.).

## 7. Publication of derived datasets

When the operator publishes any output from honeymcp (blog post,
conference talk, shared corpus), the following defaults apply:

1. No raw source IPs. Truncate to /24 for IPv4 or /48 for IPv6.
2. No raw user-agents verbatim if they could be used to identify a
   specific natural person.
3. Redact known secret patterns (already done automatically).
4. Prefer aggregate statistics over per-record detail.

## 8. Review triggers

Re-run this assessment when:

- Default retention changes.
- A new captured field is added (e.g. a new header).
- Processing purpose changes beyond defensive research.
- Operator is asked to host an instance on behalf of a third party
  (introduces a processor relationship under Art. 28).

---

## Operator signature block

```
Controller:            ______________________________
Contact:               ______________________________
Date assessment run:   ______________________________
Deployment ID / host:  ______________________________
Retention policy:      raw 90 days / derived 13 months
                       (or document deviation here)
Signature:             ______________________________
```

Keep a signed copy outside of the repository. This file is the template;
the signed PDF is the record.
