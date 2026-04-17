# Security Policy

`honeymcp` is a honeypot. It is designed to be attacked, but the honeypot itself must not be a vulnerability.

## Reporting a Vulnerability

If you find a security issue in `honeymcp` itself (not in the systems it impersonates), please report privately via GitHub Security Advisory:

https://github.com/kosiorkosa47/honeymcp/security/advisories/new

## Operational Safety

`honeymcp` is intended for research deployment only.

- Do **not** run it as a replacement for legitimate MCP servers on production endpoints.
- Run with minimum privileges, in isolated environments (containers, VMs, dedicated user).
- Never place real secrets or credentials in persona response text — personas are content served back to potential attackers.
- Log storage may contain attacker-supplied payloads; treat the database and JSONL files as untrusted input when processing downstream.

## Responsible Use

Running a honeypot on infrastructure you do not control or have explicit authorization for may violate computer misuse laws in your jurisdiction. You are responsible for legal compliance of your deployment.
