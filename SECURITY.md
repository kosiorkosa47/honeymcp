# Security Policy

honeymcp is a honeypot. It is designed to be attacked, but the honeypot itself must not be a vulnerability.

## Reporting a Vulnerability

If you find a security issue in honeymcp itself (not in the systems it impersonates), please report privately:

- GitHub Security Advisory: https://github.com/kosiorkosa47/honeymcp/security/advisories/new
- Or open an issue marked `[SECURITY]` if non-sensitive

## Operational Safety

honeymcp is intended for research deployment only. Do not run it as a replacement for legitimate MCP servers on production endpoints. Run with minimum privileges, in isolated environments (containers, VMs), and never expose real secrets via persona response text.
