# Security Policy

## Supported versions

Only the latest release on the `main` branch of
[reyk-zepper/claude-home-server](https://github.com/reyk-zepper/claude-home-server)
receives security fixes. There are no long-term support branches at this time.

| Version | Supported |
|---------|-----------|
| Latest on `main` | Yes |
| Older releases | No |

---

## Reporting a vulnerability

Security vulnerabilities should be reported privately. Do not open a public
GitHub issue for a security bug.

**Contact:** security@zepper.me

Please include in your report:

- A clear description of the vulnerability and the component affected (e.g.,
  PathValidator, AuditLogger, a specific module).
- The attack scenario: what an adversary could achieve by exploiting it.
- Steps to reproduce or a proof-of-concept. This can be a code snippet,
  a crafted input, or a description of the conditions required.
- The version or commit SHA where you found the issue.
- Whether you have already developed or tested a fix.

You do not need to have a complete fix to submit a report. Partial information
is still valuable.

---

## What to expect after you report

| Milestone | Target time |
|-----------|-------------|
| Acknowledgement of your report | 3 business days |
| Initial assessment (confirmed, disputed, or needs more info) | 10 business days |
| Patch or mitigation plan shared with reporter | 30 business days |
| Public disclosure (coordinated with reporter) | 90 days from initial report |

If the vulnerability is particularly severe or has a known active exploit, the
timeline may be accelerated. If additional time is needed for a complex fix,
the timeline may be extended by mutual agreement with the reporter.

---

## Disclosure policy

This project follows a 90-day coordinated disclosure policy:

1. The reporter notifies the maintainer privately.
2. The maintainer confirms receipt within 3 business days.
3. The maintainer works on a fix and keeps the reporter informed of progress.
4. A patch is released and a GitHub Security Advisory is published no later
   than 90 days after the initial report, or sooner if a fix is ready.
5. The reporter is credited in the advisory unless they prefer anonymity.

If the maintainer cannot produce a fix within 90 days, the reporter may proceed
with public disclosure. Please notify the maintainer before publishing.

---

## Out of scope

The following are not considered security vulnerabilities for this project:

- Vulnerabilities in third-party dependencies (report these to the upstream
  project; if they directly affect claude-home-server, include that context in
  your report).
- Issues that require the attacker to already have root access on the server
  where claude-home-server is deployed.
- Denial-of-service attacks that require physical access to the machine.
- Bugs that are only exploitable when the operator has deliberately misconfigured
  the server in a way documented as insecure (for example, adding `/` to
  `filesystem.allowed_paths`).
- Social engineering or phishing attacks against the server operator.
- Vulnerabilities in the Claude LLM itself or in Claude Code (report these to
  Anthropic).
- Issues that require the SSH private key to already be compromised.

---

## Threat model reference

For a detailed description of the attack surface, trust boundaries, and existing
mitigations, see [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## Acknowledgements

Responsible disclosures that lead to a confirmed fix will be acknowledged in the
release notes and in the GitHub Security Advisory, with the reporter's name or
handle unless they prefer to remain anonymous.
