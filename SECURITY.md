# Security Policy

## Responsible Disclosure & Safety Policy

Pentrare is built specifically to assist authorized security researchers, penetration testers, and bug bounty hunters.

### Safety Design Constraints

Pentrare enforces strict human-in-the-loop controls:
1. **Zero Autonomous Probing**: The system never sends network requests, probes endpoints, or executes payloads against real targets.
2. **Deterministic Evidence Validation**: Findings require empirical, researcher-provided evidence before validation.
3. **Prompt Injection Quarantine**: Untrusted external documents and evidence are treated strictly as data and cannot override system instructions.
4. **Secret Sanitization**: All ingested evidence is scrubbed for API keys, tokens, session IDs, and credentials.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x: |

---

## Reporting a Vulnerability

If you discover a security vulnerability or bypass in Pentrare's safety boundary, please report it responsibly:

1. **Email**: Open a security advisory on GitHub or email the maintainers directly.
2. **Do Not Open Public Issues**: Please avoid posting exploit payloads or vulnerability details in public issues.
3. **Response Window**: Maintainers will acknowledge reports within 48 hours and provide a fix timeline within 7 days.

---

## Authorized Use Only

This tool is strictly intended for:
- Explicitly authorized bug bounty targets within defined program scopes.
- Internal systems owned or operated by the researcher.
- Authorized professional penetration testing and security assessments.
- Local educational labs, CTFs, and security research environments.

Users are solely responsible for ensuring their testing complies with applicable local, state, and international laws.
