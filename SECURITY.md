# Security Policy and Responsible Use

This repository documents a defensive learning lab intended to run in an isolated environment.

- Do not expose the intentionally vulnerable AI application to the public internet.
- Never commit `.env`, API keys, active-response tokens, private keys, certificates, raw logs, databases, or local backups.
- Rotate any credential that may have been exposed.
- Use synthetic identifiers and redact infrastructure details from screenshots and logs.
- Use least privilege and restrict access to dashboards and management ports.
- Overlapping active-response alerts for the same user are a known limitation.
