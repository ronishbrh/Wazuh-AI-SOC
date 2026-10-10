# Wazuh AI SOC Lab
## Technical Project Report

### Abstract

This project demonstrates a security monitoring and response workflow for a deliberately vulnerable AI chatbot. The application sends structured events to Wazuh, where custom rules detect selected AI-abuse patterns. A custom integration creates a TheHive alert/case and links it to the affected user. Wazuh invokes a custom active-response script that calls an authenticated FastAPI endpoint to apply a temporary restriction. After the configured timeout, Wazuh sends a delete action, and the application removes the restriction and records the action.

The single-alert lifecycle was verified in the lab. Handling overlapping alerts for the same user remains a known limitation.

### 1. Objectives

- Generate structured security events from an AI application.
- Detect selected input patterns using custom Wazuh rules.
- Create and link TheHive alerts and cases.
- Apply temporary defensive restrictions through an authenticated endpoint.
- Remove restrictions after timeout and retain an audit trail.

### 2. Architecture

The lab uses Docker Compose to run the application and security services. The FastAPI application sends JSON-formatted events to Wazuh over UDP port 514. Wazuh evaluates custom rules and triggers TheHive integration and active response. SQLite stores restriction state, user-to-case mappings, and audit records.

**Workflow:** AI application → Wazuh detection → TheHive alert/case and active response → temporary restriction → timeout-driven deletion → case status transition and audit event.

### 3. Technology stack

- **Python / FastAPI:** Application endpoints, restriction handling, case linking, and audit logging.
- **Wazuh:** Event collection, custom detections, and active-response execution.
- **TheHive:** Alert and case management.
- **SQLite:** Restriction state, case links, and audit records.
- **Docker Compose:** Service orchestration and internal networking.

### 4. Detection rules

| Rule ID | Purpose | Level |
|---|---|---:|
| 100900 | Prompt-injection pattern | 10 |
| 100901 | Sensitive-information extraction pattern | 10 |
| 100902 | Safety-bypass pattern | 10 |
| 100903 | Active-response audit event | 3 |

These are custom lab detections. Further tuning and evaluation are required to determine their accuracy and false-positive rates.

### 5. Active-response implementation

1. The application emits a structured event.
2. Wazuh generates an alert when a custom rule matches.
3. The TheHive integration creates an alert/case and records its link to the test user.
4. Wazuh invokes the custom active-response script with `add`.
5. The application stores a temporary restriction and audit record.
6. After the configured 300-second timeout, Wazuh invokes the script with `delete`.
7. The application removes the restriction, records the deletion, and emits an audit event.
8. The linked TheHive case is transitioned to `Indeterminate`.

### 6. Testing and results

The following behavior was verified:

- A synthetic prompt-injection event matched rule 100900.
- TheHive case creation and user-to-case linking succeeded.
- The active-response add request returned HTTP 200 and stored a restriction.
- The timeout delete request returned HTTP 200 and removed the restriction.
- The linked case transitioned to Indeterminate and appeared in the Closed stage.
- Audit records were present for both actions with the matching alert ID.

These results apply to the tested single-alert scenario. They do not prove production readiness or correct handling of all concurrent events.

### 7. Known limitation

The current `flagged_sessions` table allows one restriction row per `user_id`. If multiple alerts for the same user overlap, an earlier timeout's delete action may remove the restriction while a newer alert is still active.

The planned improvement is to track active response instances by `(user_id, alert_id)`, make operations idempotent, and remove the restriction only when no active instances remain. Tests should cover duplicate actions, missing alert IDs, overlapping timeouts, and TheHive API failures.

### 8. Security considerations

- Keep the intentionally vulnerable application isolated.
- Do not commit environment files, credentials, tokens, certificates, raw logs, or runtime databases.
- Rotate any credential that may have been exposed.
- Use least-privilege service credentials and restrict management interfaces.
- Redact screenshots and logs before publishing.
- Treat the current Indeterminate case transition as a lab policy choice, not a universal incident-handling recommendation.

### 9. Future work

- Implement per-alert restriction tracking.
- Add automated tests for concurrent alerts and API failures.
- Measure false-positive and false-negative rates.
- Add health checks and structured, redacted logging.
- Publish sanitized screenshots and reproducible deployment instructions.

### 10. Conclusion

The lab demonstrates a tested single-alert workflow connecting an AI-facing application, Wazuh, and TheHive. The workflow includes detection, case creation, temporary restriction, timeout-driven removal, case status transition, and audit records. Per-alert concurrency handling, rule evaluation, and additional hardening are required before adapting the prototype beyond an isolated learning environment.

### Suggested evidence for the final report

1. Sanitized Wazuh alert for rule 100900.
2. TheHive case overview with sensitive details removed.
3. Active-response log excerpts showing add and delete results.
4. Restriction-state and audit-query output using synthetic identifiers.
5. TheHive case status showing Indeterminate / Closed.
