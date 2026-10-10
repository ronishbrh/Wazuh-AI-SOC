I built a hands-on AI security monitoring lab integrating a deliberately vulnerable AI chatbot with Wazuh SIEM, TheHive case management, and a custom active-response workflow.

What I implemented:
- Custom Wazuh detections for prompt-injection, sensitive-information extraction, and safety-bypass patterns
- Automated TheHive alert/case creation and linking
- A custom Python active-response script and authenticated FastAPI endpoint
- Temporary restriction handling, timeout-driven removal, and audit events
- Docker Compose-based service integration

I tested the single-alert lifecycle end to end: detection → TheHive case creation/linking → restriction applied → timeout → restriction removed → case transitioned to Indeterminate/Closed, with audit records for both response actions.

One important engineering lesson was that automated response requires careful state management. Overlapping alerts for the same user remain a known limitation, and per-alert tracking is a planned improvement.

This project helped me practice SIEM engineering, detection logic, API integration, incident workflow automation, Python, Docker, and security testing.

#Cybersecurity #SOC #Wazuh #TheHive #SIEM #BlueTeam #Python #Docker #AIsecurity
