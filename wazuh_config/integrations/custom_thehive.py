#!/usr/bin/env python3
import json
import os
import sys
import urllib.request
import urllib.error

APP_URL = "http://ai_app:8000/thehive_case_link"
ACTIVE_RESPONSE_TOKEN = os.getenv("ACTIVE_RESPONSE_TOKEN", "")


def post_json(url, token, payload, token_header="Authorization"):
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            token_header: (
                f"Bearer {token}" if token_header == "Authorization" else token
            ),
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        body = response.read().decode("utf-8")
        return response.status, json.loads(body) if body else {}


def main():
    if len(sys.argv) < 4:
        sys.stderr.write("Usage: custom-thehive <alert_file> <api_key> <hook_url>\n")
        sys.exit(1)

    alert_file, api_key, hook_url = sys.argv[1:4]

    if not ACTIVE_RESPONSE_TOKEN:
        sys.stderr.write("ACTIVE_RESPONSE_TOKEN is not configured.\n")
        sys.exit(1)

    with open(alert_file, "r", encoding="utf-8") as f:
        alert = json.load(f)

    rule = alert.get("rule", {})
    data = alert.get("data", {})
    description = rule.get("description", "AI Security Alert")
    attacker = str(data.get("user_id") or data.get("user") or "").strip()
    malicious_input = str(data.get("user_input") or "")

    if not attacker:
        sys.stderr.write("No user_id found; refusing to create an unlinked case.\n")
        sys.exit(1)

    alert_payload = {
        "title": f"[Wazuh Exploit Alert] {description}",
        "description": (
            "AI chatbot security alert\n"
            f"Attacker: {attacker}\n"
            f"Malicious input: {malicious_input}"
        ),
        "severity": 3,
        "type": "external",
        "source": "Wazuh-SIEM",
        "sourceRef": str(alert.get("id", "")),
        "observables": [
            {"dataType": "other", "data": attacker},
            {"dataType": "other", "data": malicious_input},
        ],
    }

    try:
        status, created_alert = post_json(hook_url, api_key, alert_payload)
        alert_id = created_alert.get("_id") or created_alert.get("id")
        if not alert_id:
            raise RuntimeError("TheHive did not return an alert ID.")

        case_payload = {
            "title": f"[AI SOC] {description} - {attacker}",
            "description": (
                "Automated case for an AI chatbot security detection.\n"
                f"Attacker: {attacker}\n"
                f"Malicious input: {malicious_input}\n"
                "Linked to the active-response restriction."
            ),
            "severity": 3,
            "tags": ["wazuh", "ai-soc", "automated"],
        }
        case_url = f"http://thehive-app:9000/api/v1/alert/{alert_id}/case"
        case_status, created_case = post_json(case_url, api_key, case_payload)
        case_id = created_case.get("_id") or created_case.get("id")
        if not case_id:
            raise RuntimeError("TheHive did not return a case ID.")

        link_status, link_result = post_json(
            APP_URL,
            ACTIVE_RESPONSE_TOKEN,
            {"user_id": attacker, "case_id": case_id},
            "X-Active-Response-Token",
        )

        print(f"TheHive alert created: HTTP {status}")
        print(f"TheHive case created: HTTP {case_status}; ID {case_id}")
        print(
            f"Case mapping: HTTP {link_status}; "
            f"{link_result.get('status', 'unknown')}"
        )

    except urllib.error.HTTPError as exc:
        sys.stderr.write(
            f"Integration HTTP error {exc.code}: "
            f"{exc.read().decode('utf-8', errors='replace')[:500]}\n"
        )
        sys.exit(1)
    except Exception as exc:
        sys.stderr.write(f"Integration failed: {type(exc).__name__}: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
