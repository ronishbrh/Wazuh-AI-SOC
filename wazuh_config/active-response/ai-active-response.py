#!/usr/bin/env python3
import json
import os
import sys
import urllib.request
import urllib.error

LOG_FILE = "/var/ossec/logs/active-responses.log"


def log_message(message):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(message + "\n")
    except Exception:
        pass


APP_URL = os.getenv("AI_APP_URL", "http://ai_app:8000")
TOKEN = os.getenv("ACTIVE_RESPONSE_TOKEN", "")


def main():
    log_message("AI active response script launched")
    try:
        raw_input = sys.stdin.readline()
        log_message("Raw Wazuh input: " + repr(raw_input[:2000]))
        message = json.loads(raw_input)
        log_message("Received command: " + str(message.get("command")))
        log_message("Token present: " + str(bool(TOKEN)))
        log_message(
            "Alert data: "
            + repr(message.get("parameters", {}).get("alert", {}).get("data", {}))
        )
    except Exception as e:
        print(f"Could not read Wazuh event: {e}", file=sys.stderr)
        sys.exit(1)

    if not TOKEN:
        print("ACTIVE_RESPONSE_TOKEN is missing", file=sys.stderr)
        sys.exit(1)

    command = message.get("command", "")
    if command not in ("add", "delete"):
        print("Ignoring unsupported command", file=sys.stderr)
        sys.exit(1)

    alert = message.get("parameters", {}).get("alert", {})
    data = alert.get("data", {})
    rule = alert.get("rule", {})

    user_id = data.get("user_id") or data.get("user") or ""
    rule_id = rule.get("id")
    rule_description = rule.get("description")
    alert_id = alert.get("id")

    if not isinstance(user_id, str) or not user_id.strip():
        print("No user_id found in Wazuh alert", file=sys.stderr)
        sys.exit(1)

    payload = json.dumps(
        {
            "user_id": user_id.strip(),
            "action": command,
            "source": "wazuh",
            "rule_id": rule_id,
            "rule_description": rule_description,
            "alert_id": alert_id,
        }
    ).encode("utf-8")

    log_message("User ID validated; preparing HTTP request to " + APP_URL)

    request = urllib.request.Request(
        f"{APP_URL}/active_response",
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Active-Response-Token": TOKEN,
        },
    )

    log_message("HTTP handler entered")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            result = response.read().decode("utf-8", errors="replace")
            log_message(f"HTTP response: {response.status} {result}")
            print(f"AI active response completed: HTTP {response.status}")
    except Exception as e:
        log_message("HTTP exception: " + repr(e))
        raise


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log_message("UNHANDLED ERROR: " + repr(e))
        raise
