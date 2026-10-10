import json
import sys
import socket
import os
import secrets
import urllib.request
import urllib.error
import sqlite3
from contextlib import contextmanager
import re
import unicodedata
from fastapi import FastAPI, Header, HTTPException

app = FastAPI()

ACTIVE_RESPONSE_TOKEN = os.getenv("ACTIVE_RESPONSE_TOKEN", "")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")
DB_PATH = "/app/data/restrictions.db"
ANALYST_PASSWORD = os.getenv("ANALYST_PASSWORD", "")

PROMPT_FILE = "/app/system_prompt.txt"
WAZUH_HOST = "wazuh"
WAZUH_PORT = 514


@contextmanager
def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.on_event("startup")
def initialize_database():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS flagged_sessions (
                user_id TEXT PRIMARY KEY,
                flagged_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS active_response_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                source TEXT NOT NULL DEFAULT 'wazuh',
                rule_id TEXT,
                rule_description TEXT,
                alert_id TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS thehive_case_links (
                user_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                linked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(active_response_audit)")
        }

        for column in ("rule_id", "rule_description", "alert_id"):
            if column not in columns:
                conn.execute(
                    f"ALTER TABLE active_response_audit ADD COLUMN {column} TEXT"
                )


def close_thehive_case(case_id: str):
    if not THEHIVE_API_KEY:
        raise RuntimeError("THEHIVE_API_KEY is not configured")

    url = f"http://thehive-app:9000/api/v1/case/{case_id}"
    request = urllib.request.Request(
        url,
        data=json.dumps({"status": "Indeterminate"}).encode("utf-8"),
        method="PATCH",
        headers={
            "Authorization": f"Bearer {THEHIVE_API_KEY}",
            "Content-Type": "application/json",
        },
    )

    with urllib.request.urlopen(request, timeout=15) as response:
        return response.status


def is_flagged(user_id: str) -> bool:
    with get_db() as conn:
        row = conn.execute(
            "SELECT 1 FROM flagged_sessions WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        return row is not None


def send_syslog(message: str):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(message.encode("utf-8"), (WAZUH_HOST, WAZUH_PORT))
    except Exception:
        pass


def get_system_prompt():
    try:
        with open(PROMPT_FILE, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        default_prompt = "You are a secure data assistant."
        with open(PROMPT_FILE, "w") as f:
            f.write(default_prompt)
        return default_prompt


@app.get("/session_status")
async def session_status(user_id: str = Header("anonymous")):
    if is_flagged(user_id):
        return {
            "status": "active_response",
            "reply": "This session is restricted due to a detected security threat.",
        }

    return {"status": "success"}


@app.post("/chat")
async def chat(payload: dict, user_id: str = Header("anonymous")):
    user_input = str(payload.get("text", ""))

    if is_flagged(user_id):
        return {
            "status": "active_response",
            "reply": "This session is restricted due to a detected security threat.",
        }

    system_prompt = get_system_prompt()
    log_event = {
        "event_source": "ai_chatbot",
        "user_id": user_id,
        "user_input": user_input,
        "active_prompt": system_prompt,
    }
    send_syslog(json.dumps(log_event))
    print(json.dumps(log_event))
    sys.stdout.flush()

    detection = detect_prompt_injection(user_input)

    if detection:
        event = {
            "event_source": "ai_chatbot",
            "event_type": "prompt_injection_detected",
            "user_id": user_id,
            "category": detection,
        }
        send_syslog(json.dumps(event))
        print(json.dumps(event))
        sys.stdout.flush()

        return {
            "status": "security_violation",
            "reply": "Request terminated by security policy.",
        }

    return {
        "status": "success",
        "reply": "Processed safely.",
    }


def detect_prompt_injection(user_input: str) -> str | None:
    # Normalize case, Unicode and repeated whitespace.
    text = unicodedata.normalize("NFKC", user_input).casefold()
    text = re.sub(r"\s+", " ", text).strip()

    patterns = {
        "instruction_override": [
            r"\bignore\b.{0,40}\b(previous|prior|above|earlier)\b.{0,30}\b(instructions?|rules?|prompts?)\b",
            r"\b(disregard|override|bypass)\b.{0,40}\b(instructions?|rules?|safeguards?|restrictions?)\b",
            r"\bignore\s+rules\b",
            r"\b(forget|disregard|discard)\b.{0,50}\b(what|everything|all)\b.{0,30}\b(told|instructed|given)\b",
            r"\b(forget|ignore|disregard)\b.{0,40}\b(before|earlier|previously)\b",
        ],
        "sensitive_data_request": [
            r"\b(reveal|disclose|print|expose|dump)\b.{0,40}\b(secrets?|private keys?|credentials?|api keys?|system prompt)\b",
            r"\breveal\s+keys\b",
            r"\b(show|display|provide|give|reveal|expose)\b.{0,50}\b(hidden|internal|secret|private)\b.{0,30}\b(configuration|instructions?|credentials?|keys?|prompt|settings?)\b",
            r"\b(secret credentials|hidden configuration|internal instructions)\b",
        ],
        "priority_manipulation": [
            r"\b(treat|consider)\b.{0,30}\b(my|this)\b.{0,20}\b(instruction|message|prompt)\b.{0,30}\b(highest priority|system instruction)\b",
        ],
    }

    for category, expressions in patterns.items():
        if any(re.search(pattern, text) for pattern in expressions):
            return category

    return None


@app.post("/update_prompt")
async def update_prompt(payload: dict):
    new_prompt = payload.get("prompt", "")
    with open(PROMPT_FILE, "w") as f:
        f.write(new_prompt)
    return {"status": "prompt_hardened", "current": new_prompt}


@app.post("/thehive_case_link")
async def thehive_case_link(
    payload: dict,
    x_active_response_token: str = Header(""),
):
    if not ACTIVE_RESPONSE_TOKEN or not secrets.compare_digest(
        x_active_response_token, ACTIVE_RESPONSE_TOKEN
    ):
        raise HTTPException(status_code=401, detail="Unauthorized")

    user_id = str(payload.get("user_id") or "").strip()
    case_id = str(payload.get("case_id") or "").strip()

    if not user_id or not case_id:
        raise HTTPException(status_code=400, detail="Missing user_id or case_id")

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO thehive_case_links (user_id, case_id)
            VALUES (?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                case_id = excluded.case_id,
                linked_at = CURRENT_TIMESTAMP
            """,
            (user_id, case_id),
        )

    return {"status": "case_linked", "user_id": user_id, "case_id": case_id}


@app.post("/active_response")
async def active_response(
    payload: dict,
    x_active_response_token: str = Header(""),
):
    if not ACTIVE_RESPONSE_TOKEN or not secrets.compare_digest(
        x_active_response_token, ACTIVE_RESPONSE_TOKEN
    ):
        raise HTTPException(status_code=401, detail="Unauthorized")

    user_id = payload.get("user_id", "").strip()
    action = payload.get("action", "add")

    if not user_id:
        raise HTTPException(status_code=400, detail="Missing user_id")

    if action not in ("add", "delete"):
        raise HTTPException(status_code=400, detail="Invalid action")

    rule_id = str(payload.get("rule_id") or "") or None
    rule_description = payload.get("rule_description") or None
    alert_id = payload.get("alert_id") or None
    source = payload.get("source") or "wazuh"

    case_id = None

    with get_db() as conn:
        if action == "add":
            conn.execute(
                "INSERT OR IGNORE INTO flagged_sessions (user_id) VALUES (?)",
                (user_id,),
            )
        else:
            row = conn.execute(
                "SELECT case_id FROM thehive_case_links WHERE user_id = ?",
                (user_id,),
            ).fetchone()
            if row:
                case_id = row[0]

            conn.execute(
                "DELETE FROM flagged_sessions WHERE user_id = ?",
                (user_id,),
            )

    if action == "delete" and case_id:
        try:
            close_thehive_case(case_id)
        except Exception as exc:
            print(
                f"Failed to close TheHive case {case_id}: "
                f"{type(exc).__name__}: {exc}",
                file=sys.stderr,
            )

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO active_response_audit
                (user_id, action, source, rule_id, rule_description, alert_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                action,
                source,
                rule_id,
                rule_description,
                alert_id,
            ),
        )

    audit_event = {
        "event_source": "ai_soc_active_response_audit",
        "user_id": user_id,
        "action": action,
        "source": source,
        "rule_id": rule_id,
        "rule_description": rule_description,
        "alert_id": alert_id,
    }
    send_syslog(json.dumps(audit_event))

    if action == "add":
        return {
            "status": "active_response_applied",
            "user_id": user_id,
            "mode": "defensive",
        }

    return {"status": "active_response_removed", "user_id": user_id}


@app.post("/analyst/release")
async def analyst_release(
    payload: dict,
    x_analyst_password: str = Header(""),
):
    if not ANALYST_PASSWORD or not secrets.compare_digest(
        x_analyst_password, ANALYST_PASSWORD
    ):
        raise HTTPException(status_code=401, detail="Unauthorized")

    user_id = str(payload.get("user_id") or "").strip()

    if not user_id:
        raise HTTPException(status_code=400, detail="Missing user_id")

    return await active_response(
        {
            "user_id": user_id,
            "action": "delete",
            "source": "analyst",
        },
        x_active_response_token=ACTIVE_RESPONSE_TOKEN,
    )
