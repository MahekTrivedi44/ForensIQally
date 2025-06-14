# forensiq.py

import os
import re
import json
import requests
from dotenv import load_dotenv
from datetime import datetime
from typing import Tuple
import firebase_admin
from firebase_admin import credentials, firestore
from rag.vector_store_qdrant import ThreatRAG  


load_dotenv()

API_KEY = os.getenv("GROQ_API_KEY")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

# --- Feature 1: Log Preprocessing and Timeline Generator ---
def preprocess_logs(log_text: str) -> str:
    lines = log_text.strip().split('\n')
    lines.sort()  # Assumes logs begin with timestamp
    return '\n'.join(lines)

# --- Feature 2: PII Anonymization (Safe Mode) ---
def anonymize_logs(log_text: str) -> str:
    log_text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP_REDACTED]', log_text)
    log_text = re.sub(r'user "?[\w\-]+"?', '[USER]', log_text, flags=re.IGNORECASE)
    log_text = re.sub(r'[a-zA-Z]:\\(?:[^\\\n]+\\)*[^\\\n]+', '[FILE_PATH]', log_text)
    return log_text

# --- Feature 3: Log Type Detection ---
def detect_log_type(log_text: str) -> str:
    if "powershell" in log_text.lower():
        return "Windows Event Log"
    elif "iptables" in log_text.lower() or "deny" in log_text.lower():
        return "Firewall Log"
    elif "auth" in log_text.lower() or "login" in log_text.lower():
        return "Authentication Log"
    else:
        return "Unknown Log Type"

# --- Feature 4: Core LLM Log Analysis + Risk Score ---
def analyze_logs(log_text: str, log_type: str, rag_context: str = "") -> Tuple[str, dict]:
    if not log_text.strip():
        return "No logs provided.", {}
    if not rag_context:
        try:
            log_lines = log_text.splitlines()
            threat_rag = ThreatRAG(log_lines)
            rag_context = threat_rag.search(log_text.splitlines())
        except Exception as e:
            print("[RAG] Threat context load failed:", e)
            rag_context = "None found"

    prompt = f"""
Analyze the following {log_type} logs and return a structured plain-text report with the following **8 mandatory sections**.
You may use the external threat knowledge (below) **only to improve your reasoning about the logs** — do not generate a report about the threat data itself.

=== THREAT INTELLIGENCE (from MITRE ATT&CK) ===
{rag_context if rag_context else "No threat context found."}

MANDATORY FORMAT:
1. STEP-BY-STEP TIMELINE
2. ROOT CAUSE (root cause + type of cyber attack(if relevent))
3. TOTAL IMPACT (use exact format below — number first, explanation after)
- Downtime: <number of minutes/seconds> <explanation>
- Users Affected: <number or 'At least N users'> <explanation>
- Failed Jobs: <number> <explanation>
4. REMEDIATION STEPS
5. RISK SCORE FOR EACH EVENT — list in format: YYYY-MM-DD HH:MM:SS: Event Summary - Risk Score (0–100). I want the score, not the LEVEL.
6. CONFIDENCE LEVELS PER CONCLUSION — list numbered statements like "1. Cause of failure - 92%"
7. MISSING CONTEXT OR DATA
8. LOGS CONTRIBUTING TO EACH FINDING

REQUIREMENTS:
- Format section titles in ALL CAPS as exact matches above
- Format all sub-points as bulleted lists using '- ' or numbered lists when relevant
- Separate entries with line breaks, not paragraphs
- Do NOT skip any section. If uncertain, leave “Unknown” but still return the section
- Do NOT format with Markdown, bullets, or bold
- Use structured, parseable output
- Base all findings on the evidence in the logs

SCORING GUIDANCE:
- Evaluate events **in their full context**, not in isolation.
- Low-risk actions (e.g., successful logins, backups, configuration changes) should receive **higher risk scores** if they precede or correlate with downstream issues like failures, alerts, access denials, or anomalous behavior.
- Analyze **sequences of events** — if a benign-looking log is the trigger for cascading failures, consider it a significant precursor.
- Risk scores must reflect:
  • Severity of the event
  • Temporal proximity to other anomalies
  • Repetition, frequency, or volume of similar events
  • Anomalous user behavior (unexpected access, odd timing, privilege escalation)
- Use statistical and behavioral inference to detect indirect contributors.
- Do **not default to 0** unless an event is clearly unrelated and contextually irrelevant.
- Justify each risk score briefly — especially when scoring events above or below what might be expected at first glance.

CONFIDENCE SCORING:
- Confidence values must reflect how strong the evidence is. Consider log clarity, repetition, direct cause-effect patterns, and absence of ambiguity.
- Assign higher confidence when conclusions are directly supported by multiple consistent events. Lower it when logs are vague, missing, or indirectly inferred.


Logs:
{log_text}
"""


    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an elite cybersecurity log analyst. Your output MUST include all 8 sections:\n"
                    "1. STEP-BY-STEP TIMELINE\n"
                    "2. ROOT CAUSE (root cause + type of cyber attack(if relevent))\n"
                    "3. TOTAL IMPACT (use exact format below — number first, explanation after)\n"
                    "- Downtime: <number of minutes/seconds> <explanation>\n"
                    "- Users Affected: <number or 'At least N users'> <explanation>\n"
                    "- Failed Jobs: <number> <explanation>\n"
                    "4. REMEDIATION STEPS\n"
                    "5. RISK SCORE FOR EACH EVENT — format: 'YYYY-MM-DD HH:MM:SS: Event Summary - Risk Score (0–100)'\n"
                    "6. CONFIDENCE LEVELS PER CONCLUSION — numbered list with '... - 92%'\n"
                    "7. MISSING CONTEXT OR DATA\n"
                    "8. LOGS CONTRIBUTING TO EACH FINDING\n\n"
                    "Use ALL CAPS section titles exactly as listed above. Do NOT skip any section. If unsure, write 'Unknown'."
                    "IMPORTANT FORMATTING RULES:\n"
                    "- Start each section title in ALL CAPS with a number prefix (e.g., 1. STEP-BY-STEP TIMELINE)\n"
                    "- Format all sub-points as bulleted lists using '- ' or numbered lists when relevant\n"
                    "- Separate entries with line breaks, not paragraphs\n"
                    "- Do not skip any section; if uncertain, write 'Unknown'\n"
                    "- Do not use Markdown or rich formatting — just plain structured text"
                    "SCORING GUIDANCE:\n"
                    "- Evaluate events in their full context, not in isolation.\n"
                    "- Increase the risk score of low-risk events (e.g., successful logins, backups, configuration changes) if they precede or correlate with failures, alerts, access denials, or anomalies.\n"
                    "- Analyze sequences of events. If a benign-looking log triggers cascading failures, treat it as a significant precursor.\n"
                    "- Base each risk score on:\n"
                    "  1. Severity of the event\n"
                    "  2. Temporal proximity to other issues\n"
                    "  3. Frequency, volume, or recurrence\n"
                    "  4. Unusual user behavior (e.g., unexpected access, late-night activity, privilege escalation)\n"
                    "- Use statistical or behavioral inference to detect indirect contributors to incidents.\n"
                    "- Do not assign a risk score of 0 unless the event is clearly unrelated and irrelevant.\n"
                    "- Justify each score briefly, especially when the score differs from what might be expected at first glance.\n"
                    "CONFIDENCE SCORING:\n"
                    "- Confidence values must reflect how strong the evidence is. Consider log clarity, repetition, direct cause-effect patterns, and absence of ambiguity.\n"
                    "- Assign higher confidence when conclusions are directly supported by multiple consistent events. Lower it when logs are vague, missing, or indirectly inferred.\n"

                )
            },
            {"role": "user", "content": f"Log Type: {log_type}\n\nLogs:\n{log_text}"}
        ],
        "temperature": 0.1,  # Makes it more deterministic
        "max_tokens": 30000   # Safer than 12000

    }

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    response = requests.post(GROQ_URL, headers=headers, json=payload)

    if response.status_code == 200:
        try:
            data = response.json()
            result = data["choices"][0]["message"]["content"]
            audit_entry = {
                "log_type": log_type,
                "timestamp": datetime.now().isoformat(),
                "confidence": "Extract from LLM result manually if needed"
            }
            return result, audit_entry
        except Exception as e:
            print("LLM response parse error:", e)
            print("Raw response text:", response.text)
            return "LLM returned an invalid response.", {}
    else:
        print("API error:", response.status_code, response.text)
        return f"Error: {response.status_code} - {response.text}", {}


# --- Feature 5 and 6: Feedback & Audit Storage ---
from firebase_utils import db

def store_feedback(log_id, feedback, correction):
    db.collection("feedback").add({
        "log_id": log_id,
        "feedback": feedback,
        "correction": correction,
        "timestamp": firestore.SERVER_TIMESTAMP
    })
def store_audit_log(log_id, audit_data):
    db.collection("audit_logs").document(log_id).set(audit_data)


def classify_logs_with_llm(log_lines: list[str]) -> list[dict]:
    import os
    import requests
    import json

    GROQ_API_KEY = os.getenv("GROQ_API_KEY")
    GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

    # Batch prompt for ~100 logs
    batched_prompt = """You are a cybersecurity log classifier.
For each of the following logs, return a JSON object with:
- log (original string)
- risk_score (0–100)
- risk_level (High, Medium, Low) based on score (>=70 = High, 40–69 = Medium, <40 = Low)
- justification (short reason)
- confidence (0–100)
SCORING GUIDANCE:
- Evaluate events **in their full context**, not in isolation.
- Low-risk actions (e.g., successful logins, backups, configuration changes) should receive **higher risk scores** if they precede or correlate with downstream issues like failures, alerts, access denials, or anomalous behavior.
- Analyze **sequences of events** — if a benign-looking log is the trigger for cascading failures, consider it a significant precursor.
- Risk scores must reflect:
  • Severity of the event
  • Temporal proximity to other anomalies
  • Repetition, frequency, or volume of similar events
  • Anomalous user behavior (unexpected access, odd timing, privilege escalation)
- Use statistical and behavioral inference to detect indirect contributors.
- Do **not default to 0** unless an event is clearly unrelated and contextually irrelevant.
- Justify each risk score briefly — especially when scoring events above or below what might be expected at first glance.
CONFIDENCE SCORING:
- Confidence values must reflect how strong the evidence is. Consider log clarity, repetition, direct cause-effect patterns, and absence of ambiguity.
- Assign higher confidence when conclusions are directly supported by multiple consistent events. Lower it when logs are vague, missing, or indirectly inferred.

Return a JSON array.

Logs:
""" + "\n".join([f"{i+1}. {log}" for i, log in enumerate(log_lines[:100])])

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "user", "content": batched_prompt}
        ],
        "temperature": 0.1,  # Makes it more deterministic
        "max_tokens": 30000   # Safer than 12000

    }

    try:
        res = requests.post(GROQ_URL, headers=headers, json=payload)
        res.raise_for_status()
        content = res.json()["choices"][0]["message"]["content"]

        # Extract JSON block from the output
        match = re.search(r"\[.*\]", content, re.DOTALL)
        if match:
            json_str = match.group(0)
            return json.loads(json_str)
        else:
            print("No JSON array found in Groq response.")
            return []
    except Exception as e:
        print(f"[GROQ ERROR] {e}")
        return []

def get_feedback_counts(filepath="feedback.json"):
    if not os.path.exists(filepath):
        return {}
    with open(filepath, "r") as f:
        data = json.load(f)
    counts = {}
    for entry in data:
        log_id = entry["log_id"]
        counts[log_id] = counts.get(log_id, 0) + 1
    return counts

# --- Main Function ---
def main(file_path: str, log_id: str, safe_mode=True):
    with open(file_path, "r") as f:
        raw_logs = f.read()

    logs = preprocess_logs(raw_logs)
    if safe_mode:
        logs = anonymize_logs(logs)

    log_type = detect_log_type(logs)
    report, audit = analyze_logs(logs, log_type)

    print("\n--- INCIDENT REPORT ---\n")
    print(report)

    if audit:
        store_audit_log(log_id, audit)

    # Simulated user feedback capture
    give_feedback = input("\nWould you like to submit feedback? (y/n): ")
    if give_feedback.lower() == 'y':
        fb = input("Enter feedback: ")
        corr = input("Enter your correction/suggestion: ")
        store_feedback(log_id, fb, corr)
        print("Feedback saved.")

# --- Entry Point ---
if __name__ == "__main__":
    main(file_path="sample_logs.txt", log_id="log001", safe_mode=True)
