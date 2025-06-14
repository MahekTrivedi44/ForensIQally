def check_consistency(classified_logs: list[dict]):
    problems = []

    for i, entry in enumerate(classified_logs):
        log = entry.get("log", "")
        score = entry.get("risk_score", -1)
        level = entry.get("risk_level", "").lower()
        confidence = entry.get("confidence", 0)
        justification = entry.get("justification", "").lower()

        # 1. Risk score vs risk level
        if score >= 70 and level != "high":
            problems.append((log, "Score is high but labeled as non-high"))
        elif 40 <= score < 70 and level != "medium":
            problems.append((log, "Score is medium-range but not labeled as Medium"))
        elif score < 40 and level != "low":
            problems.append((log, "Score is low but not labeled as Low"))

        # 2. Confidence too high for vague explanation
        if confidence > 85 and ("possible" in justification or "normal" in justification):
            problems.append((log, "Confidence may be too high for a vague justification"))

        # 3. Critical keywords with low score
        critical_keywords = ["503", "timeout", "failed", "packet loss", "connection error", "unreachable", "exfiltration"]
        if any(k in log.lower() for k in critical_keywords) and score < 70:
            problems.append((log, "Critical log event possibly underrated"))

        # 4. Justification too vague
        vague_phrases = ["normal", "routine", "standard", "typical", "benign", "info only"]
        if any(p in justification for p in vague_phrases) and score > 30:
            problems.append((log, "Vague justification may not support a high score"))

        # 5. Downstream escalation pattern
        if i < len(classified_logs) - 2:
            next_scores = [classified_logs[i + j]["risk_score"] for j in range(1, 3) if "risk_score" in classified_logs[i + j]]
            if score < 30 and any(n >= 80 for n in next_scores):
                problems.append((log, "Low-scored precursor to high-risk events — may be underrated"))

    return problems
