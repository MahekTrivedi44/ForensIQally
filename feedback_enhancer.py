# feedback_enhancer.py

try:
    from firebase_utils import db
except Exception as e:
    db = None
    print("[WARN] Firebase unavailable:", e)
import json
import difflib
from analyze_logs import analyze_logs, detect_log_type, store_audit_log

def load_feedback():
    if not db:
        print("[WARN] Firebase DB unavailable — skipping feedback load.")
        return []
    try:
        feedback_docs = db.collection("feedback").stream()
        return [doc.to_dict() for doc in feedback_docs]
    except Exception as e:
        print(f"⚠️ Error loading feedback from Firebase: {e}")
        return []

def find_similar_feedback(log_text, feedback_data, threshold=0.6):
    matches = []
    log_lines = log_text.splitlines()

    for fb in feedback_data:
        correction = fb.get("correction", "")
        if not correction:
            continue

        for line in log_lines:
            ratio = difflib.SequenceMatcher(None, line, correction).ratio()
            if ratio >= threshold:
                matches.append(fb)
                break  # Found a match, skip to next feedback

    return matches


def enhance_prompt_with_feedback(log_text, matched_feedback):
    if not matched_feedback:
        return log_text

    feedback_notes = "\n".join(
        [f"- {fb['correction'].strip()}" for fb in matched_feedback if fb.get("correction")]
    )

    enhancement_block = (
        "IMPORTANT: The following are user-supplied expert corrections or suggestions. "
        "Use them to improve the analysis below:\n\n" + feedback_notes
    )

    return f"{enhancement_block}\n\n{log_text}"

# def auto_correct_and_rerun(log_text, log_id, feedback_data_override=None):
#     feedback_data = feedback_data_override if feedback_data_override else load_feedback()
#     matches = find_similar_feedback(log_text, feedback_data)
#     enhanced_text = enhance_prompt_with_feedback(log_text, matches)
#     log_type = detect_log_type(enhanced_text)
#     result, audit = analyze_logs(enhanced_text, log_type)
#     store_audit_log(f"{log_id}_enhanced", audit)
#     return result, matches

def auto_correct_and_rerun(log_text, log_id, feedback_data_override=None, rag_context_override=None):
    feedback_data = feedback_data_override if feedback_data_override else load_feedback()
    matches = find_similar_feedback(log_text, feedback_data)

    if feedback_data_override:
        matches.extend([fb for fb in feedback_data_override if fb not in matches])

    enhanced_text = enhance_prompt_with_feedback(log_text, matches)
    log_type = detect_log_type(enhanced_text)
    result_text, audit_dict = analyze_logs(enhanced_text, log_type, rag_context=rag_context_override)

    if isinstance(audit_dict, dict):
        store_audit_log(f"{log_id}_enhanced", audit_dict)

    return result_text, audit_dict, matches  # ✅ return audit dict too

# # Example Usage:
# if __name__ == "__main__":
#     log_id = "log001"
#     with open("sample_logs.txt", "r") as f:
#         raw = f.read()
#     report, used_feedback = auto_correct_and_rerun(raw, log_id)
#     print("\n--- ENHANCED REPORT ---\n")
#     print(report)
#     if used_feedback:
#         print("\n--- FEEDBACK USED ---\n")
#         for fb in used_feedback:
#             print(f"- From {fb['log_id']}: {fb['correction']}")
