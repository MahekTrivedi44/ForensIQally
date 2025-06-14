# streamlit_app.py

import streamlit as st
import datetime
import json
from analyze_logs import classify_logs_with_llm, analyze_logs, preprocess_logs, anonymize_logs, detect_log_type, store_feedback, store_audit_log
# from streamlit_timeline import timeline # Comment out or remove this line
import plotly.express as px # Import plotly.express
import pandas as pd # Import pandas for DataFrame creation
from analyze_logs import get_feedback_counts
from feedback_enhancer import auto_correct_and_rerun
import os
import firebase_admin
from firebase_admin import credentials, firestore
from firebase_utils import db
from score_auditor import check_consistency
import sys
import sys
import torch
import types

os.environ["STREAMLIT_FILE_WATCHER_BLACKLIST"] = "torch"

# Fix Streamlit inspecting torch internals (both approaches together)
if "torch" in sys.modules:
    sys.modules["torch"].__path__ = []
    torch.classes = types.SimpleNamespace()




# --- Page Configuration ---
st.set_page_config(page_title="ForensIQally", page_icon="🛡️", layout="wide")


# --- Theme State ---
ms = st.session_state

if "themes" not in ms:
    ms.themes = {
        "current_theme": "light",
        "refreshed": False,

        "light": {
    "theme.base": "light",
    "theme.backgroundColor": "#F0F4F8",             # very soft lavender
    "theme.primaryColor": "#A855F7",                # vibrant purple
    "theme.secondaryBackgroundColor": "#F3E8FF",    # soft lilac / muted pink
    "theme.textColor": "#2E1065",                   # deep purple text
    "button_face": "☾"
},



        "dark": {
    "theme.base": "dark",
    "theme.backgroundColor": "#131722",           # deep indigo/navy
    "theme.primaryColor": "#7B83EB",              # bright soft blue
    "theme.secondaryBackgroundColor": "#5E548E",  # elegant violet
    "theme.textColor": "#EAEAEA",                 # soft white
    "button_face": "☀︎"
},
    }
# Apply current theme
tdict = ms.themes[ms.themes["current_theme"]]
for vkey, vval in tdict.items():
    if vkey.startswith("theme"):
        st._config.set_option(vkey, vval)

if not ms.themes["refreshed"]:
    ms.themes["refreshed"] = True
    st.rerun()

def ChangeTheme():
    previous_theme = ms.themes["current_theme"]
    tdict = ms.themes["light"] if previous_theme == "light" else ms.themes["dark"]
    for vkey, vval in tdict.items():
        if vkey.startswith("theme"):
            st._config.set_option(vkey, vval)

    ms.themes["refreshed"] = False
    ms.themes["current_theme"] = "dark" if previous_theme == "light" else "light"
    st.rerun()


# # Apply current theme
# tdict = ms.themes[ms.themes["current_theme"]]
# for vkey, vval in tdict.items():
#     if vkey.startswith("theme"):
#         st._config.set_option(vkey, vval)

# if ms.themes["refreshed"] == False:
#     ms.themes["refreshed"] = True
#     st.rerun()

current_theme = ms.themes["current_theme"]
light_mode = current_theme == "light"

# --- Custom CSS for Theme ---
bg_color = "#F0F4F8" if light_mode else "#131722"
text_color = "#3B0A57" if light_mode else "#EAEAEA"
sidebar_bg = "#F3E8FF" if light_mode else "#5E548E"
st.markdown("""
<link href="https://fonts.googleapis.com/css2?family=Libre+Baskerville&display=swap" rel="stylesheet">
<style>
h1, h2, h3, h4 {
    font-family: 'Libre Baskerville', serif !important;
}
</style>
""", unsafe_allow_html=True)


st.markdown(f"""
    <style>
    body, .main, .reportview-container, .block-container {{
        background-color: {bg_color};
        color: {text_color};
    }}
    div[data-testid="stSidebar"] {{
        background-color: {sidebar_bg};
        color: {text_color};
    }}
    .css-1aumxhk, .css-ffhzg2 {{ color: {text_color} !important; }}
    .stTextInput > div > div > input,
    .stTextArea textarea {{
        background-color: {sidebar_bg};
        color: {text_color};
    }}
    
    </style>
""", unsafe_allow_html=True)
st.markdown("""
    <style>
    /* Cursor pointer for interactive widgets */
    .stRadio > div, .stSlider, .stMultiSelect > div {
        cursor: pointer !important;
    }
    </style>
""", unsafe_allow_html=True)
st.markdown("""
    <style>
    /* Reduce font size in sidebar */
    section[data-testid="stSidebar"] * {
        font-size: 15px !important;
    }

    /* Make radio buttons inline */
    div[data-testid="stRadio"] > div {
        display: flex !important;
        flex-direction: row !important;
        gap: 10px;
        flex-wrap: wrap;
    }

    /* Compress multiselect (risk levels) */
    div[data-baseweb="select"] {
        min-height: 30px !important;
        font-size: 12px !important;
    }

    div[data-baseweb="select"] div {
        padding-top: 2px !important;
        padding-bottom: 2px !important;
    }

    /* Cursor pointer remains */
    .stRadio > div,
    .stSlider,
    .stMultiSelect > div,
    div[data-baseweb="select"] > div,
    div[data-baseweb="select"] svg {
        cursor: pointer !important;
    }
    </style>
""", unsafe_allow_html=True)

st.markdown("""
    <style>
    /* Pull main content up */
    .block-container {
        padding-top: 1rem !important;
    }

    /* Pull the title closer to the top */
    h1 {
        margin-top: 0 !important;
        padding-top: 0 !important;
    }
    </style>
""", unsafe_allow_html=True)


# --- Sidebar ---
with st.sidebar:
    st.markdown("## 🧰 General Settings")
    col1, col2 = st.columns([1, 4])
    with col1:
        st.button(
            ms.themes["light"]["button_face"] if light_mode else ms.themes["dark"]["button_face"],
            on_click=ChangeTheme
        )
    with col2:
        st.markdown("<div style='line-height: 2.6'>Toggle Theme</div>", unsafe_allow_html=True)

    safe_mode = st.toggle("Safe Mode (Redact PII)", value=True)

        
    st.markdown("---")
    st.markdown("## 🗃️ Sample Case Studies")
    case_study_dir = "case_studies"
    case_study_files = [f for f in os.listdir(case_study_dir) if f.endswith((".txt", ".json"))] if os.path.exists(case_study_dir) else []
    selected_case_study = st.selectbox("📂 Choose a file", ["-- None --"] + case_study_files)

    case_study_content = None
    if selected_case_study and selected_case_study != "-- None --":
        with open(os.path.join(case_study_dir, selected_case_study), "r", encoding="utf-8") as f:
            case_study_content = f.read()
        st.success(f"📁 Loaded sample: {selected_case_study}")

    st.markdown("---")

    st.markdown("## 📤 Upload Log File")
    log_file = st.file_uploader("Manual upload", type=["txt", "json"])

    st.markdown("---")

    st.markdown("## 📊 Timeline Filters")
    time_filter = st.radio("⏱️ Time Range", ["1m", "5m", "1h", "All"], horizontal=False)
    selected_risks = st.multiselect("⚠️ Risk Levels", ["High", "Medium", "Low"], default=["High", "Medium", "Low"])
    max_events = st.slider("🎚️ Max Events", min_value=10, max_value=500, value=100, step=10)
    st.session_state["time_filter"] = time_filter
    st.session_state["selected_risks"] = selected_risks
    st.session_state["max_events"] = max_events

    st.markdown("---")

    st.markdown("## 🧠 Insights & Feedback")

    with st.expander("🗂️ View All Feedback"):
        try:
            feedback_docs = db.collection("feedback").stream()
            feedback_data = [doc.to_dict() for doc in feedback_docs]
            if feedback_data:
                df_feedback = pd.DataFrame(feedback_data)
                st.dataframe(df_feedback, use_container_width=True)
            else:
                st.info("No feedback has been submitted yet.")
        except Exception as e:
            st.error(f"Error loading feedback: {e}")

    with st.expander("🚩 Feedback Flags"):
        try:
            feedback_docs = db.collection("feedback").stream()
            feedback_data = [doc.to_dict() for doc in feedback_docs]
            counts = {}
            for entry in feedback_data:
                log_id = entry.get("log_id")
                if log_id:
                    counts[log_id] = counts.get(log_id, 0) + 1
            flagged = {k: v for k, v in counts.items() if v > 1}
            if flagged:
                st.write(flagged)
            else:
                st.write("No logs have multiple feedback entries yet.")
        except Exception as e:
            st.error(f"Error loading feedback flags: {e}")





# --- Dynamic Title ---
if current_theme == "dark":
    st.markdown("""
    <h1 style='font-size: 48px; font-weight: bold; letter-spacing: -2px; line-height: 1.2;'>
        🛡️ <span style='color:#8B5CF6;'>F</span><span style='color:#A78BFA;'>o</span><span style='color:#C084FC;'>r</span><span style='color:#D8B4FE;'>e</span><span style='color:#FBBF24;'>n</span><span style='color:#FB923C;'>s</span><span style='color:#FCD34D;'>I</span><span style='color:#8EC5FC;'>Q</span><span style='color:#A78BFA;'>a</span><span style='color:#C084FC;'>l</span><span style='color:#5591F5;'>l</span><span style='color:#82E1D7;'>y</span>
        – Cyber Incident Autopsy Tool
    </h1>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
    <h1 style='font-size: 48px; font-weight: bold; letter-spacing: -2px; line-height: 1.2;'>
        🛡️ <span style='background: linear-gradient(to right, #A855F7, #EC4899, #FBBF24); 
                         -webkit-background-clip: text; 
                         color: transparent;
                         display: inline-block;'>
            ForensIQally
        </span> <span style='color: #3B0A57;'>– Cyber Incident Autopsy Tool</span>
    </h1>
    """, unsafe_allow_html=True)

st.subheader("Cyber Incident Autopsy with AI 🔍")
st.markdown("Upload logs to generate an incident narrative, remediation plan, and audit trace.")
if current_theme == "dark":
    st.markdown("""
    <style>
    /* Make the file uploader label white in dark mode */
    label[data-testid="stFileUploadLabel"] {
        color: white !important;
        font-weight: bold;
    }
    </style>
    """, unsafe_allow_html=True)

# --- File Upload ---
uploaded_files = st.file_uploader("📁 Upload One or More Log Files", type=["txt", "json"], accept_multiple_files=True)
is_json_file = False
combined_logs = ""
import hashlib

def file_signature(file):
    content = file.read()
    file.seek(0)
    return hashlib.md5(content).hexdigest()

current_signatures = [file_signature(f) for f in uploaded_files] if uploaded_files else []
previous_signatures = st.session_state.get("prev_uploaded", [])

if current_signatures != previous_signatures:
    for key in ["log_data", "llm_result", "audit_data", "llm_classified", "combined_logs", "rag_context"]:
        st.session_state.pop(key, None)
    st.session_state["prev_uploaded"] = current_signatures
import re
timestamp_patterns = [
            re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[\+\-]\d{2}:\d{2})?)\s*[:,\-]?\s*(.+)"),
            re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(.+)"),
            re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}):\s+(.+)"),
            re.compile(r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+(.+)"),
            re.compile(r"^([A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2})\s+(.+)"),
            re.compile(r"^(\d{10})\s+(.+)"),
            re.compile(r"^\[[^\]]+\]\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(.+)"),
        ]
def is_timestamp_only(line):
        line = line.strip()
        for pattern in timestamp_patterns:
            match = pattern.match(line)
            if match:
                # Check if event/content part exists and is not just whitespace
                if len(match.groups()) > 1 and match.group(2).strip():
                    return False  # valid log with content
                else:
                    return True   # timestamp only
        return False  # not a timestamp line
# Load either uploaded logs or case study fallback
if uploaded_files:
    all_logs = []
    for uploaded_file in uploaded_files:
        try:
            content = uploaded_file.read().decode("utf-8")
            # Label each line with the source
            lines = content.splitlines()
            labeled_lines = [
                f"[{uploaded_file.name}] {line}"
                for line in lines
                if line.strip() and line.strip() not in ("[", "]")
            ]
            all_logs.extend(labeled_lines)
            if uploaded_file.name.endswith(".json"):
                is_json_file = True
        except Exception as e:
            st.error(f"Error reading {uploaded_file.name}: {e}")
    combined_logs = "\n".join(all_logs)
    st.session_state["log_data"] = combined_logs  # ✅ Save in session
    

elif case_study_content:
    combined_logs = case_study_content
    is_json_file = selected_case_study.endswith(".json")
else:
    # ❌ If file is removed, wipe all previous state-dependent data
    for key in ["log_data", "llm_result", "audit_data", "llm_classified", "combined_logs", "rag_context"]:
        st.session_state.pop(key, None)
if not combined_logs and "combined_logs" in st.session_state:
    combined_logs = st.session_state["combined_logs"]
    llm_classified = st.session_state.get("llm_classified", [])
    result = st.session_state.get("llm_result", "")
    
    # 👇 Force logs to be reparsed
    log_type = detect_log_type(combined_logs)
    logs = preprocess_logs(combined_logs)
    if safe_mode:
        logs = anonymize_logs(logs)

    log_lines = [
        line.strip()
        for line in logs.splitlines()
        if line.strip() and not is_timestamp_only(line)
    ]

    from rag.vector_store_qdrant import ThreatRAG
    with st.expander("RAG Context Injected"):
        log_lines = [
            line.strip()
            for line in logs.splitlines()
            if line.strip() and not is_timestamp_only(line)
        ]
        with st.spinner("🔍 Loading RAG Context..."):
            try:
                threat_rag = ThreatRAG(log_lines)
                rag_context = threat_rag.search(log_lines)
                st.session_state["rag_context"] = rag_context  # ✅ Store it
            except Exception as e:
                st.warning(f"⚠️ Could not connect to Qdrant: {e}")
                rag_context = ""

        st.code(rag_context if rag_context else "No RAG context found.")


if combined_logs:
    import hashlib
    log_id = f"log_{hashlib.md5(combined_logs[:5000].encode()).hexdigest()}"
    combined_logs = combined_logs.strip()
    if is_json_file:
        try:
            parsed = json.loads(combined_logs)
            combined_logs = json.dumps(parsed, indent=2)
        except Exception as e:
            st.error(f"Invalid JSON file: {e}")

    # --- Process Logs ---
    log_type = detect_log_type(combined_logs)
    st.markdown(f"**Detected Log Type:** <span style='color:lightgreen; font-weight:bold'>{log_type}</span>", unsafe_allow_html=True)

    logs = preprocess_logs(combined_logs)
    if safe_mode:
        logs = anonymize_logs(logs)

    log_lines = [
        line.strip()
        for line in logs.splitlines()
        if line.strip() and not is_timestamp_only(line)
    ]
    @st.cache_data(show_spinner="Classifying logs with LLM...")
    def get_llm_classified(log_lines):
        return classify_logs_with_llm(log_lines)

    llm_classified = get_llm_classified(log_lines)
    st.session_state["combined_logs"] = combined_logs
    st.session_state["llm_classified"] = llm_classified
    

    

    if "llm_classified" not in st.session_state:
        @st.cache_data(show_spinner="Classifying logs with LLM...")
        def get_llm_classified(log_lines):
            return classify_logs_with_llm(log_lines)
        llm_classified = get_llm_classified(log_lines)
        st.session_state.llm_classified = llm_classified
    else:
        llm_classified = st.session_state.llm_classified
    flagged = check_consistency(llm_classified)
    




    # --- LLM Analysis ---
    from feedback_enhancer import load_feedback, auto_correct_and_rerun

    # 🔁 Always load feedback and check if any apply to this log_id
    feedback_data = load_feedback()
    log_feedback = [f for f in feedback_data if f.get("log_id") == log_id]

    # 🔄 Re-analyze if it's a new session or feedback applies to this log_id
    if "llm_result" not in st.session_state or log_feedback:
        with st.spinner("Analyzing logs with LLM + Feedback..."):
            rag_context = st.session_state.get("rag_context", "")
            result, audit_data, _ = auto_correct_and_rerun(logs, log_id, feedback_data_override=feedback_data, rag_context_override=rag_context)
            store_audit_log(log_id, audit_data)
            st.session_state.llm_result = result
            st.session_state.audit_data = audit_data
    else:
        result = st.session_state.llm_result
        audit_data = st.session_state.get("audit_data", {})
        st.session_state["llm_result"] = result

    # ✅ Optional: Display applied feedback below result
    if log_feedback:
        st.markdown("### ♻️ Past Corrections Applied")
        for fb in log_feedback:
            correction = fb.get("correction", "").strip()
            if correction:
                st.markdown(f"- ✏️ `{correction}`")



    st.success("✅ Analysis complete!")
    
    from rag.vector_store_qdrant import ThreatRAG
    with st.expander("RAG Context Injected"):
        log_lines = [
            line.strip()
            for line in logs.splitlines()
            if line.strip() and not is_timestamp_only(line)
        ]
        with st.spinner("🔍 Loading RAG Context..."):
            threat_rag = ThreatRAG(log_lines)
            rag_context = threat_rag.search(log_lines)
            st.session_state["rag_context"] = rag_context  # ✅ Store it

        st.code(rag_context if rag_context else "No RAG context found.")

    # --- Output ---
    # st.subheader("🧠 Incident Narrative")
    # st.code(result, language='text')
    import pandas as pd
    import re

    # --- Custom Style for Cards and Tables ---
    card_bg = "#F6EDFF" if light_mode else "#5E548E"
    card_text = "#3B0A57" if light_mode else "#F8FAFC"
    shadow = "rgba(171, 99, 250, 0.15)" if light_mode else "rgba(147, 94, 255, 0.25)"



    st.markdown(f"""
    <style>
    .styled-section {{
        box-shadow: 0 4px 12px {shadow};
        display: flex;
        border-radius: 16px;
        padding: 1rem;
        margin-bottom: 1.5rem;
        background-color: {card_bg};
        color: {card_text};
    }}

    .styled-section h3 {{
        margin-top: 0;
    }}

    .metric-card {{
        background-color: {card_bg};
        padding: 1rem;
        border-radius: 16px;
        text-align: center;
        margin-bottom: 1rem;
        color: {card_text};
        min-height: 140px;
        width: 100%;
        box-shadow: 0 4px 12px {shadow};
        display: flex;
        flex-direction: column;
        justify-content: center;
    }}

    .metric-card h3 {{
        margin: 0;
        font-family: 'Libre Baskerville', serif;
        font-size: 18px;
        line-height: 1.2;
        white-space: nowrap;
        overflow: hidden;
    }}

    .metric-card p {{
        margin: 0.25rem 0 0;
        font-size: 18px;
        font-weight: 500;
    }}
    </style>
    """, unsafe_allow_html=True)


    # --- Helper: Parse LLM Output Into Sections ---
    def parse_llm_output(result_text):
        sections = {}
        current_section = ""
        lines = result_text.strip().splitlines()

        for line in lines:
            line = line.strip()

            # Match both "SECTION" and "1. SECTION"
            match = re.match(r"^(?:\d+\.\s*)?([A-Z \-]+)$", line)
            if match:
                current_section = match.group(1).strip()
                sections[current_section] = []
            elif current_section:
                sections[current_section].append(line)

        for key in sections:
            sections[key] = "\n".join(sections[key]).strip()

        return sections

    
    # st.markdown("### 🔍 Raw AI Response (Debug)")
    # st.code(result[:1500], language='text')

    # --- Parse Result ---
    sections = parse_llm_output(result)

    # --- Incident Summary Metrics (Estimate from Sections) ---
    impact = sections.get("TOTAL IMPACT", "")
    if not impact:
        impact = result  # fallback to entire text if section missing

    downtime_match = re.search(r"Downtime:\s*(\d+)", impact, re.IGNORECASE)
    downtime = f"{downtime_match.group(1)} minutes" if downtime_match else "N/A"

    # Users Affected: At least 3 users ...
    users_match = re.search(r"Users Affected:\s*(?:At least )?(\d+)", impact, re.IGNORECASE)
    user_count = users_match.group(1) if users_match else "N/A"

    # Failed Jobs: 1 ...
    failed_match = re.search(r"Failed Jobs:\s*(\d+)", impact, re.IGNORECASE)
    failed_jobs = failed_match.group(1) if failed_match else "N/A"
    # # Extract affected users
    # num_users = re.search(r"users? affected.*?(\d+)|at least (\d+)", impact, re.IGNORECASE)
    # user_count = num_users.group(1) if num_users and num_users.group(1) else (num_users.group(2) if num_users else "N/A")

    # # Extract downtime duration
    # downtime_match = re.search(r"(?:approximately|estimated)? ?(\d+ ?(?:minutes?|seconds?))", impact, re.IGNORECASE)
    # downtime = downtime_match.group(1) if downtime_match else "N/A"

    # # Extract failed backups
    # # Match common formats like:
    # # "Failed jobs: 1", "1 failed job", or "1 backup failure"
    # failed = re.search(
    #     r"failed jobs?:\s*(\d+)|(\d+)\s+failed\s+job|(\d+)\s+backup\s+fail",
    #     impact,
    #     re.IGNORECASE
    # )

    # # Safely extract from any of the matching groups
    # failed_jobs = next((g for g in failed.groups() if g), "N/A") if failed else "N/A"


    col1, col2, col3 = st.columns(3)

    col1.markdown(f"""
        <div class='metric-card'>
            <h3>⏱️ Downtime</h3>
            <p>{downtime}</p>
        </div>
    """, unsafe_allow_html=True)

    col2.markdown(f"""
        <div class='metric-card'>
            <h3>👥 Users Affected</h3>
            <p>{user_count}</p>
        </div>
    """, unsafe_allow_html=True)

    col3.markdown(f"""
        <div class='metric-card'>
            <h3>💾 Failed Jobs</h3>
            <p>{failed_jobs}</p>
        </div>
    """, unsafe_allow_html=True)


    # --- Step-by-Step Timeline ---
    if "STEP-BY-STEP TIMELINE" in sections:
        st.markdown("<div class='styled-section'><h3>🕒 Step-by-Step Timeline</h3>", unsafe_allow_html=True)
        st.code(sections["STEP-BY-STEP TIMELINE"], language="text")
        st.markdown("</div>", unsafe_allow_html=True)

    # --- Root Cause ---
    if "ROOT CAUSE" in sections:
        st.markdown("<div class='styled-section'><h3>🧠 Root Cause</h3>", unsafe_allow_html=True)
        st.markdown(sections["ROOT CAUSE"])
        st.markdown("</div>", unsafe_allow_html=True)

    # --- Total Impact ---
    if "TOTAL IMPACT" in sections:
        st.markdown("<div class='styled-section'><h3>📉 Total Impact</h3>", unsafe_allow_html=True)
        st.markdown(sections["TOTAL IMPACT"])
        st.markdown("</div>", unsafe_allow_html=True)

    # --- Remediation Steps ---
    if "REMEDIATION STEPS" in sections:
        st.markdown("<div class='styled-section'><h3>🛠️ Remediation Steps</h3>", unsafe_allow_html=True)
        st.markdown(sections["REMEDIATION STEPS"])
        st.markdown("</div>", unsafe_allow_html=True)

    # --- Risk Score Table ---
    # 🔥 Always show classifier-based Risk & Confidence
    flagged_logs = set(f[0] for f in flagged) if flagged else set()

    fallback_risks = []
    for item in llm_classified:
        log_text = item.get("log", "N/A")
        is_flagged = "⚠️" if log_text in flagged_logs else "✅"
        fallback_risks.append({
            "Status": is_flagged,
            "Log - Breakdown": log_text,
            "Risk Score": item.get("risk_score", "N/A"),
            "Risk Level": item.get("risk_level", "N/A"),
            "Confidence": f"{item.get('confidence', 'N/A')}%",
        })
    df_risk = pd.DataFrame(fallback_risks)
    

    if fallback_risks:
        df_risk = pd.DataFrame(fallback_risks)
        st.markdown("<div class='styled-section'><h3>⚠️ Risk & Confidence Scores</h3>", unsafe_allow_html=True)
        st.dataframe(df_risk, use_container_width=True)

        st.markdown(
    """
    <p style="font-size:15px; color:gray;">
    Check LLM Classification to know on what basis these were justified.  
    Feedback can be added towards the end of the page.<br><br>
    The <b>Consistency Check</b> flags any mismatches between scores, labels, or vague justifications.  
    You can <b>export issues</b>, <b>re-run LLM</b> on flagged logs, and even <b>apply new scores</b> if needed.
    </p>
    """,
    unsafe_allow_html=True
)


        st.markdown("</div>", unsafe_allow_html=True)
    
        with st.expander("🧪 Consistency Check Results"):
            if not flagged:
                st.success("✅ No consistency issues found.")
            else:
                for log, issue in flagged:
                    st.warning(f"⚠️ {issue}\n\n→ `{log}`")

                # Export as CSV
                import pandas as pd
                from io import StringIO

                flagged_df = pd.DataFrame(flagged, columns=["Log", "Issue"])
                csv_buffer = StringIO()
                flagged_df.to_csv(csv_buffer, index=False)
                st.download_button(
                    label="📥Download Flagged Issues as CSV",
                    data=csv_buffer.getvalue(),
                    file_name="flagged_issues.csv",
                    mime="text/csv"
                )
            if flagged:
                if st.button("♻️ Re-run LLM Risk Scoring on Flagged Logs"):
                    flagged_only = [f[0] for f in flagged]  # log text only

                    from analyze_logs import classify_logs_with_llm
                    rerun_results = classify_logs_with_llm(flagged_only)

                    st.markdown("### 🔁 Updated Classifications (Flagged Logs Only)")
                    st.json(rerun_results)

                    st.session_state["rerun_flagged_results"] = rerun_results
            if "rerun_flagged_results" in st.session_state:
                if st.button("✅ Overwrite Original Scores with Updated Values"):
                    updated_logs = {item["log"]: item for item in st.session_state["rerun_flagged_results"]}
                    for i, entry in enumerate(llm_classified):
                        log_text = entry.get("log", "")
                        if log_text in updated_logs:
                            llm_classified[i].update(updated_logs[log_text])
                    st.success("Updated values merged into current session.")
                    del st.session_state["rerun_flagged_results"]
                    st.rerun()
        
    # risk_text = sections.get("RISK SCORE FOR EACH EVENT", "")
    # if risk_text.strip():
    #     risk_lines = risk_text.splitlines()
    #     risk_data = []
    #     for line in risk_lines:
    #         match = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}): (.+?) - (\d+)", line)
    #         if match:
    #             timestamp, description, score = match.groups()
    #             risk_data.append({
    #                 "Time": timestamp,
    #                 "Event": description,
    #                 "Risk Score": int(score)
    #             })
    #     if risk_data:
    #         df_risk = pd.DataFrame(risk_data)
    #         st.markdown("<div class='styled-section'><h3>⚠️ Risk Scores</h3>", unsafe_allow_html=True)
    #         st.dataframe(df_risk, use_container_width=True)
    #         st.markdown("</div>", unsafe_allow_html=True)
    #     else:
    #         st.info("No valid risk score entries were found to display.")
    # else:
    #     # 🔁 FALLBACK TO classify_logs_with_llm
    #     st.warning("⚠️ Risk scores missing from AI response. Falling back to classifier...")
    #     fallback_risks = []
    #     for item in llm_classified:
    #         log = item.get("log", "N/A")
    #         confidence = item.get("confidence", "N/A")
    #         risk_level = item.get("risk_level", "N/A")
    #         fallback_risks.append({
    #             "Log": log,
    #             "Risk Level": risk_level,
    #             "Confidence": f"{confidence}%",
    #         })
    #     if fallback_risks:
    #         df_risk = pd.DataFrame(fallback_risks)
    #         st.markdown("<div class='styled-section'><h3>⚠️ Risk & Confidence</h3>", unsafe_allow_html=True)
    #         st.dataframe(df_risk, use_container_width=True)
    #         st.markdown("</div>", unsafe_allow_html=True)

    # --- Confidence Levels ---
    if "CONFIDENCE LEVELS PER CONCLUSION" in sections:
        conf_lines = sections.get("CONFIDENCE LEVELS PER CONCLUSION", "").splitlines()
        conf_data = []

        for line in conf_lines:
            match = re.match(r"\d+\.\s*(.+?)\s*-\s*(\d+)", line)
            if match:
                label, confidence = match.groups()
                conf_data.append({
                    "Conclusion": label.strip(),
                    "Confidence": f"{confidence}%"
                })

        if conf_data:
            df_conf = pd.DataFrame(conf_data)
            st.markdown("<div class='styled-section'><h3>✅ Confidence Levels</h3>", unsafe_allow_html=True)
            st.dataframe(df_conf, use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)


    # --- Missing Context or Data ---
    if "MISSING CONTEXT OR DATA" in sections:
        st.markdown("<div class='styled-section'><h3>🔍 Missing Context or Data</h3>", unsafe_allow_html=True)
        st.markdown(sections["MISSING CONTEXT OR DATA"])
        st.markdown("</div>", unsafe_allow_html=True)

    # --- Logs Contributing to Each Finding ---
    if "LOGS CONTRIBUTING TO EACH FINDING" in sections:
        st.markdown("<div class='styled-section'><h3>📚 Logs Contributing to Each Finding</h3>", unsafe_allow_html=True)
        st.markdown(sections["LOGS CONTRIBUTING TO EACH FINDING"])
        st.markdown("</div>", unsafe_allow_html=True)


    timeline_data_for_plotly = []


    with st.expander("📄 View Raw Logs"):
        st.code(logs)

    with st.expander("🤖 LLM Classifications"):
        st.json(llm_classified)

    risk_colors_plotly = {
        "High": "#FF9AA2",
        "Medium": "#FFBE7D",
        "Low": "#C7E9B0"
    }
    def wrap_text(text, max_length=60):
        import textwrap
        return "<br>".join(textwrap.wrap(text, width=max_length))

    timeline_data_for_plotly = []
    event_index = 0
    import re
    from dateutil import parser as dtparser
    import datetime
    if is_json_file and "STEP-BY-STEP TIMELINE" in sections:
        classified = llm_classified  # rename for brevity
        

        narrative = sections.get("STEP-BY-STEP TIMELINE", "")
        lines = narrative.splitlines()

        timeline_data_for_plotly = []
        for idx, line in enumerate(lines):
            m = re.match(r"-\s*([\d\-T:\.Z]+):\s*(.+)", line)
            if not m:
                continue
            ts_str, desc = m.groups()
            try:
                ts = dtparser.parse(ts_str)
            except Exception:
                continue

            # 2) normalize tz
            if ts.tzinfo is not None:
                ts = ts.astimezone(datetime.timezone.utc).replace(tzinfo=None)

            # 3) risk (as before)
            risk = "High" if "malicious" in desc.lower() else "Medium"

            # 4) find the matching classified entry
            match = next(
                (c for c in classified if c["log"] in desc),
                {}
            )
            justification = match.get("justification", "N/A")
            confidence    = match.get("confidence",    "N/A")
            timeline_data_for_plotly.append({
                "Event":     f"Step {idx+1}",
                "Start":     ts,
                "End":       ts + datetime.timedelta(seconds=1),
                "Risk Level": risk,
                "Justification": justification,    # <–– add this
                "Confidence":    confidence,       # <–– add this
                "Description":   desc,             # you already have this
            })
    elif is_json_file and not timeline_data_for_plotly:
        try:
            json_logs = json.loads(combined_logs)
            for idx, entry in enumerate(json_logs):
                ts_str = entry.get("timestamp")
                desc = entry.get("event") or entry.get("full_log") or json.dumps(entry)
                ts = dtparser.parse(ts_str)
                timeline_data_for_plotly.append({
                    "Event": f"Event {idx+1}",
                    "Start": ts,
                    "End": ts + datetime.timedelta(seconds=1),
                    "Risk Level": "Medium",  # You can improve this by mapping to LLM output if needed
                    "Description": wrap_text(desc)
                })
        except Exception as e:
            st.warning(f"Timeline fallback parsing failed: {e}")


    elif not is_json_file:
        timestamp_patterns = [
            re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[\+\-]\d{2}:\d{2})?)\s*[:,\-]?\s*(.+)"),
            re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(.+)"),
            re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}):\s+(.+)"),
            re.compile(r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+(.+)"),
            re.compile(r"^([A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2})\s+(.+)"),
            re.compile(r"^(\d{10})\s+(.+)"),
            re.compile(r"^\[[^\]]+\]\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(.+)"),
        ]


        for item in llm_classified:
            line = item["log"]
            original_line = line
            source = "Unknown"
            if line.startswith("["):
                parts = line.split("]", 1)
                if len(parts) == 2:
                    source = parts[0][1:]
                    line = parts[1].strip()

            for pattern in timestamp_patterns:
                match = pattern.match(line)
                if match:
                    ts_str, desc = match.groups()
                    dt = dtparser.parse(ts_str)
                    timeline_data_for_plotly.append({
                        "Event": f"Event {event_index + 1}",
                        "Start": dt,
                        "End": dt + datetime.timedelta(seconds=1),
                        "Risk Level": item["risk_level"],
                        "Description": wrap_text(
                            f"<br>Source: {source}<br>Log: {original_line}<br>Justification: {item.get('justification', 'N/A')}<br>Confidence: {item.get('confidence', 'N/A')}%"
                        )
                    })
                    event_index += 1
                    break  # match found, skip remaining patterns


    df = pd.DataFrame(timeline_data_for_plotly)
    if not timeline_data_for_plotly:
        st.error("❌ No valid timeline data was generated from logs. Check timestamp format in logs.")
        st.stop()

    df.sort_values(by="Start", inplace=True)
    # Extract unique dates for dropdown
    available_dates = sorted(set(df["Start"].dt.date))
    # Date anchor for zooming
    jump_date = st.selectbox("🗓️ Jump to Date", options=available_dates, index=0, format_func=str)


    # Timeline view remains in main area
    st.subheader("📊 Timeline View")
    # Use session values if reloaded
    # Always use sidebar values if available (even after rerun)
    time_filter = st.session_state["time_filter"]
    selected_risks = st.session_state["selected_risks"]
    max_events = st.session_state["max_events"]

    # Filter logs accordingly
    filtered_df = df[df["Risk Level"].isin(selected_risks)]

    # Now limit by time range
    if not filtered_df.empty:
        min_time = filtered_df["Start"].min()
        if time_filter == "1m":
            max_time = min_time + datetime.timedelta(minutes=1)
        elif time_filter == "5m":
            max_time = min_time + datetime.timedelta(minutes=5)
        elif time_filter == "1h":
            max_time = min_time + datetime.timedelta(hours=1)
        else:
            max_time = filtered_df["End"].max()
        
        filtered_df = filtered_df[filtered_df["Risk Level"].isin(selected_risks)].head(max_events)


    # Prevent rendering if timeline spans too far and filter is "All"
    time_span_days = (df["End"].max() - df["Start"].min()).days

    if time_filter == "All" and time_span_days > 30:
        st.toast(f"⚠️ Timeline spans {time_span_days} days. Please choose a shorter time filter or use 'Jump to Date' for better clarity.")
        st.info("⏳ Timeline not rendered due to large time span.")
    else:
        if filtered_df.empty:
            st.info("No valid events to display after filtering.")
        else:
            # 👇 Jump to selected date if provided
            if jump_date and jump_date in df["Start"].dt.date.values:
                jump_day_df = df[df["Start"].dt.date == jump_date]
                if not jump_day_df.empty:
                    min_time = jump_day_df["Start"].min()
                else:
                    min_time = filtered_df["Start"].min()
            else:
                min_time = filtered_df["Start"].min()

            max_time_full = filtered_df['End'].max()

            if time_filter == "1m":
                max_time = min_time + datetime.timedelta(minutes=1)
            elif time_filter == "5m":
                max_time = min_time + datetime.timedelta(minutes=5)
            elif time_filter == "1h":
                max_time = min_time + datetime.timedelta(hours=1)
            else:
                max_time = max_time_full


            fig = px.timeline(
                filtered_df,
                x_start="Start",
                x_end="End",
                y="Event",
                color="Risk Level",
                color_discrete_map=risk_colors_plotly,
                hover_name="Event",
                hover_data={"Description": True, "Event": True, "Start": True, "End": True, "Risk Level": True},
                title="Incident Timeline",
                height=400
            )

            fig.update_yaxes(autorange="reversed", title_text="", showticklabels=False)
            fig.update_layout(
                xaxis_range=[min_time, max_time],
                xaxis_rangeslider_visible=True,
                xaxis_title="Time",
                margin=dict(t=60, b=40)
            )

            st.plotly_chart(fig, use_container_width=True)


    # --- Feedback ---
    # Initialize session state outside the expander to avoid re-triggering reruns
    if "feedback" not in st.session_state:
        st.session_state["feedback"] = ""
    if "correction" not in st.session_state:
        st.session_state["correction"] = ""
    if "submit_feedback" not in st.session_state:
        st.session_state["submit_feedback"] = False
    if "run_again" not in st.session_state:
        st.session_state["run_again"] = False

    with st.expander("📝 Submit Feedback"):
        st.session_state["feedback"] = st.text_area(
            "What's missing, incorrect, or confusing in the output?",
            value=st.session_state["feedback"]
        )
        st.session_state["correction"] = st.text_area(
            "Your suggestion or fix:",
            value=st.session_state["correction"]
        )
        st.session_state["run_again"] = st.checkbox("Re-run analysis using your correction?")

        if st.button("Submit Feedback"):
            store_feedback(log_id, st.session_state["feedback"], st.session_state["correction"])
            st.success("Feedback saved successfully!")
            st.session_state["submit_feedback"] = True
            from feedback_enhancer import load_feedback
            if st.session_state["run_again"] and st.session_state["correction"].strip():
                # Temporarily include current correction before Firebase updates
                feedback_data = load_feedback()
                feedback_data.append({
                    "log_id": log_id,
                    "feedback": st.session_state["feedback"],
                    "correction": st.session_state["correction"]
                })
                new_report, _, used_feedback = auto_correct_and_rerun(
                    logs,  # ✅ The real original logs, not the correction
                    log_id,
                    feedback_data_override=feedback_data  # ← includes both existing & newly added

                )


                # Instead of appending the report, update the session state
                st.session_state["llm_result"] = new_report
                st.session_state["audit_data"] = {}  # Optionally update if needed

                # Force re-render of the existing report section with new data
                st.rerun()


                if used_feedback:
                    st.markdown("### ♻️ Past Corrections Applied")
                    for fb in used_feedback:
                        st.markdown(f"- From `{fb['log_id']}`: {fb['correction']}")
                else:
                    st.warning("⚠️ Feedback was not matched or used.")

            # Clear fields after processing
            st.session_state["feedback"] = ""
            st.session_state["correction"] = ""
            st.session_state["run_again"] = False

    # --- Audit Info ---
    with st.expander("🔎 Audit Log Info"):
        st.json({"Log ID": log_id, **audit_data})
