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
import glob



# --- Page Configuration ---
st.set_page_config(page_title="ForensIQally", page_icon="🛡️", layout="wide")

# --- Theme State ---
ms = st.session_state

if "themes" not in ms:
    ms.themes = {
        "current_theme": "light",
        "refreshed": True,

        "light": {
    "theme.base": "light",
    "theme.backgroundColor": "#F0F4F8",           # light cool gray-blue
    "theme.primaryColor": "#9D8DF1",              # dreamy lavender
    "theme.secondaryBackgroundColor": "#C8E7DC",  # soft mint green
    "theme.textColor": "#263238",                 # graphite gray (great contrast)
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

def ChangeTheme():
    previous_theme = ms.themes["current_theme"]
    tdict = ms.themes["light"] if previous_theme == "light" else ms.themes["dark"]
    for vkey, vval in tdict.items():
        if vkey.startswith("theme"):
            st._config.set_option(vkey, vval)
    ms.themes["refreshed"] = False
    ms.themes["current_theme"] = "dark" if previous_theme == "light" else "light"

# Apply current theme
tdict = ms.themes[ms.themes["current_theme"]]
for vkey, vval in tdict.items():
    if vkey.startswith("theme"):
        st._config.set_option(vkey, vval)

if ms.themes["refreshed"] == False:
    ms.themes["refreshed"] = True
    st.rerun()

current_theme = ms.themes["current_theme"]
light_mode = current_theme == "light"

# --- Custom CSS for Theme ---
bg_color = "#F0F4F8" if light_mode else "#131722"
text_color = "#263238" if light_mode else "#EAEAEA"
sidebar_bg = "#C8E7DC" if light_mode else "#5E548E"

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
    st.title("⚙️ Settings")
    st.button(
        ms.themes["light"]["button_face"] if light_mode else ms.themes["dark"]["button_face"],
        on_click=ChangeTheme
    )
    safe_mode = st.toggle("Safe Mode (Redact PII)", value=True)

    # --- Case Study Loader ---
    with st.sidebar.expander("🎓 Load a Case Study"):
        case_files = glob.glob("case_studies/*.txt") + glob.glob("case_studies/*.json")
        case_names = [f.split("/")[-1].replace(".txt", "").replace(".json", "").replace("_", " ").title() for f in case_files]
        case_dict = dict(zip(case_names, case_files))

        selected_case = st.selectbox("Choose a sample case", ["(None)"] + case_names)

        if selected_case != "(None)":
            selected_path = case_dict[selected_case]
            log_id = f"case_{selected_case.lower().replace(' ', '_')}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
            with open(selected_path, "r") as f:
                raw = f.read()
            if selected_path.endswith(".json"):
                try:
                    parsed = json.loads(raw)
                    raw_text = json.dumps(parsed, indent=2)
                    st.session_state["is_json_file"] = True
                except:
                    st.error("❌ Invalid JSON in selected case study.")
                    raw_text = None
            else:
                raw_text = raw
                st.session_state["is_json_file"] = False
            st.session_state["loaded_case_logs"] = raw_text
            st.session_state["case_log_id"] = log_id


    with st.expander("🗂️ View All Feedback"):
        try:
            with open("feedback.json", "r") as f:
                feedback_data = json.load(f)
            df_feedback = pd.DataFrame(feedback_data)
            st.dataframe(df_feedback, use_container_width=True)
        except FileNotFoundError:
            st.info("No feedback has been submitted yet.")

    with st.expander("⚠️ Logs with Frequent Feedback"):
        feedback_counts = get_feedback_counts()
        flagged = {k: v for k, v in feedback_counts.items() if v > 1}
        if flagged:
            st.write(flagged)
        else:
            st.write("No logs have multiple feedback entries yet.")



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
        🛡️ ForensIQally – Cyber Incident Autopsy Tool
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
log_file = st.file_uploader("📁 Upload a Log File", type=["txt", "json"])
is_json_file = log_file and log_file.name.endswith(".json")



# Handle uploaded file or case study
# Support both uploaded file and case study
raw_text = None
log_id = None

if "loaded_case_logs" in st.session_state:
    raw_text = st.session_state.pop("loaded_case_logs")
    log_id = f"case_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
elif log_file:
    raw_text = log_file.read().decode("utf-8")
    log_id = f"log_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
    if log_file.name.endswith(".json"):
        try:
            parsed = json.loads(raw_text)
            raw_text = json.dumps(parsed, indent=2)
        except Exception as e:
            st.error(f"Invalid JSON file: {e}")
if raw_text:
    # --- Process Logs ---
    log_type = detect_log_type(raw_text)
    st.markdown(f"**Detected Log Type:** <span style='color:lightgreen; font-weight:bold'>{log_type}</span>", unsafe_allow_html=True)
    
    logs = preprocess_logs(raw_text)
    if safe_mode:
        logs = anonymize_logs(logs)

    log_lines = [line.strip() for line in logs.splitlines() if line.strip()]
    @st.cache_data(show_spinner="Classifying logs with LLM...")
    def get_llm_classified(log_lines):
        return classify_logs_with_llm(log_lines)

    llm_classified = get_llm_classified(log_lines)
    if "llm_classified" not in st.session_state:
        st.session_state.llm_classified = get_llm_classified(log_lines)
    llm_classified = st.session_state.llm_classified

    # --- LLM Analysis ---
    with st.spinner("Analyzing logs with LLM..."):
        result, audit_data = analyze_logs(logs, log_type)
        store_audit_log(log_id, audit_data)

    st.success("✅ Analysis complete!")

    # --- Output ---
    # st.subheader("🧠 Incident Narrative")
    # st.code(result, language='text')
    import pandas as pd
    import re

    # --- Custom Style for Cards and Tables ---
    st.markdown("""
        <style>
        .styled-section {
            border: 1px solid #444;
            border-radius: 10px;
            padding: 1rem;
            margin-bottom: 1.5rem;
            background-color: #1e1e1e;
        }
        .styled-section h3 {
            margin-top: 0;
            color: #FBBF24;
        }
        .metric-card {
            background-color: #262626;
            padding: 1rem;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 1rem;
            color: #F8FAFC;
        }
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


    # Extract affected users
    num_users = re.search(r"users? affected.*?(\d+)|at least (\d+)", impact, re.IGNORECASE)
    user_count = num_users.group(1) if num_users and num_users.group(1) else (num_users.group(2) if num_users else "N/A")

    # Extract downtime duration
    downtime_match = re.search(r"(?:approximately|estimated)? ?(\d+ ?(?:minutes?|seconds?))", impact, re.IGNORECASE)
    downtime = downtime_match.group(1) if downtime_match else "N/A"

    # Extract failed backups
    # Match common formats like:
    # "Failed jobs: 1", "1 failed job", or "1 backup failure"
    failed = re.search(
        r"failed jobs?:\s*(\d+)|(\d+)\s+failed\s+job|(\d+)\s+backup\s+fail",
        impact,
        re.IGNORECASE
    )

    # Safely extract from any of the matching groups
    failed_jobs = next((g for g in failed.groups() if g), "N/A") if failed else "N/A"


    col1, col2, col3 = st.columns(3)
    col1.markdown(f"<div class='metric-card'><h3>⏱️ Downtime</h3><p>{downtime}</p></div>", unsafe_allow_html=True)
    col2.markdown(f"<div class='metric-card'><h3>👥 Users Affected</h3><p>{user_count}</p></div>", unsafe_allow_html=True)
    col3.markdown(f"<div class='metric-card'><h3>💾 Failed Jobs</h3><p>{failed_jobs}</p></div>", unsafe_allow_html=True)

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
    fallback_risks = []
    for item in llm_classified:
        fallback_risks.append({
            "Log - Breakdown": item.get("log", "N/A"),
            "Risk Score": item.get("risk_score", "N/A"),
            "Risk Level": item.get("risk_level", "N/A"),
            "Confidence": f"{item.get('confidence', 'N/A')}%",
        })
    if fallback_risks:
        df_risk = pd.DataFrame(fallback_risks)
        st.markdown("<div class='styled-section'><h3>⚠️ Risk & Confidence Scores</h3>", unsafe_allow_html=True)
        st.dataframe(df_risk, use_container_width=True)
        st.markdown(
            """
            <p style="font-size:15px; color:gray;">
            Check LLM Classification to know on what basis these were justified.  
            Feedback can be added towards the end of the page.
            </p>
            """,
            unsafe_allow_html=True
        )

        st.markdown("</div>", unsafe_allow_html=True)
    

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

    elif not is_json_file:
        for item in llm_classified:
            try:
                line = item["log"]
                risk = item["risk_level"]
                justification = item.get("justification", "N/A")
                confidence = item.get("confidence", "N/A")
                from dateutil import parser as dtparser
                parts = line.split()
                dt = datetime.datetime.now()
                if len(parts) >= 2:
                    timestamp_str = f"{parts[0]} {parts[1]}"
                    from dateutil import parser as dtparser

                    try:
                        dt = dtparser.parse(timestamp_str)
                    except Exception:
                        continue  # skip if unparseable
            
                timeline_data_for_plotly.append({
                    "Event": f"Event {event_index + 1}",
                    "Start": dt,
                    "End": dt + datetime.timedelta(seconds=1),
                    "Risk Level": risk,
                    "Description": wrap_text(
                        f"Log: {line}<br>Justification: {justification}<br>Confidence: {confidence}"
                        # or tweak to your liking
                    )
                })
                event_index += 1
            except:
                continue

    df = pd.DataFrame(timeline_data_for_plotly)
    if not timeline_data_for_plotly:
        st.error("❌ No valid timeline data was generated from logs. Check timestamp format in logs.")
        st.stop()

    df.sort_values(by="Start", inplace=True)

    # --- UI Controls ---
    # --- UI Controls in Sidebar ---
    with st.sidebar:
        st.subheader("🕒 Timeline Filters")
        time_filter = st.radio("Select Time Range", ["1m", "5m", "1h", "All"], horizontal=False)
        selected_risks = st.multiselect("Risk Levels", ["High", "Medium", "Low"], default=["High", "Medium", "Low"])
        max_events = st.slider("Max Events to Display", min_value=10, max_value=500, value=100, step=10)

    # Timeline view remains in main area
    st.subheader("📊 Timeline View")

    filtered_df = df[df["Risk Level"].isin(selected_risks)].head(max_events)

    if filtered_df.empty:
        st.info("No valid events to display after filtering.")
    else:
        min_time = filtered_df['Start'].min()
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
    with st.expander("📝 Submit Feedback"):
        feedback = st.text_area("What's missing, incorrect, or confusing in the output?")
        correction = st.text_area("Your suggestion or fix:")
        if st.button("Submit Feedback"):
            store_feedback(log_id, feedback, correction)
            st.success("Feedback saved successfully!")

            if st.checkbox("Re-run analysis using your correction?"):
                new_log_text = correction.strip()
                if new_log_text:
                    new_report, used_feedback = auto_correct_and_rerun(new_log_text, log_id)
                    st.markdown("### 🧠 Updated Incident Report Based on Feedback")
                    st.code(new_report, language="text")

                    if used_feedback:
                        st.markdown("### ♻️ Past Corrections Applied")
                        for fb in used_feedback:
                            st.markdown(f"- From `{fb['log_id']}`: {fb['correction']}")
            st.session_state.submit_feedback = True
            st.session_state["feedback"] = ""
            st.session_state["correction"] = ""

    # --- Audit Info ---
    with st.expander("🔎 Audit Log Info"):
        st.json({"Log ID": log_id, **audit_data})
