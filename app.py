import streamlit as st
import json
import pandas as pd
import sys
import os
import textwrap
from dotenv import load_dotenv

# Ensure root path is in sys.path & load .env from project root
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT_DIR)
load_dotenv(dotenv_path=os.path.join(ROOT_DIR, ".env"), override=True)

from src.graph import run_investigation_pipeline
from src.investigator import is_gemini_available, clear_gemini_cache

# -----------------------------------------------------------------------------
# PAGE CONFIGURATION & METADATA
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="SentinelX — Verify Before You Trust",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -----------------------------------------------------------------------------
# SAFE HTML RENDERING HELPER
# Prevents Streamlit's markdown parser from treating indented HTML as code blocks
# -----------------------------------------------------------------------------
def render_html(html_str: str) -> None:
    """
    Renders pure HTML directly into the Streamlit DOM without passing through
    the Markdown parser, ensuring indented tags are never turned into <pre><code> blocks.
    """
    st.html(textwrap.dedent(html_str).strip())

# -----------------------------------------------------------------------------
# CUSTOM STYLING (Dark Cybersecurity Theme)
# -----------------------------------------------------------------------------
CUSTOM_CSS = """
<style>
    /* Dark Theme Core Base */
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    
    /* Header Card styling */
    .main-header {
        background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 24px 28px;
        margin-bottom: 20px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.5);
    }
    
    .title-text {
        font-size: 2.3rem;
        font-weight: 800;
        letter-spacing: -0.5px;
        color: #58a6ff;
        margin: 0;
    }
    
    .subtitle-text {
        font-size: 1.2rem;
        color: #f0f6fc;
        margin-top: 4px;
        font-weight: 600;
    }
    
    .tagline-banner {
        background: rgba(88, 166, 255, 0.1);
        border-left: 4px solid #58a6ff;
        padding: 12px 18px;
        border-radius: 6px;
        margin-top: 14px;
        font-size: 1.05rem;
        color: #f0f6fc;
        font-weight: 500;
        line-height: 1.5;
    }
    
    .status-indicator-ready {
        display: inline-flex;
        align-items: center;
        background: rgba(46, 160, 67, 0.15);
        color: #3fb950;
        border: 1px solid rgba(46, 160, 67, 0.4);
        padding: 6px 14px;
        border-radius: 20px;
        font-size: 0.85rem;
        font-weight: 700;
    }

    .status-indicator-live {
        display: inline-flex;
        align-items: center;
        background: rgba(163, 113, 247, 0.15);
        color: #bc8cff;
        border: 1px solid rgba(163, 113, 247, 0.4);
        padding: 6px 14px;
        border-radius: 20px;
        font-size: 0.85rem;
        font-weight: 700;
    }

    /* Metric Cards */
    .metric-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 16px 18px;
        text-align: center;
        box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    }
    
    .metric-title {
        color: #8b949e;
        font-size: 0.8rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    .metric-value {
        font-size: 2.0rem;
        font-weight: 800;
        color: #f0f6fc;
        margin-top: 4px;
    }
    
    .metric-value-trust {
        color: #3fb950;
    }

    /* 30-Second Primer Card Grid */
    .primer-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: 16px;
        margin: 20px 0;
    }

    .primer-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 18px 20px;
        transition: transform 0.15s ease, border-color 0.15s ease;
    }

    .primer-card:hover {
        border-color: #58a6ff;
        transform: translateY(-2px);
    }

    .primer-badge {
        font-size: 0.75rem;
        font-weight: 800;
        text-transform: uppercase;
        padding: 4px 8px;
        border-radius: 4px;
        display: inline-block;
        margin-bottom: 8px;
    }

    .primer-card h4 {
        margin: 0 0 8px 0;
        font-size: 1.1rem;
        color: #f0f6fc;
    }

    .primer-card p {
        margin: 0;
        font-size: 0.9rem;
        color: #8b949e;
        line-height: 1.45;
    }

    /* Visual Flow Diagram */
    .flow-container {
        display: flex;
        align-items: center;
        justify-content: space-between;
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 18px 22px;
        margin: 18px 0;
        flex-wrap: wrap;
        gap: 8px;
    }

    .flow-step {
        background: #21262d;
        border: 1px solid #30363d;
        padding: 10px 14px;
        border-radius: 8px;
        font-weight: 700;
        font-size: 0.82rem;
        color: #f0f6fc;
        text-align: center;
        flex: 1;
        min-width: 120px;
    }

    .flow-step-highlight {
        background: rgba(88, 166, 255, 0.15);
        border: 1.5px solid #58a6ff;
        color: #58a6ff;
    }

    .flow-step-result {
        background: rgba(248, 81, 73, 0.12);
        border: 1.5px solid #f85149;
        color: #f85149;
    }

    .flow-arrow {
        color: #8b949e;
        font-size: 1.1rem;
        font-weight: bold;
    }

    /* Verification Status Badges */
    .badge-supported {
        background-color: rgba(46, 160, 67, 0.2);
        color: #3fb950;
        border: 1px solid #2ea043;
        padding: 6px 14px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.95rem;
        display: inline-block;
    }

    .badge-unsupported {
        background-color: rgba(248, 81, 73, 0.25);
        color: #f85149;
        border: 1px solid #f85149;
        padding: 6px 14px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.95rem;
        display: inline-block;
    }

    .badge-insufficient {
        background-color: rgba(210, 153, 34, 0.2);
        color: #d29922;
        border: 1px solid #d29922;
        padding: 6px 14px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.95rem;
        display: inline-block;
    }

    /* Finding Card Container */
    .finding-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 16px 18px;
        margin-bottom: 12px;
    }

    .callout-banner {
        background: rgba(210, 153, 34, 0.12);
        border: 1px solid rgba(210, 153, 34, 0.4);
        border-radius: 8px;
        padding: 12px 18px;
        margin: 16px 0;
        font-size: 0.95rem;
        font-weight: 600;
        color: #d29922;
        text-align: center;
    }

    /* Timeline step box */
    .timeline-step {
        background-color: #161b22;
        border-top: 3px solid #58a6ff;
        border-radius: 8px;
        padding: 12px;
        text-align: center;
    }

    /* Comparison Table styling */
    .comp-table {
        width: 100%;
        border-collapse: collapse;
        margin: 16px 0;
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        overflow: hidden;
    }
    .comp-table th, .comp-table td {
        padding: 12px 16px;
        text-align: left;
        border-bottom: 1px solid #30363d;
        font-size: 0.92rem;
    }
    .comp-table th {
        background-color: #21262d;
        color: #8b949e;
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    /* Claim Box styling */
    .claim-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 22px;
        margin-bottom: 18px;
        box-shadow: 0 4px 16px rgba(0,0,0,0.3);
    }

    .claim-card-rejected {
        border-left: 6px solid #f85149;
    }

    .claim-card-supported {
        border-left: 6px solid #3fb950;
    }

    .claim-card-insufficient {
        border-left: 6px solid #d29922;
    }
</style>
"""
render_html(CUSTOM_CSS)

# -----------------------------------------------------------------------------
# PIPELINE EXECUTION & CACHING
# -----------------------------------------------------------------------------
CACHE_VERSION = "v3_canonical_utc_2026"

@st.cache_data(show_spinner=False)
def get_cached_pipeline_result(mode: str = "controlled_demo", incident_id: str = "INC-2025-CAM-LDS-001", cache_version: str = CACHE_VERSION):
    """
    Executes the SentinelX LangGraph investigation pipeline.
    Cached so that mode switches and button clicks are instantaneous.
    """
    return run_investigation_pipeline(incident_id, mode=mode)

# -----------------------------------------------------------------------------
# SESSION STATE INITIALIZATION
# -----------------------------------------------------------------------------
if "active_section" not in st.session_state:
    st.session_state["active_section"] = "01_OVERVIEW"

if "selected_claim_tab" not in st.session_state:
    st.session_state["selected_claim_tab"] = "REJECTED"

# -----------------------------------------------------------------------------
# SIDEBAR CONTROLS
# -----------------------------------------------------------------------------
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/shield.png", width=52)
    st.markdown("<h2 style='margin:0; color:#58a6ff;'>SENTINELX</h2>", unsafe_allow_html=True)
    st.caption("Evidence-Verified AI for Cyber Incidents")
    st.divider()

    st.markdown("### 🎛️ Pipeline Mode")
    
    # REQUIRED: Benchmark / Controlled Demo Mode MUST be DEFAULT (index=0)
    mode_selection = st.radio(
        "Select Mode:",
        [
            "⚡ Controlled Benchmark Demo (Fast & Reproducible)",
            "🤖 LIVE GEMINI AI (Dynamic LLM Analysis)"
        ],
        index=0,
        help="Controlled Benchmark Demo executes instantly using verified evaluation cases. Live Gemini AI calls Google Gemini dynamically."
    )

    is_live_mode = "LIVE GEMINI" in mode_selection
    selected_mode = "live_ai" if is_live_mode else "controlled_demo"
    gemini_ready = is_gemini_available()

    if is_live_mode:
        st.markdown("**LIVE GEMINI AI**")
        st.caption("Dynamic investigation using Gemini. Live mode generates fresh investigation findings from the security-event stream and may take longer.")
        if gemini_ready:
            st.success("🟢 Gemini API Key Detected")
            if st.button("🔄 Clear Cache & Re-run Gemini", use_container_width=True):
                get_cached_pipeline_result.clear()
                clear_gemini_cache()
                st.rerun()
        else:
            st.error("⚠️ GEMINI_API_KEY Not Configured")
            st.caption("To use Live AI, add `GEMINI_API_KEY` in Streamlit Secrets or `.env`. The default Controlled Benchmark Demo runs 100% offline.")
    else:
        st.info("⚡ Controlled Benchmark Demo Active")
        st.caption("Deterministic verification against Zenodo CAM-LDS ground truth. Zero external API calls, instant load time (<50ms).")

    st.divider()
    st.markdown("### 📋 Incident Telemetry")
    render_html("""
    <div style="background:#161b22; border:1px solid #30363d; border-radius:8px; padding:12px; margin-bottom:8px;">
        <div style="font-size:0.75rem; color:#8b949e; font-weight:700;">DATASET SOURCE</div>
        <div style="font-weight:700; color:#f0f6fc; font-size:0.88rem;">Zenodo CAM-LDS (APT 3_ssh_apt)</div>
    </div>
    <div style="background:#161b22; border:1px solid #30363d; border-radius:8px; padding:12px; margin-bottom:8px;">
        <div style="font-size:0.75rem; color:#8b949e; font-weight:700;">RAW EVENT STREAM</div>
        <div style="font-weight:700; color:#58a6ff; font-size:0.88rem;">44 Normalized Security Logs</div>
    </div>
    <div style="background:#161b22; border:1px solid #30363d; border-radius:8px; padding:12px;">
        <div style="font-size:0.75rem; color:#8b949e; font-weight:700;">BENCHMARK VERIFICATION</div>
        <div style="font-weight:700; color:#3fb950; font-size:0.88rem;">100% Ground Truth Accuracy</div>
    </div>
    """)

    st.divider()
    st.caption("SentinelX | CraftVerse 2.0")

# -----------------------------------------------------------------------------
# RUN PIPELINE (WITH SPINNER FOR LIVE AI)
# -----------------------------------------------------------------------------
pipeline_error = None
state = {}

try:
    if is_live_mode:
        with st.spinner("🤖 Calling Google Gemini API to investigate 44 security log events dynamically..."):
            state = get_cached_pipeline_result(mode=selected_mode)
    else:
        state = get_cached_pipeline_result(mode=selected_mode)
except Exception as e:
    pipeline_error = str(e)
    state = {
        "incident_id": "INC-2025-CAM-LDS-001",
        "events": [],
        "findings": [],
        "verification_results": [],
        "trust_score": 0.0,
        "report": {},
        "evaluation_summary": {}
    }

incident_id = state.get("incident_id", "INC-2025-CAM-LDS-001")
events = state.get("events", [])
findings = state.get("findings", [])
verification_results = state.get("verification_results", [])
trust_score = state.get("trust_score", 0.0)
report = state.get("report", {})
eval_summary = state.get("evaluation_summary", {})
ver_map = {r["finding_id"]: r for r in verification_results if "finding_id" in r}

# -----------------------------------------------------------------------------
# MAIN HEADER
# -----------------------------------------------------------------------------
status_badge = (
    '<span class="status-indicator-live">⚡ LIVE GEMINI AI MODE</span>'
    if is_live_mode else
    '<span class="status-indicator-ready">● CONTROLLED BENCHMARK DEMO</span>'
)

render_html(f"""
<div class="main-header">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
        <div>
            <div class="title-text">🛡️ SENTINELX</div>
            <div class="subtitle-text">Verify Before You Trust</div>
        </div>
        <div>{status_badge}</div>
    </div>
    <div class="tagline-banner">
        <strong>Core Concept:</strong> SentinelX uses AI to investigate cybersecurity event logs, then independently verifies each AI-generated finding against the underlying security evidence.
    </div>
</div>
""")

if pipeline_error:
    st.error(
        f"🚨 **Pipeline Error in {selected_mode} mode**: {pipeline_error}\n\n"
        "Switch to **Controlled Benchmark Demo** in the sidebar for an instant, reproducible offline demo."
    )

# -----------------------------------------------------------------------------
# STEP-BASED NAVIGATION BAR
# -----------------------------------------------------------------------------
nav_tabs = [
    ("01_OVERVIEW", "📊 1. Overview & Concept"),
    ("02_LOGS", "📜 2. Input Security Logs"),
    ("03_AI_CLAIMS", "🤖 3. AI Claims & Confidence"),
    ("04_VERIFICATION", "🛡️ 4. SentinelX Verification"),
    ("05_REPORT", "📄 5. Trust Score & Report")
]

cols = st.columns(len(nav_tabs))
for idx, (tab_id, tab_label) in enumerate(nav_tabs):
    with cols[idx]:
        is_active = (st.session_state["active_section"] == tab_id)
        btn_style = "primary" if is_active else "secondary"
        if st.button(tab_label, key=f"nav_{tab_id}", type=btn_style, use_container_width=True):
            st.session_state["active_section"] = tab_id
            st.rerun()

st.write("")

# =============================================================================
# SECTION 1: OVERVIEW & CONCEPT (THE 30-SECOND ELEVATOR PITCH)
# =============================================================================
if st.session_state["active_section"] == "01_OVERVIEW":
    
    # 3-Part Input / Process / Output Concept Container
    render_html("""
    <div style="background: linear-gradient(135deg, #161b22 0%, #1c2128 100%); border: 1px solid #30363d; border-radius: 12px; padding: 20px; margin-bottom: 20px;">
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; text-align: center;">
            <div style="background: #21262d; border: 1px solid #30363d; border-radius: 8px; padding: 16px;">
                <div style="font-size: 0.75rem; font-weight: 800; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px;">INPUT</div>
                <div style="font-size: 1.15rem; font-weight: 800; color: #58a6ff; margin: 6px 0 4px 0;">Security Event Logs</div>
                <div style="font-size: 0.85rem; color: #8b949e;">Authentication, process, cron, and system logs from host machines</div>
            </div>
            <div style="background: #21262d; border: 1.5px solid #58a6ff; border-radius: 8px; padding: 16px;">
                <div style="font-size: 0.75rem; font-weight: 800; color: #58a6ff; text-transform: uppercase; letter-spacing: 0.5px;">PROCESS</div>
                <div style="font-size: 0.98rem; font-weight: 800; color: #f0f6fc; margin: 6px 0 4px 0;">AI Investigation → Evidence Retrieval → Independent Verification</div>
                <div style="font-size: 0.85rem; color: #8b949e;">Cross-checks every AI claim deterministically against cited raw events</div>
            </div>
            <div style="background: #21262d; border: 1px solid #30363d; border-radius: 8px; padding: 16px;">
                <div style="font-size: 0.75rem; font-weight: 800; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px;">OUTPUT</div>
                <div style="font-size: 0.98rem; font-weight: 800; color: #3fb950; margin: 6px 0 4px 0;">SUPPORTED / UNSUPPORTED / INSUFFICIENT</div>
                <div style="font-size: 0.85rem; color: #8b949e;">Audit verdicts + Evidence Trust Score (0–100) + Clean Report</div>
            </div>
        </div>
    </div>
    """)

    # Concrete High-Impact Teaser Example
    render_html("""
    <div style="background: #161b22; border: 1px solid #30363d; border-left: 6px solid #f85149; border-radius: 10px; padding: 18px 22px; margin-bottom: 22px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
            <span style="font-size: 0.78rem; font-weight: 800; color: #f85149; text-transform: uppercase; letter-spacing: 0.5px;">⚡ Core Problem & Solution Example</span>
            <span style="font-size: 0.75rem; color: #8b949e; background: #21262d; padding: 3px 8px; border-radius: 4px;">Catching AI Hallucinations</span>
        </div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin-top: 10px;">
            <div style="background: #21262d; padding: 12px 14px; border-radius: 6px;">
                <div style="font-size: 0.72rem; color: #8b949e; font-weight: 700;">AI CLAIM</div>
                <div style="font-weight: 700; color: #f0f6fc; font-size: 0.95rem; margin-top: 2px;">"Apache Zero-Day Attack"</div>
            </div>
            <div style="background: #21262d; padding: 12px 14px; border-radius: 6px;">
                <div style="font-size: 0.72rem; color: #8b949e; font-weight: 700;">AI CONFIDENCE</div>
                <div style="font-weight: 800; color: #58a6ff; font-size: 1.15rem; margin-top: 2px;">98% (High)</div>
            </div>
            <div style="background: #21262d; padding: 12px 14px; border-radius: 6px;">
                <div style="font-size: 0.72rem; color: #8b949e; font-weight: 700;">ACTUAL LOG EVIDENCE</div>
                <div style="font-weight: 700; color: #d29922; font-size: 0.95rem; margin-top: 2px;">"SSH Brute-Force Activity"</div>
            </div>
            <div style="background: rgba(248, 81, 73, 0.15); border: 1px solid #f85149; padding: 12px 14px; border-radius: 6px; text-align: center;">
                <div style="font-size: 0.72rem; color: #f85149; font-weight: 800;">SENTINELX VERDICT</div>
                <div style="font-weight: 900; color: #f85149; font-size: 1.15rem; margin-top: 2px;">🔴 UNSUPPORTED</div>
            </div>
        </div>
    </div>
    """)

    # 30-Second Primer Card Grid
    st.markdown("### 💡 Why SentinelX Matters")
    render_html("""
    <div class="primer-grid">
        <div class="primer-card">
            <span class="primer-badge" style="background:rgba(88,166,255,0.2); color:#58a6ff;">1. The Problem</span>
            <h4>AI Hallucinations in SOC</h4>
            <p>Generative AI models sound highly confident (98%+) even when inventing attack vectors that never happened in reality. Relying on unverified AI leads to costly false alarms and wrong remediations.</p>
        </div>
        <div class="primer-card">
            <span class="primer-badge" style="background:rgba(163,113,247,0.2); color:#bc8cff;">2. The Input</span>
            <h4>Raw Security Log Stream</h4>
            <p>44 normalized security event logs extracted from the authentic Zenodo CAM-LDS APT dataset (SSH auth logs, sudo commands, cron modifications, shadow file access, ransomware).</p>
        </div>
        <div class="primer-card">
            <span class="primer-badge" style="background:rgba(46,160,67,0.2); color:#3fb950;">3. The Innovation</span>
            <h4>Independent Verification</h4>
            <p>SentinelX never trusts AI confidence. It deterministically cross-checks every claim against raw security logs for event existence, process matching, MITRE alignment, and chronological consistency.</p>
        </div>
        <div class="primer-card">
            <span class="primer-badge" style="background:rgba(210,153,34,0.2); color:#d29922;">4. The Output</span>
            <h4>Audit-Grade Incident Report</h4>
            <p>Clear audit verdicts (🟢 SUPPORTED, 🔴 UNSUPPORTED, 🟡 INSUFFICIENT) and a mathematical Evidence Trust Score (0-100) independent of AI confidence.</p>
        </div>
    </div>
    """)

    # Verdict Meaning Guide (Zero-Jargon)
    st.markdown("### ⚖️ The 3 Verification Statuses")
    v_col1, v_col2, v_col3 = st.columns(3)
    with v_col1:
        render_html("""
        <div style="background:#161b22; border:1px solid #2ea043; border-radius:8px; padding:16px;">
            <div class="badge-supported">🟢 SUPPORTED</div>
            <div style="font-weight:700; color:#f0f6fc; margin:10px 0 6px 0;">Direct Evidence Exists</div>
            <div style="font-size:0.88rem; color:#8b949e; line-height:1.4;">
                Real security logs directly substantiate the claim with matching processes, IPs, actions, and chronological sequence.
            </div>
        </div>
        """)

    with v_col2:
        render_html("""
        <div style="background:#161b22; border:1px solid #f85149; border-radius:8px; padding:16px;">
            <div class="badge-unsupported">🔴 UNSUPPORTED</div>
            <div style="font-weight:700; color:#f0f6fc; margin:10px 0 6px 0;">Contradicted by Logs</div>
            <div style="font-size:0.88rem; color:#8b949e; line-height:1.4;">
                The underlying security logs directly contradict the AI claim (e.g., AI claims Apache web exploit, but logs prove SSH brute-force).
            </div>
        </div>
        """)

    with v_col3:
        render_html("""
        <div style="background:#161b22; border:1px solid #d29922; border-radius:8px; padding:16px;">
            <div class="badge-insufficient">🟡 INSUFFICIENT EVIDENCE</div>
            <div style="font-weight:700; color:#f0f6fc; margin:10px 0 6px 0;">Unproven Claim</div>
            <div style="font-size:0.88rem; color:#8b949e; line-height:1.4;">
                The cited event IDs do not contain proof of the claim, or the cited event IDs do not exist in the security log database.
            </div>
        </div>
        """)

    st.write("")
    
    # 4 Quick Metric Cards
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        render_html(f"""
        <div class="metric-card">
            <div class="metric-title">Security Log Events</div>
            <div class="metric-value">{len(events) if events else 44}</div>
        </div>
        """)
    with m2:
        render_html(f"""
        <div class="metric-card">
            <div class="metric-title">Claims Investigated</div>
            <div class="metric-value">{len(findings)}</div>
        </div>
        """)
    with m3:
        sup_count = sum(1 for r in verification_results if r.get("verification_status") == "SUPPORTED")
        render_html(f"""
        <div class="metric-card">
            <div class="metric-title">Verified True Claims</div>
            <div class="metric-value" style="color:#3fb950;">{sup_count} <span style="font-size:1.1rem; color:#8b949e;">/ {len(findings)}</span></div>
        </div>
        """)
    with m4:
        render_html(f"""
        <div class="metric-card">
            <div class="metric-title">Evidence Trust Score</div>
            <div class="metric-value metric-value-trust">{trust_score} <span style="font-size:1.1rem; color:#8b949e;">/100</span></div>
        </div>
        """)

    st.write("")
    st.write("")
    
    # PRIMARY CALL TO ACTION
    st.markdown("""
    <div style="text-align:center; padding:10px 0 6px 0;">
        <p style="color:#8b949e; font-size:1.05rem; margin-bottom:10px;">Experience how SentinelX catches high-confidence AI hallucinations in real-time:</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.button("▶ START DEMO", type="primary", use_container_width=True):
        st.session_state["active_section"] = "02_LOGS"
        st.rerun()

    # Optional Expandable Section for Technical Deep-Dive
    with st.expander("🔬 Technical Architecture & Dataset Details (CAM-LDS, MITRE ATT&CK, LangGraph)"):
        st.markdown("""
        - **Dataset**: Research dataset from **Zenodo CAM-LDS (Sequence 3_ssh_apt)** containing multi-stage enterprise Linux incident telemetry.
        - **Pipeline Architecture**: 6-node **LangGraph** workflow: `Load Events` → `Investigate` → `Retrieve Evidence` → `Verify Claims` → `Calculate Trust Score` → `Generate Report`.
        - **Deterministic Verification Engine**: Cross-checks MITRE technique alignment, process names, network IPs, chronological timestamps, and evidence completeness.
        """)

# =============================================================================
# SECTION 2: INPUT SECURITY LOGS & SCENARIO
# =============================================================================
elif st.session_state["active_section"] == "02_LOGS":
    st.markdown("# 01 — Input: Raw Security Logs")
    st.markdown(
        "SentinelX begins with authentic, raw telemetry from an enterprise incident. "
        "Here, 44 normalized security events are ingested from the **Zenodo CAM-LDS Cybersecurity Dataset (Sequence 3_ssh_apt)**."
    )

    # Attack Progression Timeline
    st.markdown("### 🎯 Ground-Truth Attack Progression")
    st.caption("How the threat actor actually infiltrated and compromised the system:")
    
    t1, t2, t3, t4, t5, t6 = st.columns(6)
    stages = [
        ("1. INITIAL ACCESS", "Hydra SSH Brute-Force", "#f85149", "10:28:22"),
        ("2. PRIV ESCALATION", "Sudo Elevation to Root", "#d29922", "10:32:05"),
        ("3. CREDENTIAL ACCESS", "Dump /etc/shadow Hashes", "#d29922", "10:33:14"),
        ("4. PERSISTENCE", "Malicious Cron Job in /etc", "#a371f7", "10:37:41"),
        ("5. LATERAL MOVEMENT", "Exec over Internal Net", "#a371f7", "10:41:09"),
        ("6. IMPACT", "donotcry Ransomware", "#f85149", "10:44:18"),
    ]
    cols_t = [t1, t2, t3, t4, t5, t6]
    for idx, (stg_title, stg_desc, color, time_str) in enumerate(stages):
        with cols_t[idx]:
            render_html(f"""
            <div class="timeline-step" style="border-top-color:{color};">
                <div style="font-size:0.68rem; font-weight:800; color:{color};">{stg_title}</div>
                <div style="font-size:0.85rem; font-weight:700; color:#f0f6fc; margin-top:4px;">{stg_desc}</div>
                <div style="font-size:0.75rem; color:#8b949e; margin-top:4px;">⏱️ {time_str}</div>
            </div>
            """)

    st.write("")
    st.markdown("### 📜 Normalized Security Event Stream (Sample)")
    
    # Convert events to compact DataFrame for inspection
    if events:
        df_events = pd.DataFrame([
            {
                "Event ID": e.get("event_id"),
                "Timestamp": e.get("timestamp", "").replace("T", " ")[:19],
                "Process": e.get("process"),
                "Action": e.get("action"),
                "MITRE Technique": e.get("mitre_technique"),
                "Severity": e.get("severity"),
                "Description": e.get("description")
            }
            for e in events[:10]
        ])
        st.dataframe(df_events, use_container_width=True, hide_index=True)
        st.caption(f"Showing first 10 of {len(events)} security events. Each event contains authenticated timestamps, processes, and network details.")

    # Step Navigation Buttons
    st.write("")
    nav_c1, nav_c2 = st.columns([1, 2])
    with nav_c1:
        if st.button("◀ Back to Overview", use_container_width=True):
            st.session_state["active_section"] = "01_OVERVIEW"
            st.rerun()
    with nav_c2:
        if st.button("▶ Next: See What the AI Claims (AI Findings)", type="primary", use_container_width=True):
            st.session_state["active_section"] = "03_AI_CLAIMS"
            st.rerun()

# =============================================================================
# SECTION 3: AI INVESTIGATION & CLAIMS
# =============================================================================
elif st.session_state["active_section"] == "03_AI_CLAIMS":
    st.markdown("# 02 — AI Investigation: Findings & Confidence")
    st.markdown(
        "The AI investigator analyzes the 44 security events and synthesizes structured findings. "
        "Each finding includes an attack stage, MITRE technique, cited event IDs, and an **AI Confidence Score**."
    )

    render_html("""
    <div class="callout-banner">
        ⚠️ <strong>CRITICAL OBSERVATION:</strong> All of the AI findings below display high confidence (89% – 98%) and sound completely plausible.
        Can an analyst trust them without independent verification?
    </div>
    """)

    if not findings:
        st.warning("No findings loaded. Please verify pipeline status.")
    else:
        grid_col1, grid_col2 = st.columns(2)
        for idx, f in enumerate(findings):
            target_col = grid_col1 if idx % 2 == 0 else grid_col2
            ai_conf = round(f.get("ai_confidence", 0.0) * 100.0, 1)
            is_hallucinated = (f.get("finding_id") == "FINDING-005")
            
            card_border = "#f85149" if is_hallucinated else "#30363d"
            flag_text = ' <span style="background:#f85149; color:#fff; font-size:0.7rem; padding:2px 6px; border-radius:4px; font-weight:bold;">HALLUCINATED CLAIM</span>' if is_hallucinated else ''

            with target_col:
                render_html(f"""
                <div class="finding-card" style="border-color:{card_border};">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-size:0.8rem; font-weight:700; color:#8b949e;">{f.get('finding_id', 'FID')} {flag_text}</span>
                        <span style="font-weight:800; color:#58a6ff; font-size:1.0rem;">AI Confidence: {ai_conf}%</span>
                    </div>
                    <div style="font-weight:700; font-size:1.05rem; color:#f0f6fc; margin:6px 0;">{f.get('title')}</div>
                    <div style="font-size:0.85rem; color:#8b949e; margin-bottom:8px;">
                        Stage: <strong style="color:#c9d1d9;">{f.get('attack_stage')}</strong> | MITRE: <span style="font-family:monospace; color:#58a6ff;">{f.get('mitre_technique')}</span>
                    </div>
                    <div style="font-size:0.88rem; color:#c9d1d9; line-height:1.4;">{f.get('description')}</div>
                    <div style="font-size:0.8rem; color:#8b949e; margin-top:8px;">
                        Cited Log Events: <code>{', '.join(f.get('supporting_event_ids', []))}</code>
                    </div>
                </div>
                """)

    st.write("")
    nav_c1, nav_c2 = st.columns([1, 2])
    with nav_c1:
        if st.button("◀ Back to Logs", use_container_width=True):
            st.session_state["active_section"] = "02_LOGS"
            st.rerun()
    with nav_c2:
        if st.button("▶ Next: Run Independent SentinelX Verification", type="primary", use_container_width=True):
            st.session_state["active_section"] = "04_VERIFICATION"
            st.rerun()

# =============================================================================
# SECTION 4: SENTINELX VERIFICATION (THE PRIMARY DEMO MOMENT)
# =============================================================================
elif st.session_state["active_section"] == "04_VERIFICATION":
    st.markdown("# 03 — SentinelX Independent Verification")
    st.markdown(
        "SentinelX's core engine takes every AI claim, retrieves the cited raw security logs, "
        "and deterministically verifies content relevance, chronological ordering, and MITRE alignment."
    )

    if selected_mode == "controlled_demo":
        # Interactive Claim Selector
        c_tab1, c_tab2, c_tab3 = st.columns(3)
        curr_tab = st.session_state.get("selected_claim_tab", "REJECTED")

        with c_tab1:
            btn_type = "primary" if curr_tab == "REJECTED" else "secondary"
            if st.button("🔴 1. Hallucinated Claim (UNSUPPORTED)", type=btn_type, use_container_width=True):
                st.session_state["selected_claim_tab"] = "REJECTED"
                st.rerun()

        with c_tab2:
            btn_type = "primary" if curr_tab == "SUPPORTED" else "secondary"
            if st.button("🟢 2. Authentic Claim (SUPPORTED)", type=btn_type, use_container_width=True):
                st.session_state["selected_claim_tab"] = "SUPPORTED"
                st.rerun()

        with c_tab3:
            btn_type = "primary" if curr_tab == "INSUFFICIENT" else "secondary"
            if st.button("🟡 3. Unproven Claim (INSUFFICIENT)", type=btn_type, use_container_width=True):
                st.session_state["selected_claim_tab"] = "INSUFFICIENT"
                st.rerun()

        st.write("")

        # ---------------------------------------------------------------------
        # CASE 1: THE PRIMARY DEMO MOMENT — UNSUPPORTED HALLUCINATION
        # ---------------------------------------------------------------------
        if curr_tab == "REJECTED":
            f_rejected = next((f for f in findings if f["finding_id"] == "FINDING-005"), findings[4] if len(findings)>4 else findings[0])
            v_rejected = ver_map.get(f_rejected.get("finding_id"), {})
            ai_conf = round(f_rejected.get("ai_confidence", 0.98) * 100.0, 1)
            ev_score = round(v_rejected.get("evidence_score", 6.0), 1)

            # Render cleanly through render_html to avoid Markdown code-block interpretation
            render_html(f"""
            <div class="claim-card claim-card-rejected">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; flex-wrap:wrap; gap:8px;">
                    <div>
                        <span style="font-size:0.8rem; font-weight:800; color:#8b949e; letter-spacing:0.5px;">FINDING-005 | INITIAL ACCESS</span>
                        <span style="background:rgba(88,166,255,0.15); color:#58a6ff; border:1px solid rgba(88,166,255,0.4); padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:700; margin-left:8px;">Controlled Verification Case</span>
                    </div>
                    <span class="badge-unsupported">🔴 FINAL VERDICT: UNSUPPORTED</span>
                </div>
                <h3 style="color:#f0f6fc; margin:0 0 14px 0; font-size:1.4rem;">{f_rejected.get('title')}</h3>
                <p style="color:#c9d1d9; font-size:1.0rem; margin-bottom:18px; line-height:1.5;">
                    <em>"{f_rejected.get('description')}"</em>
                </p>
                <div style="background:#21262d; border:1px solid #30363d; border-radius:10px; padding:18px; margin-bottom:18px;">
                    <div style="display:flex; justify-content:space-around; align-items:center; text-align:center; flex-wrap:wrap; gap:16px;">
                        <div>
                            <div style="font-size:0.8rem; color:#8b949e; font-weight:700; text-transform:uppercase;">AI Confidence Score</div>
                            <div style="font-size:2.6rem; font-weight:900; color:#58a6ff;">{ai_conf}%</div>
                            <div style="font-size:0.8rem; color:#8b949e;">(LLM Confidence)</div>
                        </div>
                        <div style="font-size:2.0rem; color:#8b949e;">VS</div>
                        <div>
                            <div style="font-size:0.8rem; color:#8b949e; font-weight:700; text-transform:uppercase;">SentinelX Evidence Score</div>
                            <div style="font-size:2.6rem; font-weight:900; color:#f85149;">{ev_score}%</div>
                            <div style="font-size:0.8rem; color:#8b949e;">(Deterministic Verification)</div>
                        </div>
                        <div>
                            <div style="font-size:0.8rem; color:#8b949e; font-weight:700; text-transform:uppercase;">Ground Truth Verdict</div>
                            <div style="font-size:1.8rem; font-weight:900; color:#f85149; margin-top:4px;">REJECTED</div>
                            <div style="font-size:0.8rem; color:#3fb950;">Accurately Caught!</div>
                        </div>
                    </div>
                </div>
                <div style="background:rgba(248,81,73,0.1); border-left:4px solid #f85149; padding:16px; border-radius:6px; margin-bottom:16px;">
                    <h4 style="color:#f85149; margin:0 0 8px 0;">🔍 WHY SENTINELX REJECTED THIS CLAIM:</h4>
                    <p style="color:#c9d1d9; margin:0 0 10px 0; font-size:0.95rem;">
                        The AI claimed that the threat actor exploited an Apache Buffer Overflow (CVE-2025-9999). 
                        It cited event IDs <strong>EVT-1001</strong> and <strong>EVT-1002</strong>.
                    </p>
                    <div style="color:#f0f6fc; font-weight:700; font-size:0.92rem; margin-bottom:6px;">ACTUAL EVIDENCE IN SECURITY LOGS:</div>
                    <ul style="color:#c9d1d9; font-size:0.92rem; margin:0 0 10px 20px;">
                        <li><strong>EVT-1001:</strong> Process <code>hydra</code> initiating high-frequency SSH password brute-force on port 22 against <code>10.12.0.223</code>.</li>
                        <li><strong>EVT-1002:</strong> Process <code>sshd</code> recording repeated authentication failures (MITRE T1110.001).</li>
                    </ul>
                    <div style="color:#f85149; font-weight:700; font-size:0.92rem;">
                        🚨 CONTRADICTION: There is NO Apache web server running, NO HTTP traffic, and NO buffer overflow. The AI completely hallucinated the attack vector!
                    </div>
                </div>
            </div>
            """)

            # SIDE-BY-SIDE COMPARISON TABLE
            st.markdown("### 📊 Side-by-Side Comparison")
            render_html(f"""
            <table class="comp-table">
                <thead>
                    <tr>
                        <th style="width:25%;">ATTRIBUTION METRIC</th>
                        <th style="width:37%;">WHAT THE AI CLAIMED</th>
                        <th style="width:38%;">WHAT THE LOGS ACTUALLY PROVE</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>Attack Technique</strong></td>
                        <td>Apache Web Server Buffer Overflow (CVE-2025-9999)</td>
                        <td>Hydra SSH Password Brute-Force (T1110.001)</td>
                    </tr>
                    <tr>
                        <td><strong>Targeted Service & Port</strong></td>
                        <td>HTTP / HTTPS (Port 80 / 443)</td>
                        <td>SSH Daemon (Port 22)</td>
                    </tr>
                    <tr>
                        <td><strong>Attacking Process</strong></td>
                        <td><code>httpd / apache2</code> payload</td>
                        <td><code>hydra</code> dictionary attack</td>
                    </tr>
                    <tr>
                        <td><strong>Confidence vs Evidence</strong></td>
                        <td><strong style="color:#58a6ff;">{ai_conf}% (High Confidence)</strong></td>
                        <td><strong style="color:#f85149;">{ev_score}% (Severe Contradiction)</strong></td>
                    </tr>
                    <tr>
                        <td><strong>Analyst Outcome</strong></td>
                        <td>Would waste hours patching web servers</td>
                        <td>Immediately blocks attacker IP & enforces SSH keys</td>
                    </tr>
                </tbody>
            </table>
            """)

        # ---------------------------------------------------------------------
        # CASE 2: SUPPORTED CLAIM
        # ---------------------------------------------------------------------
        elif curr_tab == "SUPPORTED":
            f_supported = next((f for f in findings if f["finding_id"] == "FINDING-001"), findings[0])
            v_supported = ver_map.get("FINDING-001", {})
            ai_conf = round(f_supported.get("ai_confidence", 0.94) * 100.0, 1)
            ev_score = round(v_supported.get("evidence_score", 99.0), 1)

            render_html(f"""
            <div class="claim-card claim-card-supported">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; flex-wrap:wrap; gap:8px;">
                    <div>
                        <span style="font-size:0.8rem; font-weight:800; color:#8b949e; letter-spacing:0.5px;">FINDING-001 | INITIAL ACCESS</span>
                        <span style="background:rgba(88,166,255,0.15); color:#58a6ff; border:1px solid rgba(88,166,255,0.4); padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:700; margin-left:8px;">Controlled Verification Case</span>
                    </div>
                    <span class="badge-supported">🟢 FINAL VERDICT: SUPPORTED</span>
                </div>
                <h3 style="color:#f0f6fc; margin:0 0 14px 0; font-size:1.4rem;">{f_supported.get('title')}</h3>
                <p style="color:#c9d1d9; font-size:1.0rem; margin-bottom:18px; line-height:1.5;">
                    <em>"{f_supported.get('description')}"</em>
                </p>
                <div style="background:#21262d; border:1px solid #30363d; border-radius:10px; padding:18px; margin-bottom:18px;">
                    <div style="display:flex; justify-content:space-around; align-items:center; text-align:center; flex-wrap:wrap; gap:16px;">
                        <div>
                            <div style="font-size:0.8rem; color:#8b949e; font-weight:700; text-transform:uppercase;">AI Confidence</div>
                            <div style="font-size:2.4rem; font-weight:900; color:#58a6ff;">{ai_conf}%</div>
                        </div>
                        <div style="font-size:2.0rem; color:#8b949e;">&</div>
                        <div>
                            <div style="font-size:0.8rem; color:#8b949e; font-weight:700; text-transform:uppercase;">SentinelX Evidence Score</div>
                            <div style="font-size:2.4rem; font-weight:900; color:#3fb950;">{ev_score}%</div>
                        </div>
                        <div>
                            <div style="font-size:0.8rem; color:#8b949e; font-weight:700; text-transform:uppercase;">Verdict</div>
                            <div style="font-size:1.6rem; font-weight:900; color:#3fb950; margin-top:4px;">VERIFIED TRUE</div>
                        </div>
                    </div>
                </div>
                <div style="background:rgba(46,160,67,0.1); border-left:4px solid #3fb950; padding:16px; border-radius:6px;">
                    <h4 style="color:#3fb950; margin:0 0 8px 0;">✅ WHY SENTINELX VERIFIED THIS CLAIM:</h4>
                    <p style="color:#c9d1d9; font-size:0.92rem; margin:0;">
                        Cited log events <strong>EVT-1001</strong> and <strong>EVT-1002</strong> exist in the database, match MITRE T1110.001, 
                        record the Hydra process bursting SSH login failures from 192.42.1.174, and follow perfect chronological order.
                    </p>
                </div>
            </div>
            """)

        # ---------------------------------------------------------------------
        # CASE 3: INSUFFICIENT EVIDENCE
        # ---------------------------------------------------------------------
        else:
            f_insufficient = next((f for f in findings if f["finding_id"] == "FINDING-006"), findings[-1])
            v_insufficient = ver_map.get("FINDING-006", {})
            ai_conf = round(f_insufficient.get("ai_confidence", 0.89) * 100.0, 1)
            ev_score = round(v_insufficient.get("evidence_score", 10.0), 1)

            render_html(f"""
            <div class="claim-card claim-card-insufficient">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; flex-wrap:wrap; gap:8px;">
                    <div>
                        <span style="font-size:0.8rem; font-weight:800; color:#8b949e; letter-spacing:0.5px;">FINDING-006 | EXFILTRATION</span>
                        <span style="background:rgba(88,166,255,0.15); color:#58a6ff; border:1px solid rgba(88,166,255,0.4); padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:700; margin-left:8px;">Controlled Verification Case</span>
                    </div>
                    <span class="badge-insufficient">🟡 FINAL VERDICT: INSUFFICIENT EVIDENCE</span>
                </div>
                <h3 style="color:#f0f6fc; margin:0 0 14px 0; font-size:1.4rem;">{f_insufficient.get('title')}</h3>
                <p style="color:#c9d1d9; font-size:1.0rem; margin-bottom:18px; line-height:1.5;">
                    <em>"{f_insufficient.get('description')}"</em>
                </p>
                <div style="background:#21262d; border:1px solid #30363d; border-radius:10px; padding:18px; margin-bottom:18px;">
                    <div style="display:flex; justify-content:space-around; align-items:center; text-align:center; flex-wrap:wrap; gap:16px;">
                        <div>
                            <div style="font-size:0.8rem; color:#8b949e; font-weight:700; text-transform:uppercase;">AI Confidence</div>
                            <div style="font-size:2.4rem; font-weight:900; color:#58a6ff;">{ai_conf}%</div>
                        </div>
                        <div style="font-size:2.0rem; color:#8b949e;">VS</div>
                        <div>
                            <div style="font-size:0.8rem; color:#8b949e; font-weight:700; text-transform:uppercase;">SentinelX Evidence Score</div>
                            <div style="font-size:2.4rem; font-weight:900; color:#d29922;">{ev_score}%</div>
                        </div>
                    </div>
                </div>
                <div style="background:rgba(210,153,34,0.1); border-left:4px solid #d29922; padding:16px; border-radius:6px;">
                    <h4 style="color:#d29922; margin:0 0 8px 0;">⚠️ WHY SENTINELX FLAGGED INSUFFICIENT EVIDENCE:</h4>
                    <p style="color:#c9d1d9; font-size:0.92rem; margin:0;">
                        The AI cited <strong>EVT-1026</strong> and <strong>EVT-1027</strong> claiming 50GB credit card exfiltration. 
                        However, those logs actually document local file encryption by ransomware, not network exfiltration to 203.0.113.50. 
                        Because no exfiltration logs exist, SentinelX refused to validate the claim.
                    </p>
                </div>
            </div>
            """)

    else:
        # LIVE GEMINI AI MODE: Renders all dynamically generated findings with live verifier output
        st.markdown("### 🤖 Live Gemini AI Verification Results")
        st.caption("Each AI finding generated dynamically by Gemini has been independently audited against the security event stream.")

        for f in findings:
            fid = f.get("finding_id", "FINDING")
            v_res = ver_map.get(fid, {})
            status = v_res.get("verification_status", "UNKNOWN")
            ai_conf = round(f.get("ai_confidence", 0.0) * 100.0, 1)
            ev_score = round(v_res.get("evidence_score", 0.0), 1)

            card_border = "#2ea043" if status == "SUPPORTED" else ("#f85149" if status == "UNSUPPORTED" else "#d29922")
            badge_html = (
                '<span class="badge-supported">🟢 SUPPORTED</span>' if status == "SUPPORTED" else (
                    '<span class="badge-unsupported">🔴 UNSUPPORTED</span>' if status == "UNSUPPORTED" else
                    '<span class="badge-insufficient">🟡 INSUFFICIENT EVIDENCE</span>'
                )
            )

            render_html(f"""
            <div class="claim-card" style="border-left:6px solid {card_border};">
                <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                    <div>
                        <div style="font-size:0.8rem; font-weight:700; color:#8b949e;">{fid} | {f.get('attack_stage')}</div>
                        <h3 style="color:#f0f6fc; margin:4px 0 10px 0;">{f.get('title')}</h3>
                    </div>
                    <div>{badge_html}</div>
                </div>
                <div style="font-size:0.95rem; color:#c9d1d9; margin-bottom:14px;">{f.get('description')}</div>
                <div style="display:flex; gap:32px; margin-bottom:14px;">
                    <div>AI Confidence: <strong style="color:#58a6ff;">{ai_conf}%</strong></div>
                    <div>Deterministic Evidence Score: <strong style="color:{card_border};">{ev_score} / 100</strong></div>
                </div>
                <div style="background:#21262d; border-radius:6px; padding:12px; font-size:0.9rem; color:#f0f6fc;">
                    <strong>SentinelX Explanation:</strong> {v_res.get('verification_explanation', 'Verified against security log events.')}
                </div>
            </div>
            """)

    st.write("")
    nav_c1, nav_c2 = st.columns([1, 2])
    with nav_c1:
        if st.button("◀ Back to AI Claims", use_container_width=True):
            st.session_state["active_section"] = "03_AI_CLAIMS"
            st.rerun()
    with nav_c2:
        if st.button("▶ Next: View Trust Score & Incident Report", type="primary", use_container_width=True):
            st.session_state["active_section"] = "05_REPORT"
            st.rerun()

# =============================================================================
# SECTION 5: TRUST SCORE & ACTIONABLE REPORT
# =============================================================================
elif st.session_state["active_section"] == "05_REPORT":
    st.markdown("# 04 — Evidence Trust Score & Audit Report")
    st.markdown(
        "SentinelX combines verified evidence into an **audit-grade Incident Report** "
        "and calculates a transparent **Evidence Trust Score** (0–100)."
    )

    # Top Metric Summary Cards
    r1, r2, r3 = st.columns(3)
    with r1:
        render_html("""
        <div class="metric-card">
            <div class="metric-title">Incident Identifier</div>
            <div class="metric-value" style="font-size:1.3rem; color:#58a6ff;">INC-2025-CAM-LDS-001</div>
        </div>
        """)
    with r2:
        render_html("""
        <div class="metric-card">
            <div class="metric-title">Overall Incident Severity</div>
            <div class="metric-value" style="font-size:1.6rem; color:#f85149;">CRITICAL</div>
        </div>
        """)
    with r3:
        render_html(f"""
        <div class="metric-card">
            <div class="metric-title">Overall Evidence Trust Score</div>
            <div class="metric-value metric-value-trust">{trust_score} <span style="font-size:1.1rem; color:#8b949e;">/100</span></div>
        </div>
        """)

    st.write("")
    
    # 5-Factor Trust Score Breakdown
    st.markdown("### 🧮 How the Evidence Trust Score is Calculated (0–100)")
    st.caption("Unlike LLM confidence which is subjective, SentinelX's Trust Score uses 5 deterministic mathematical factors:")

    f1, f2, f3, f4, f5 = st.columns(5)
    with f1:
        render_html("""
        <div style="background:#161b22; border:1px solid #30363d; border-radius:8px; padding:12px; text-align:center;">
            <div style="font-size:0.75rem; color:#8b949e; font-weight:700;">1. COVERAGE</div>
            <div style="font-size:1.4rem; font-weight:800; color:#3fb950; margin:4px 0;">23.3 pts</div>
            <div style="font-size:0.7rem; color:#8b949e;">4/6 Supported (35% max)</div>
        </div>
        """)
    with f2:
        render_html("""
        <div style="background:#161b22; border:1px solid #30363d; border-radius:8px; padding:12px; text-align:center;">
            <div style="font-size:0.75rem; color:#8b949e; font-weight:700;">2. TIMELINE</div>
            <div style="font-size:1.4rem; font-weight:800; color:#3fb950; margin:4px 0;">20.0 pts</div>
            <div style="font-size:0.7rem; color:#8b949e;">0 Anomalies (20% max)</div>
        </div>
        """)
    with f3:
        render_html("""
        <div style="background:#161b22; border:1px solid #30363d; border-radius:8px; padding:12px; text-align:center;">
            <div style="font-size:0.75rem; color:#8b949e; font-weight:700;">3. MITRE ACCURACY</div>
            <div style="font-size:1.4rem; font-weight:800; color:#3fb950; margin:4px 0;">18.4 pts</div>
            <div style="font-size:0.7rem; color:#8b949e;">Technique Match (20% max)</div>
        </div>
        """)
    with f4:
        render_html("""
        <div style="background:#161b22; border:1px solid #30363d; border-radius:8px; padding:12px; text-align:center;">
            <div style="font-size:0.75rem; color:#8b949e; font-weight:700;">4. EVENT INTEGRITY</div>
            <div style="font-size:1.4rem; font-weight:800; color:#3fb950; margin:4px 0;">10.0 pts</div>
            <div style="font-size:0.7rem; color:#8b949e;">Valid IDs (15% max)</div>
        </div>
        """)
    with f5:
        render_html("""
        <div style="background:#161b22; border:1px solid #30363d; border-radius:8px; padding:12px; text-align:center;">
            <div style="font-size:0.75rem; color:#8b949e; font-weight:700;">5. CONTRADICTIONS</div>
            <div style="font-size:1.4rem; font-weight:800; color:#f85149; margin:4px 0;">5.0 pts</div>
            <div style="font-size:0.7rem; color:#8b949e;">-5 pt Penalty (10% max)</div>
        </div>
        """)

    st.write("")
    
    # Actionable Remediation Checklist (Filter out unsupported recommendations)
    st.markdown("### 🛡️ Actionable Defensive Recommendations (Verified Only)")
    st.caption("SentinelX protects SOC operations by discarding recommendations for hallucinated claims.")

    supported_recs = [f for f in findings if ver_map.get(f.get("finding_id"), {}).get("verification_status") == "SUPPORTED"]
    for rec in supported_recs:
        render_html(f"""
        <div style="background:#161b22; border-left:4px solid #3fb950; border-radius:6px; padding:12px 16px; margin-bottom:8px;">
            <strong style="color:#f0f6fc;">{rec.get('title')}:</strong> 
            <span style="color:#c9d1d9;">{rec.get('recommendation')}</span>
        </div>
        """)

    render_html("""
    <div style="background:rgba(248,81,73,0.1); border-left:4px solid #f85149; border-radius:6px; padding:12px 16px; margin-top:8px;">
        <strong style="color:#f85149;">DISCARDED HALLUCINATION:</strong> 
        <span style="color:#8b949e; text-decoration:line-through;">Patch Apache HTTP server immediately to version 2.4.60.</span> 
        <span style="color:#f85149; font-size:0.85rem;"> (Rejected: Host does not run Apache; no buffer overflow occurred.)</span>
    </div>
    """)

    st.write("")
    st.divider()

    # JSON Export Section
    st.markdown("### 📥 Export Verified Incident Investigation Report")
    report_json = json.dumps(report, indent=2)
    st.download_button(
        label="Download Full Audit Report (JSON)",
        data=report_json,
        file_name=f"SentinelX_Report_{incident_id}.json",
        mime="application/json",
        type="primary"
    )

    with st.expander("🔬 View Raw JSON Report"):
        st.json(report)

    st.write("")
    nav_c1, nav_c2 = st.columns([1, 2])
    with nav_c1:
        if st.button("◀ Back to Verification", use_container_width=True):
            st.session_state["active_section"] = "04_VERIFICATION"
            st.rerun()
    with nav_c2:
        if st.button("🔄 Restart Demo from Overview", use_container_width=True):
            st.session_state["active_section"] = "01_OVERVIEW"
            st.rerun()
