import streamlit as st
import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))

from rag.pipeline import query, get_collection_stats

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Threat Intel Copilot",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600&display=swap');

/* Base */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* Background */
.stApp {
    background-color: #0a0e1a;
    color: #e2e8f0;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background-color: #0d1117;
    border-right: 1px solid #1e2d3d;
}

/* Header */
.hero-header {
    padding: 1.5rem 0 1rem 0;
    border-bottom: 1px solid #1e2d3d;
    margin-bottom: 1.5rem;
}

.hero-title {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.6rem;
    font-weight: 600;
    color: #38bdf8;
    letter-spacing: -0.02em;
    margin: 0;
}

.hero-subtitle {
    font-size: 0.85rem;
    color: #64748b;
    margin-top: 0.25rem;
    font-family: 'JetBrains Mono', monospace;
}

/* Answer box */
.answer-box {
    background: #0d1117;
    border: 1px solid #1e2d3d;
    border-left: 3px solid #38bdf8;
    border-radius: 6px;
    padding: 1.25rem 1.5rem;
    font-size: 0.93rem;
    line-height: 1.7;
    color: #cbd5e1;
    margin: 1rem 0;
}

/* Source cards */
.source-card {
    background: #0d1117;
    border: 1px solid #1e2d3d;
    border-radius: 6px;
    padding: 0.85rem 1rem;
    margin-bottom: 0.6rem;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    color: #94a3b8;
}

.source-id {
    color: #38bdf8;
    font-weight: 600;
    font-size: 0.82rem;
}

.badge {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
    margin-left: 0.4rem;
    font-family: 'JetBrains Mono', monospace;
}

.badge-critical { background: #7f1d1d; color: #fca5a5; }
.badge-high     { background: #78350f; color: #fcd34d; }
.badge-medium   { background: #1e3a5f; color: #93c5fd; }
.badge-low      { background: #14532d; color: #86efac; }
.badge-mitre    { background: #1e1b4b; color: #a5b4fc; }
.badge-nvd      { background: #0f2942; color: #7dd3fc; }

.score-text {
    color: #f59e0b;
    font-size: 0.72rem;
}

/* Stat cards */
.stat-card {
    background: #0d1117;
    border: 1px solid #1e2d3d;
    border-radius: 6px;
    padding: 1rem;
    text-align: center;
}

.stat-number {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.8rem;
    font-weight: 600;
    color: #38bdf8;
}

.stat-label {
    font-size: 0.75rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-top: 0.2rem;
}

/* Query input */
.stTextArea textarea {
    background-color: #0d1117 !important;
    border: 1px solid #1e2d3d !important;
    border-radius: 6px !important;
    color: #e2e8f0 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.88rem !important;
}

.stTextArea textarea:focus {
    border-color: #38bdf8 !important;
    box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.15) !important;
}

/* Buttons */
.stButton > button {
    background: #0284c7;
    color: white;
    border: none;
    border-radius: 6px;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 600;
    font-size: 0.85rem;
    padding: 0.5rem 1.5rem;
    transition: background 0.2s;
    width: 100%;
}

.stButton > button:hover {
    background: #0369a1;
}

/* Divider */
hr {
    border-color: #1e2d3d;
    margin: 1rem 0;
}

/* Spinner */
.stSpinner > div {
    border-top-color: #38bdf8 !important;
}

/* History item */
.history-item {
    background: #0d1117;
    border: 1px solid #1e2d3d;
    border-radius: 6px;
    padding: 0.75rem 1rem;
    margin-bottom: 0.5rem;
    cursor: pointer;
    font-size: 0.82rem;
    color: #94a3b8;
    font-family: 'JetBrains Mono', monospace;
}

.history-item:hover {
    border-color: #38bdf8;
    color: #e2e8f0;
}

/* Section headers */
.section-header {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #475569;
    margin: 1rem 0 0.5rem 0;
}

/* Expander */
[data-testid="stExpander"] {
    background: #0d1117;
    border: 1px solid #1e2d3d;
    border-radius: 6px;
}

/* Scrollbar */
::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-track { background: #0a0e1a; }
::-webkit-scrollbar-thumb { background: #1e2d3d; border-radius: 4px; }
</style>
""", unsafe_allow_html=True)


# ── Session state ──────────────────────────────────────────────────────────────
if "history" not in st.session_state:
    st.session_state.history = []
if "current_result" not in st.session_state:
    st.session_state.current_result = None
if "current_question" not in st.session_state:
    st.session_state.current_question = ""


# ── Helpers ────────────────────────────────────────────────────────────────────
def severity_badge(severity: str) -> str:
    s = (severity or "").upper()
    cls = {
        "CRITICAL": "badge-critical",
        "HIGH": "badge-high",
        "MEDIUM": "badge-medium",
        "LOW": "badge-low",
    }.get(s, "badge-medium")
    return f'<span class="badge {cls}">{s}</span>' if s else ""


def render_cve_source(r: dict):
    meta = r.get("metadata", {})
    cve_id = meta.get("id", "CVE-???")
    severity = meta.get("cvss_severity", "")
    score = meta.get("cvss_score", "")
    published = meta.get("published", "")
    sim = r.get("score", 0)

    badge = severity_badge(severity)
    score_str = f"CVSS {score}" if score else ""

    st.markdown(f"""
    <div class="source-card">
        <span class="source-id">{cve_id}</span>
        <span class="badge badge-nvd">NVD</span>
        {badge}
        <br>
        <span class="score-text">{score_str}</span>
        {"&nbsp;·&nbsp;" if score_str and published else ""}
        <span style="color:#475569">{published}</span>
        <span style="float:right; color:#334155">relevance {sim}</span>
    </div>
    """, unsafe_allow_html=True)


def render_mitre_source(r: dict):
    meta = r.get("metadata", {})
    tech_id = meta.get("id", "T????")
    name = meta.get("name", "")
    tactics = meta.get("tactics", "")
    sim = r.get("score", 0)

    st.markdown(f"""
    <div class="source-card">
        <span class="source-id">{tech_id}</span>
        <span class="badge badge-mitre">ATT&CK</span>
        <br>
        <span style="color:#cbd5e1">{name}</span><br>
        <span style="color:#475569; font-size:0.72rem">{tactics}</span>
        <span style="float:right; color:#334155">relevance {sim}</span>
    </div>
    """, unsafe_allow_html=True)


EXAMPLE_QUERIES = [
    "What critical CVEs were published in the last 30 days?",
    "What ATT&CK techniques are used for credential dumping?",
    "Show me high severity vulnerabilities affecting Apache",
    "What are common techniques for lateral movement?",
    "Are there any CVEs related to remote code execution this month?",
    "How do attackers establish persistence on Windows systems?",
]


# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="padding: 0.5rem 0 1rem 0;">
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; 
                    text-transform: uppercase; letter-spacing: 0.1em; color: #475569;">
            ThreatScope
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Stats
    stats = get_collection_stats()
    c1, c2 = st.columns(2)
    with c1:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-number">{stats.get('cve_intel', 0)}</div>
            <div class="stat-label">CVEs</div>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-number">{stats.get('mitre_attack', 0)}</div>
            <div class="stat-label">ATT&CK</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<hr>", unsafe_allow_html=True)

    # Example queries
    st.markdown('<div class="section-header">Example Queries</div>', unsafe_allow_html=True)
    for eq in EXAMPLE_QUERIES:
        if st.button(eq, key=f"ex_{eq[:20]}", use_container_width=True):
            st.session_state.prefill_query = eq
            st.rerun()

    st.markdown("<hr>", unsafe_allow_html=True)

    # Query history
    if st.session_state.history:
        st.markdown('<div class="section-header">Recent Queries</div>', unsafe_allow_html=True)
        for i, item in enumerate(reversed(st.session_state.history[-8:])):
            q_short = item["question"][:45] + "..." if len(item["question"]) > 45 else item["question"]
            st.markdown(f'<div class="history-item">↩ {q_short}</div>', unsafe_allow_html=True)

    # Ingest button
    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown('<div class="section-header">Data</div>', unsafe_allow_html=True)
    if st.button("🔄 Re-run Ingestion", use_container_width=True):
        st.info("Run `python ingest_runner.py` in your terminal to refresh data.")


# ── Main ────────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="hero-header">
    <div class="hero-title">ThreatScope- A threat intel copilot</div>
    <div class="hero-subtitle">NVD CVEs + MITRE ATT&CK · Powered by Llama 3.3 70B</div>
</div>
""", unsafe_allow_html=True)

# Check if a KB is empty
total_docs = sum(stats.values())
if total_docs == 0:
    st.warning("""
**Knowledge base is empty.** Run ingestion first:
```bash
python ingest_runner.py
```
This will fetch recent CVEs from NVD and all MITRE ATT&CK techniques (~10 min first run).
    """)

# Query input
prefill = st.session_state.pop("prefill_query", "")
query_input = st.text_area(
    "Ask a question about threats, CVEs, or ATT&CK techniques",
    value=prefill,
    height=90,
    placeholder="e.g. What high-severity CVEs affect Linux systems this month?",
    label_visibility="collapsed",
)

col1, col2, col3 = st.columns([3, 1, 1])
with col1:
    n_sources = st.slider("Sources per collection", min_value=2, max_value=8, value=4, label_visibility="collapsed")
with col3:
    search_btn = st.button("Search →", use_container_width=True)

# Run query
if search_btn and query_input.strip():
    with st.spinner("Searching knowledge base..."):
        start = time.time()
        result = query(query_input.strip(), n_results=n_sources)
        elapsed = time.time() - start

    st.session_state.current_result = result
    st.session_state.current_question = query_input.strip()
    st.session_state.history.append({
        "question": query_input.strip(),
        "result": result,
    })

elif search_btn:
    st.warning("Please enter a question.")

# Display result
if st.session_state.current_result:
    result = st.session_state.current_result
    question = st.session_state.current_question

    st.markdown(f"""
    <div class="section-header">Query</div>
    <div style="font-family: 'JetBrains Mono', monospace; color: #38bdf8; 
                font-size: 0.9rem; margin-bottom: 0.75rem;">
        > {question}
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="section-header">Answer</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="answer-box">{result["answer"]}</div>', unsafe_allow_html=True)

    # Sources
    cve_sources = result.get("cve_sources", [])
    mitre_sources = result.get("mitre_sources", [])

    if cve_sources or mitre_sources:
        st.markdown("<hr>", unsafe_allow_html=True)
        col_cve, col_mitre = st.columns(2)

        with col_cve:
            st.markdown('<div class="section-header">CVE Sources</div>', unsafe_allow_html=True)
            if cve_sources:
                for r in cve_sources:
                    render_cve_source(r)
            else:
                st.markdown('<span style="color:#475569; font-size:0.8rem">No CVE sources retrieved</span>', unsafe_allow_html=True)

        with col_mitre:
            st.markdown('<div class="section-header">ATT&CK Sources</div>', unsafe_allow_html=True)
            if mitre_sources:
                for r in mitre_sources:
                    render_mitre_source(r)
            else:
                st.markdown('<span style="color:#475569; font-size:0.8rem">No ATT&CK sources retrieved</span>', unsafe_allow_html=True)

        # Full source text (collapsible)
        with st.expander("View raw source chunks"):
            all_sources = [("CVE", r) for r in cve_sources] + [("ATT&CK", r) for r in mitre_sources]
            for source_type, r in all_sources:
                st.markdown(f"**[{source_type}] Relevance: {r['score']}**")
                st.code(r["text"], language=None)
                st.markdown("---")
