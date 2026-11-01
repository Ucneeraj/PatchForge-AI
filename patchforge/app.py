import streamlit as st
import time
from patchforge.orchestrator import Orchestrator

# -----------------------------------------------------------------------------
# Page Configuration
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="PatchForge-AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------------------------------------------------------
# Custom CSS for Dark Modern Dashboard Theme
# -----------------------------------------------------------------------------
st.markdown("""
<style>
    .stApp {
        background-color: #080e18;
        color: #e2e8f0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    [data-testid="stSidebar"] {
        background-color: #060a12;
        border-right: 1px solid #142033;
    }
    .stat-card {
        background: #0d1726;
        border: 1px solid #16243b;
        border-radius: 12px;
        padding: 20px;
        position: relative;
    }
    .stat-title { color: #94a3b8; font-size: 0.85rem; margin-bottom: 6px; }
    .stat-value { font-size: 2.1rem; font-weight: 700; color: #f8fafc; margin: 4px 0; }
    .stat-sub { font-size: 0.78rem; color: #10b981; }
    .banner-card {
        background: radial-gradient(circle at top right, rgba(0, 229, 255, 0.12), transparent 70%), #0d1726;
        border: 1px solid #16243b;
        border-radius: 14px;
        padding: 18px 24px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .audit-row {
        background-color: #0b1422;
        border: 1px solid #14233a;
        border-radius: 10px;
        padding: 14px 18px;
        margin-bottom: 10px;
    }
    .badge-repaired {
        background-color: rgba(16, 185, 129, 0.15); color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 9999px;
        padding: 3px 10px; font-size: 0.75rem; font-weight: 600;
    }
    .badge-escalated {
        background-color: rgba(239, 68, 68, 0.15); color: #ef4444;
        border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 9999px;
        padding: 3px 10px; font-size: 0.75rem; font-weight: 600;
    }
    .file-tag {
        background-color: #1a2a44; color: #38bdf8; font-size: 0.72rem;
        font-weight: 700; padding: 3px 6px; border-radius: 4px; margin-right: 8px;
    }
    .note-box {
        background-color: #1a1a0d; border: 1px solid #3b3616; color: #fbbf24;
        border-radius: 8px; padding: 10px 14px; font-size: 0.8rem; margin-bottom: 10px;
    }
</style>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# State
# -----------------------------------------------------------------------------
if "scan_report" not in st.session_state:
    st.session_state.scan_report = None
if "selected_diff" not in st.session_state:
    st.session_state.selected_diff = None
if "scan_error" not in st.session_state:
    st.session_state.scan_error = None

# -----------------------------------------------------------------------------
# Sidebar
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("""
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 25px;">
            <div style="background: #0284c7; border-radius: 8px; padding: 6px 10px; font-weight: 800; font-size: 1.1rem; color: #fff;">P</div>
            <div>
                <h3 style="margin: 0; font-size: 1.1rem; font-weight: 700; color: #fff;">PatchForge<span style="color:#00e5ff">-AI</span></h3>
                <p style="margin: 0; font-size: 0.68rem; color: #64748b;">Auto-detect · Auto-repair · Safer code</p>
            </div>
        </div>
    """, unsafe_allow_html=True)
    st.markdown("""
        <div class="stat-card" style="padding: 14px;">
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
                <span style="font-size: 1.2rem;">🧠</span>
                <span style="font-size: 0.8rem; font-weight: 600; color: #f8fafc;">Powered by Multi-Agent AI</span>
            </div>
            <p style="font-size: 0.72rem; color: #64748b; margin: 0 0 10px 0;">AST Analysis · Self-Healing Loop · Local Sandboxed Patches</p>
            <div style="display: flex; align-items: center; gap: 6px; font-size: 0.75rem; color: #10b981;">
                <span style="height: 7px; width: 7px; background: #10b981; border-radius: 50%;"></span>
                System Online — Python (CWE-89, CWE-798) supported
            </div>
        </div>
    """, unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# Header
# -----------------------------------------------------------------------------
st.markdown("""
    <h1 style="margin: 0 0 4px 0; font-size: 1.8rem; font-weight: 700; color: #fff;">PatchForge-AI Dashboard</h1>
    <p style="color: #64748b; font-size: 0.9rem; margin-bottom: 20px;">Scan a GitHub repository (or local path) for vulnerabilities and let the agents fix them.</p>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# Input
# -----------------------------------------------------------------------------
col_input, col_btn = st.columns([4.2, 1])
with col_input:
    repo_url = st.text_input(
        "Repository Input",
        placeholder="https://github.com/username/repository or a local folder path",
        label_visibility="collapsed",
    )
with col_btn:
    run_scan = st.button("▶ Run Scan", type="primary", use_container_width=True)

st.caption(
    "Only Python files are scanned right now (CWE-89 SQL injection and "
    "CWE-798 hardcoded secrets). Other file types (.js, .java, etc.) are "
    "correctly reported as not-yet-supported, not silently ignored."
)

# -----------------------------------------------------------------------------
# Run pipeline
# -----------------------------------------------------------------------------
if run_scan:
    if not repo_url.strip():
        st.warning("Please provide a repository URL or local folder path.")
    else:
        with st.status("🔍 Ingesting repository & running agents...", expanded=True) as status:
            try:
                st.write("Cloning / opening repository...")
                orchestrator = Orchestrator()
                st.write("Scanning, patching, and validating against a corrected copy "
                         "(your original repo/folder is never modified)...")
                report = orchestrator.run_repo(repo_url.strip())
                st.session_state.scan_report = report
                st.session_state.scan_error = None
                status.update(label="✅ Scan & auto-repair complete!", state="complete", expanded=False)
            except Exception as e:
                st.session_state.scan_error = str(e)
                status.update(label="❌ Pipeline execution failed", state="error")
                st.error(f"Error during scan: {e}")

# -----------------------------------------------------------------------------
# Metrics  (using the REAL RepoScanReport fields: files_scanned, total_findings,
# total_repaired, total_escalated -- not the guessed names from an earlier version)
# -----------------------------------------------------------------------------
report = st.session_state.scan_report

files_count = report.files_scanned if report else 0
findings_count = report.total_findings if report else 0
repaired_count = report.total_repaired if report else 0
escalated_count = report.total_escalated if report else 0

m1, m2, m3, m4 = st.columns(4)
with m1:
    st.markdown(f"""<div class="stat-card"><div class="stat-title">Files Scanned</div>
        <div class="stat-value">{files_count}</div></div>""", unsafe_allow_html=True)
with m2:
    st.markdown(f"""<div class="stat-card"><div class="stat-title">Findings</div>
        <div class="stat-value" style="color:#fbbf24;">{findings_count}</div></div>""", unsafe_allow_html=True)
with m3:
    st.markdown(f"""<div class="stat-card"><div class="stat-title">Repaired</div>
        <div class="stat-value" style="color:#10b981;">{repaired_count}</div></div>""", unsafe_allow_html=True)
with m4:
    st.markdown(f"""<div class="stat-card"><div class="stat-title">Escalated</div>
        <div class="stat-value" style="color:#ef4444;">{escalated_count}</div></div>""", unsafe_allow_html=True)

st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

# Honest notes: skipped languages / files that couldn't be parsed
if report and report.skipped_languages:
    skipped = ", ".join(f"{ext} ({n})" for ext, n in report.skipped_languages.items())
    st.markdown(f'<div class="note-box">⚠ Found but not scanned (language not yet supported): {skipped}</div>',
                unsafe_allow_html=True)
if report and report.scan_errors:
    for path, err in report.scan_errors.items():
        st.markdown(f'<div class="note-box">⚠ Could not parse <code>{path}</code>: {err}</div>',
                    unsafe_allow_html=True)
if report and report.corrected_clone_path:
    st.caption(f"Corrected copy written to: {report.corrected_clone_path}")

# -----------------------------------------------------------------------------
# Audit Trail  (using outcome.finding.*, outcome.success -- the REAL fields)
# -----------------------------------------------------------------------------
st.markdown("""
    <h3 style="margin: 0 0 4px 0; font-size: 1.15rem; font-weight: 700; color: #fff;">Code Audit Trail</h3>
    <p style="margin: 0 0 12px 0; font-size: 0.78rem; color: #64748b;">Detailed scan results and fixes</p>
""", unsafe_allow_html=True)

if not report or not report.outcomes:
    st.info("No scan outcomes yet. Enter a repository link or path above and click "
            "'▶ Run Scan'. Note: a clean file with no vulnerabilities correctly "
            "shows zero findings -- that's not a bug.")
else:
    for idx, outcome in enumerate(report.outcomes):
        badge_class = "badge-repaired" if outcome.success else "badge-escalated"
        badge_text = "✔ Repaired" if outcome.success else "⚠ Escalated"
        finding = outcome.finding

        col_details, col_action = st.columns([5, 1])
        with col_details:
            st.markdown(f"""
                <div class="audit-row">
                    <span class="file-tag">{finding.cwe_id}</span>
                    <strong style="color: #f8fafc; font-size: 0.9rem;">{finding.file_path}:{finding.line_start}</strong>
                    <div style="font-size: 0.75rem; color: #94a3b8; margin-top: 4px;">
                        {finding.rule_id} — severity: {finding.severity} — {outcome.iterations_used} iteration(s)
                    </div>
                </div>
            """, unsafe_allow_html=True)
        with col_action:
            st.markdown(f"<div style='margin-top: 14px;'><span class='{badge_class}'>{badge_text}</span></div>",
                        unsafe_allow_html=True)
            if outcome.final_diff and st.button("View Diff ➜", key=f"diff_{idx}"):
                st.session_state.selected_diff = (outcome.final_diff, finding.file_path)

if st.session_state.selected_diff:
    diff_text, path = st.session_state.selected_diff
    st.markdown("<hr style='border-color: #16243b; margin: 30px 0;'>", unsafe_allow_html=True)
    st.subheader(f"Diff: {path}")
    st.code(diff_text, language="diff")
    if st.button("Close Diff Viewer"):
        st.session_state.selected_diff = None
        st.rerun()
