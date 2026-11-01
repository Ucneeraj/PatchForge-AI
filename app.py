import os
import time
import tempfile
import streamlit as st
from pathlib import Path
from dataclasses import asdict, is_dataclass

# Import Orchestrator and Agents
from orchestrator import Orchestrator
from agents.repo_ingestion_agent import RepoIngestionAgent

# --- Page Configuration ---
st.set_page_config(
    page_title="PatchForge-AI | Autonomous Remediation Pipeline",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
    <style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E293B;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #64748B;
        margin-bottom: 1.5rem;
    }
    </style>
""", unsafe_allow_html=True)

# --- Header Section ---
st.markdown('<div class="main-header">🛡️ PatchForge-AI: Autonomous Code Remediation</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Multi-Agent Pipeline for Scanning, Patching, and Containerized Sandboxed Verification</div>', unsafe_allow_html=True)

# --- Sidebar Inputs ---
with st.sidebar:
    st.header("⚙️ Target Repository")
    repo_url = st.text_input(
        "GitHub Repository URL",
        value="",
        placeholder="https://github.com/username/repository.git",
        help="Enter any public Git repository link to scan and repair."
    )
    
    st.header("🔑 API Credentials")
    openai_key = st.text_input(
        "OpenAI API Key",
        value="",
        type="password",
        placeholder="sk-proj-...",
        help="Provide your OpenAI API key for patch generation."
    )
    
    st.divider()
    st.header("🤖 Agent Architecture")
    st.caption("Pipeline: Ingestion ➔ Scanner ➔ Planner ➔ Generator ➔ Sandbox Runner ➔ Verifier")
    
    start_pipeline = st.button("🚀 Run Remediation Pipeline", type="primary", use_container_width=True)

# --- Main Dashboard ---
if not start_pipeline:
    # Default Landing View
    col1, col2, col3 = st.columns(3)
    with col1:
        st.info("**1. Automated Scanning**\nDetects security flaws, bugs, and failing test scripts across the codebase.")
    with col2:
        st.warning("**2. LLM Patch Generation**\nGenerates targeted code repairs using contextual awareness and iterative reflection.")
    with col3:
        st.success("**3. Docker Sandboxing**\nExecutes patches inside isolated test containers to verify non-breaking fixes.")
        
    st.markdown("---")
    st.caption("👈 Enter a GitHub repository link and OpenAI API Key in the sidebar, then click **Run Remediation Pipeline**.")

else:
    # Validate inputs
    active_key = openai_key.strip() or os.environ.get("OPENAI_API_KEY", "")

    if not repo_url.strip():
        st.error("⚠️ Please provide a valid GitHub repository URL in the sidebar.")
    elif not active_key:
        st.error("⚠️ Please enter your OpenAI API key in the sidebar before running the pipeline.")
    else:
        # Inject API key into system environment for OpenAI client
        os.environ["OPENAI_API_KEY"] = active_key
        
        st.subheader(f"📍 Target: `{repo_url.strip()}`")
        
        status_container = st.status("🚀 Initializing Multi-Agent Pipeline...", expanded=True)
        
        try:
            # 1. Repo Ingestion Phase
            status_container.write("📥 **[Agent: Repo Ingestion]** Cloning repository snapshot...")
            ingest_agent = RepoIngestionAgent()
            workdir = tempfile.mkdtemp(prefix="patchforge_ui_")
            
            try:
                local_path = ingest_agent._clone(repo_url.strip(), workdir)
            except Exception as clone_err:
                status_container.update(label="❌ Git Clone Failed", state="error", expanded=True)
                st.error(f"Failed to clone repository. Check the URL and try again. Details: {clone_err}")
                st.stop()
                
            status_container.write("✅ Repository ingested successfully.")

            # 2. Orchestrator Phase
            status_container.write("🔍 **[Agents: Scanner / Patch Generator / Sandbox Runner]** Executing repair loop...")
            
            orchestrator = Orchestrator()
            
            start_time = time.time()
            raw_report = orchestrator.run_repo(source=local_path)
            duration = round(time.time() - start_time, 2)
            
            # Convert dataclass report to dictionary safely
            if is_dataclass(raw_report):
                report = asdict(raw_report)
            elif isinstance(raw_report, dict):
                report = raw_report
            else:
                report = {"outcomes": raw_report if isinstance(raw_report, list) else []}

            status_container.update(label=f"🎉 Pipeline Completed in {duration}s!", state="complete", expanded=False)

            # --- Results Presentation Section ---
            st.markdown("---")
            st.subheader("📊 Remediation Executive Summary")
            
            # Safely extract outcomes
            outcomes = report.get("outcomes", report.get("file_outcomes", []))
            if not isinstance(outcomes, list):
                outcomes = []
                
            total_scanned = report.get("files_scanned", len(outcomes))
            passed = sum(1 for item in outcomes if item.get("success") is True or str(item.get("status", "")).upper() in ["PASS", "SUCCESS", "REPAIRED"])
            failed = len(outcomes) - passed

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Execution Time", f"{duration}s")
            m2.metric("Files Scanned", total_scanned)
            m3.metric("Successfully Patched", passed)
            m4.metric("Failed Attempts", failed)

            st.markdown("### 📝 Detailed File Repair Report")
            
            if outcomes:
                for idx, outcome in enumerate(outcomes, 1):
                    finding = outcome.get("finding", {})
                    file_name = finding.get("file_path", outcome.get("file", outcome.get("target_file", f"File #{idx}")))
                    is_success = outcome.get("success", False) or str(outcome.get("status", "")).upper() in ["PASS", "SUCCESS", "REPAIRED"]
                    status_str = "REPAIRED" if is_success else "FAILED"
                    attempts = outcome.get("iterations_used", outcome.get("attempts", outcome.get("iterations", "-")))
                    
                    test_rep = outcome.get("test_report", {})
                    summary = test_rep.get("stack_trace_summary") or outcome.get("summary", "No details reported.")

                    if is_success:
                        st.success(f"**[{status_str}]** `{file_name}` — Repaired in {attempts} attempt(s)")
                    else:
                        st.error(f"**[{status_str}]** `{file_name}` — Failed after {attempts} attempt(s)")
                    
                    with st.expander(f"Inspect outcome details for {file_name}"):
                        if finding:
                            st.write(f"**Vulnerability Rule:** `{finding.get('rule_id')}` | **CWE:** `{finding.get('cwe_id')}` | **Severity:** `{finding.get('severity')}`")
                            st.code(finding.get("snippet", ""), language="python")
                        st.text_area("Stack Trace / Test Log", summary, height=150)
            else:
                st.info("No actionable vulnerabilities or failing tests detected in the target repository.")

            st.markdown("### 📄 Raw JSON Output")
            with st.expander("View Full Structured JSON Payload"):
                st.json(report)

        except Exception as e:
            status_container.update(label="❌ Pipeline Execution Failed", state="error", expanded=True)
            st.error(f"Pipeline encountered an unexpected error: **{e}**")