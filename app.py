"""
app.py

PatchForge-AI: Universal Security Scanning, Sandboxed Patching & Benchmark Engine.
Autonomous multi-agent remediation pipeline with built-in sandbox evaluation and CLI artifact generation.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
import streamlit as st

from orchestrator import Orchestrator
from evaluator import PatchForgeEvaluator

# Page Configuration
st.set_page_config(
    page_title="PatchForge-AI | Autonomous Remediation Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E88E5;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #6C757D;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #F8F9FA;
        border: 1px solid #E9ECEF;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }
    .status-badge-pass {
        background-color: #D4EDDA;
        color: #155724;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
    .status-badge-fail {
        background-color: #F8D7DA;
        color: #721C24;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


def main():
    # Header Section
    st.markdown('<div class="main-header">🛡️ PatchForge-AI</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Autonomous Vulnerability Remediation & Security Benchmark Engine</div>', unsafe_allow_html=True)

    # Sidebar Options
    st.sidebar.header("⚙️ Execution Settings")
    max_iters = st.sidebar.slider("Max Patch Retries per Finding", min_value=1, max_value=5, value=3)
    
    openai_key = st.sidebar.text_input(
        "OpenAI API Key", 
        value=os.environ.get("OPENAI_API_KEY", ""), 
        type="password",
        help="Required for PatchGenerator agent calls."
    )
    if openai_key:
        os.environ["OPENAI_API_KEY"] = openai_key

    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🛠️ Core Engine Stack")
    st.sidebar.markdown("""
    - **Scanner:** Static AST Analysis
    - **Planner:** Vulnerability Prioritization
    - **Patch Generator:** LLM Differential Engine
    - **Sandbox:** Docker Execution Backend
    - **Evaluator:** Automated Performance Analytics
    """)

    # Main Input Section
    st.markdown("### 📥 Repository Input")
    target_input = st.text_input(
        "Enter Target Repository Path or Remote Git URL:",
        value=".",
        help="Provide a local directory path (e.g. '.') or a public Git repository URL (e.g. 'https://github.com/Ucneeraj/PatchForge-AI.git')."
    )

    run_pipeline = st.button("🚀 Execute Autonomous Pipeline", type="primary", use_container_width=True)

    if run_pipeline:
        if not target_input.strip():
            st.error("Please enter a valid directory path or Git repository URL.")
            return

        st.markdown("---")
        st.markdown("### 🔄 Execution Timeline")
        
        progress_bar = st.progress(0)
        status_text = st.empty()

        # Step 1: Run Multi-Agent Remediation Orchestration
        status_text.text("1/3 Ingesting Repository & Executing Multi-Agent Scanner/Sandbox Engine...")
        progress_bar.progress(25)
        
        start_time = time.time()
        orchestrator = Orchestrator(max_iterations=max_iters)
        
        try:
            report = orchestrator.run_repo(source=target_input)
            progress_bar.progress(60)
            
            # Step 2: Auto-Apply Benchmark Evaluation
            status_text.text("2/3 Running Automatic Benchmark Evaluation & Calculating Metrics...")
            evaluator = PatchForgeEvaluator(orchestrator=orchestrator)
            benchmark_data = evaluator.evaluate_repository(target_input)
            progress_bar.progress(85)

            # Step 3: Generate Production CLI Audit Artifacts
            status_text.text("3/3 Exporting Production Audit & CLI Reports...")
            cli_summary = {
                "source": report.source,
                "files_scanned": report.files_scanned,
                "corrected_clone_path": report.corrected_clone_path,
                "total_outcomes": len(report.outcomes),
                "repaired_count": sum(1 for o in report.outcomes if o.success),
                "outcomes": [
                    {
                        "attempt_id": o.attempt_id,
                        "cwe": getattr(o.finding, "cwe_id", getattr(o.finding, "cwe", "CWE-UNKNOWN")),
                        "file": getattr(o.finding, "file_path", getattr(o.finding, "file", "unknown")),
                        "line": getattr(o.finding, "line_number", getattr(o.finding, "line", 0)),
                        "success": o.success,
                        "iterations": o.iterations_used,
                        "diff": o.final_diff,
                    }
                    for o in report.outcomes
                ],
            }
            
            with open("production_audit.json", "w", encoding="utf-8") as f:
                json.dump(cli_summary, f, indent=2)
                
            progress_bar.progress(100)
            status_text.empty()
            st.success("✅ Complete Pipeline Execution Finished Successfully!")

            # -----------------------------------------------------------------
            # VISUAL RESULTS & BENCHMARK DASHBOARD
            # -----------------------------------------------------------------
            st.markdown("---")
            st.markdown("### 📊 Benchmark Performance Summary")
            
            metrics = benchmark_data["metrics"]
            m_col1, m_col2, m_col3, m_col4, m_col5 = st.columns(5)
            
            m_col1.metric("Repair Success Rate", f"{metrics['success_rate_pct']}%")
            m_col2.metric("Total Findings", metrics["total_findings"])
            m_col3.metric("Repaired / Escalated", f"{metrics['repaired_findings']} / {metrics['failed_findings']}")
            m_col4.metric("Total Latency", f"{metrics['total_duration_seconds']}s")
            m_col5.metric("Estimated Cost", f"${metrics['estimated_cost_usd']}")

            # Detailed Remediation Findings
            st.markdown("### 🔍 Remediation Findings & Sandboxed Diffs")
            
            outcomes = report.outcomes
            if not outcomes:
                st.info("No security vulnerabilities detected in the ingested repository.")
            else:
                for idx, outcome in enumerate(outcomes, 1):
                    cwe_name = getattr(outcome.finding, "cwe_id", getattr(outcome.finding, "cwe", "CWE-UNKNOWN"))
                    file_path = getattr(outcome.finding, "file_path", getattr(outcome.finding, "file", "Unknown File"))
                    line_no = getattr(outcome.finding, "line_number", getattr(outcome.finding, "line", 0))
                    
                    status_badge = "✅ REPAIRED" if outcome.success else "❌ ESCALATED"
                    
                    with st.expander(f"Finding #{idx}: {cwe_name} in {file_path}:{line_no} — {status_badge}", expanded=True):
                        col_a, col_b = st.columns(2)
                        with col_a:
                            st.write(f"**Target File:** `{file_path}`")
                            st.write(f"**Line Number:** `{line_no}`")
                        with col_b:
                            st.write(f"**Iterations Used:** `{outcome.iterations_used} / {max_iters}`")
                            st.write(f"**Status:** {status_badge}")
                        
                        if outcome.final_diff:
                            st.markdown("**Applied Patch Diff:**")
                            st.code(outcome.final_diff, language="diff")
                        else:
                            st.warning("No diff applied. Vulnerability escalated to human review.")

            # Artifact Download Section
            st.markdown("---")
            st.markdown("### 📄 Generated Audit Artifacts")
            art_col1, art_col2 = st.columns(2)
            
            with art_col1:
                st.download_button(
                    label="📥 Download Benchmark Results (JSON)",
                    data=json.dumps(benchmark_data, indent=2),
                    file_name="benchmark_results.json",
                    mime="application/json",
                    use_container_width=True
                )
                
            with art_col2:
                st.download_button(
                    label="📥 Download CLI Audit Report (JSON)",
                    data=json.dumps(cli_summary, indent=2),
                    file_name="production_audit.json",
                    mime="application/json",
                    use_container_width=True
                )

        except Exception as e:
            progress_bar.progress(0)
            status_text.empty()
            st.error(f"❌ Execution failed: {str(e)}")


if __name__ == "__main__":
    main()