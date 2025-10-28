"""
AWS Security Audit Tool - Interface Interactive
Application web professionnelle pour audits de sécurité AWS
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import json
from datetime import datetime
from pathlib import Path

# Configuration de la page
st.set_page_config(
    page_title="AWS Security Audit Tool",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Import des modules
from data.aws_services_questions import ALL_QUESTIONS, IAM_QUESTIONS, VPC_QUESTIONS
from utils.session import AuditSession
from utils.export import export_to_markdown, export_to_pdf
from utils.diagram import DiagramEditor

# Styles CSS personnalisés
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #232F3E;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #5A6C7D;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    .critical {
        background-color: #FF4B4B;
        color: white;
        padding: 0.3rem 0.8rem;
        border-radius: 5px;
        font-weight: 600;
    }
    .high {
        background-color: #FFA500;
        color: white;
        padding: 0.3rem 0.8rem;
        border-radius: 5px;
        font-weight: 600;
    }
    .medium {
        background-color: #FFD700;
        color: #333;
        padding: 0.3rem 0.8rem;
        border-radius: 5px;
        font-weight: 600;
    }
    .low {
        background-color: #90EE90;
        color: #333;
        padding: 0.3rem 0.8rem;
        border-radius: 5px;
        font-weight: 600;
    }
    .question-card {
        border-left: 4px solid #667eea;
        padding: 1rem;
        margin: 1rem 0;
        background-color: #f8f9fa;
        border-radius: 5px;
    }
    .stButton>button {
        width: 100%;
        border-radius: 5px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'audit_session' not in st.session_state:
    st.session_state.audit_session = AuditSession()

if 'current_page' not in st.session_state:
    st.session_state.current_page = "Dashboard"

# Sidebar Navigation
with st.sidebar:
    st.markdown("### Navigation")

    menu = {
        "Dashboard": "📊",
        "IAM Security": "👤",
        "VPC & Network": "🌐",
        "EC2 & Compute": "💻",
        "S3 & Storage": "📦",
        "RDS & Databases": "🗄️",
        "Lambda & Serverless": "⚡",
        "API Gateway": "🔌",
        "Architecture Diagram": "🏗️",
        "Audit Session": "📋",
        "Export Report": "📄"
    }

    for page, icon in menu.items():
        if st.button(f"{icon} {page}", key=f"nav_{page}"):
            st.session_state.current_page = page

    st.markdown("---")
    st.markdown("### Current Session")
    session = st.session_state.audit_session
    st.metric("Questions Answered", f"{session.answered}/{session.total}")
    st.metric("Progress", f"{session.progress}%")

    if st.button("Save Session"):
        session.save()
        st.success("Session saved!")

    if st.button("Load Session"):
        session.load()
        st.success("Session loaded!")

# Main Content Area
def render_dashboard():
    st.markdown('<div class="main-header">AWS Security Audit Tool</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Professional security audit framework for AWS infrastructure</div>', unsafe_allow_html=True)

    # Metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown("""
        <div class="metric-card">
            <h2>150+</h2>
            <p>Security Questions</p>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        critical_count = len([q for q in ALL_QUESTIONS if q.severity == "CRITICAL"])
        st.markdown(f"""
        <div class="metric-card">
            <h2>{critical_count}</h2>
            <p>Critical Items</p>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        services_count = len(set([q.category for q in ALL_QUESTIONS]))
        st.markdown(f"""
        <div class="metric-card">
            <h2>{services_count}</h2>
            <p>AWS Services</p>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown("""
        <div class="metric-card">
            <h2>8</h2>
            <p>Compliance Frameworks</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # Distribution charts
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Questions by Severity")
        severity_counts = pd.DataFrame([
            {"Severity": q.severity, "Count": 1} for q in ALL_QUESTIONS
        ]).groupby("Severity").count().reset_index()

        fig = go.Figure(data=[
            go.Bar(
                x=severity_counts['Severity'],
                y=severity_counts['Count'],
                marker_color=['#FF4B4B', '#FFA500', '#FFD700', '#90EE90']
            )
        ])
        fig.update_layout(
            xaxis_title="Severity Level",
            yaxis_title="Number of Questions",
            height=300
        )
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Questions by Service")
        category_counts = pd.DataFrame([
            {"Category": q.category, "Count": 1} for q in ALL_QUESTIONS
        ]).groupby("Category").count().reset_index()

        fig = go.Figure(data=[
            go.Pie(
                labels=category_counts['Category'],
                values=category_counts['Count'],
                hole=0.4
            )
        ])
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")

    # Quick Start Guide
    st.subheader("Quick Start Guide")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("""
        **Step 1: Select Service**

        Navigate to the specific AWS service you want to audit using the sidebar menu.
        """)

    with col2:
        st.markdown("""
        **Step 2: Answer Questions**

        Review each security question and mark as compliant, non-compliant, or N/A. Add notes for findings.
        """)

    with col3:
        st.markdown("""
        **Step 3: Export Report**

        Generate a comprehensive audit report in Markdown or PDF format for documentation.
        """)

def render_service_questions(service_name, questions):
    st.markdown(f'<div class="main-header">{service_name}</div>', unsafe_allow_html=True)

    # Filters
    col1, col2, col3 = st.columns(3)

    with col1:
        severity_filter = st.multiselect(
            "Filter by Severity",
            options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        )

    with col2:
        compliance_options = list(set([c for q in questions for c in q.compliance]))
        compliance_filter = st.multiselect(
            "Filter by Compliance",
            options=compliance_options,
            default=compliance_options
        )

    with col3:
        show_only_unanswered = st.checkbox("Show only unanswered")

    # Filter questions
    filtered_questions = [
        q for q in questions
        if q.severity in severity_filter
        and any(c in compliance_filter for c in q.compliance)
    ]

    if show_only_unanswered:
        filtered_questions = [
            q for q in filtered_questions
            if q.id not in st.session_state.audit_session.answers
        ]

    st.markdown(f"**Showing {len(filtered_questions)} of {len(questions)} questions**")
    st.markdown("---")

    # Display questions
    for idx, question in enumerate(filtered_questions):
        with st.expander(f"**{question.id}** | {question.question}", expanded=False):
            # Severity badge
            severity_class = question.severity.lower()
            st.markdown(f'<span class="{severity_class}">{question.severity}</span>', unsafe_allow_html=True)

            # Question details
            st.markdown(f"**Description:** {question.description}")

            # Technical details
            with st.container():
                st.markdown("**Technical Details:**")
                st.code(question.technical_details.strip(), language="text")

            # Compliance
            st.markdown(f"**Compliance Frameworks:** {', '.join(question.compliance)}")

            # Remediation
            with st.container():
                st.markdown("**Remediation Steps:**")
                for step in question.remediation:
                    st.markdown(f"- {step}")

            # Verification
            with st.container():
                st.markdown("**Verification Steps:**")
                for step in question.verification_steps:
                    st.code(step, language="bash")

            # References
            st.markdown("**References:**")
            for ref in question.references:
                st.markdown(f"- [{ref}]({ref})")

            # Answer section
            st.markdown("---")
            col1, col2, col3 = st.columns([2, 2, 3])

            with col1:
                answer = st.radio(
                    "Status",
                    options=["Compliant", "Non-Compliant", "N/A", "To Review"],
                    key=f"answer_{question.id}",
                    horizontal=True
                )

            with col2:
                risk_level = st.select_slider(
                    "Risk Level",
                    options=["Low", "Medium", "High", "Critical"],
                    key=f"risk_{question.id}"
                )

            with col3:
                notes = st.text_area(
                    "Notes / Findings",
                    key=f"notes_{question.id}",
                    height=100
                )

            if st.button("Save Answer", key=f"save_{question.id}"):
                st.session_state.audit_session.save_answer(
                    question.id,
                    answer,
                    risk_level,
                    notes
                )
                st.success("Answer saved!")

def render_diagram_editor():
    st.markdown('<div class="main-header">Architecture Diagram</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Visualize client AWS architecture during audit</div>', unsafe_allow_html=True)

    st.markdown("""
    Use this tool to document the client's AWS architecture. This helps in:
    - Understanding the infrastructure layout
    - Identifying security boundaries
    - Mapping data flows
    - Documenting findings visually
    """)

    diagram_editor = DiagramEditor()
    diagram_editor.render()

def render_export():
    st.markdown('<div class="main-header">Export Audit Report</div>', unsafe_allow_html=True)

    session = st.session_state.audit_session

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Report Details")
        client_name = st.text_input("Client Name")
        auditor_name = st.text_input("Auditor Name")
        report_date = st.date_input("Report Date", datetime.now())

    with col2:
        st.subheader("Include Sections")
        include_compliant = st.checkbox("Include Compliant Items", value=False)
        include_na = st.checkbox("Include N/A Items", value=False)
        include_diagrams = st.checkbox("Include Architecture Diagrams", value=True)

    st.markdown("---")

    col1, col2 = st.columns(2)

    with col1:
        if st.button("Export as Markdown", use_container_width=True):
            markdown_content = export_to_markdown(
                session,
                client_name,
                auditor_name,
                report_date,
                include_compliant,
                include_na
            )
            st.download_button(
                "Download Markdown Report",
                markdown_content,
                file_name=f"aws_audit_{client_name}_{report_date}.md",
                mime="text/markdown"
            )

    with col2:
        if st.button("Export as PDF", use_container_width=True):
            pdf_content = export_to_pdf(
                session,
                client_name,
                auditor_name,
                report_date,
                include_compliant,
                include_na
            )
            st.download_button(
                "Download PDF Report",
                pdf_content,
                file_name=f"aws_audit_{client_name}_{report_date}.pdf",
                mime="application/pdf"
            )

# Route to appropriate page
page = st.session_state.current_page

if page == "Dashboard":
    render_dashboard()
elif page == "IAM Security":
    render_service_questions("IAM Security", IAM_QUESTIONS)
elif page == "VPC & Network":
    render_service_questions("VPC & Network Security", VPC_QUESTIONS)
elif page == "Architecture Diagram":
    render_diagram_editor()
elif page == "Export Report":
    render_export()
else:
    st.info(f"{page} - Section en cours de développement")
    st.markdown("Plus de 150 questions techniques seront ajoutées pour ce service.")
