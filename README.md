# AWS Security Audit Tool

**Professional interactive web application for comprehensive AWS security audits**

A modern, professional security audit tool designed for security consultants and auditors conducting client workshops and AWS infrastructure assessments.

🌐 **[Try Live Demo on Streamlit Cloud](https://aws-security-audit-tool.streamlit.app)**


<img width="1494" height="739" alt="image" src="https://github.com/user-attachments/assets/4b99b4ec-d89d-47c0-9fa6-1786e447c2dd" />

## Overview

This tool provides an interactive web interface for conducting thorough AWS security audits with:

- **100 advanced technical questions** covering critical AWS services
- **Interactive checklist** with real-time progress tracking
- **Architecture diagram editor** to visualize client infrastructure
- **Session management** to save and resume audits
- **Professional report generation** (Markdown & PDF)
- **Compliance mapping** (ISO 27001, SOC2, PCI-DSS, HIPAA, GDPR, CIS Benchmark, NIST)
- **Cloud deployment** - Live on Streamlit Cloud

## Features

### Interactive Web Interface

- Modern, professional design suitable for client workshops
- Real-time progress tracking and statistics
- Filter questions by severity, compliance framework, and service
- Mark questions as Compliant, Non-Compliant, N/A, or To Review
- Add detailed notes and findings for each question

### AWS Services Covered

#### Identity & Access Management
- IAM policies, roles, and users
- MFA enforcement and password policies
- Access key rotation and management
- Service Control Policies (SCPs)
- Cross-account access and trust policies

#### Network Security
- VPC architecture and isolation
- Security Groups and Network ACLs
- VPC Flow Logs analysis
- VPC Endpoints and PrivateLink
- Network Firewall and inspection

#### Compute & Containers
- EC2 instance security configurations
- Lambda function security
- ECS/EKS container security
- Systems Manager and patch management

#### Storage & Databases
- S3 bucket security and encryption
- RDS security configurations
- Database encryption at rest and in transit
- Backup and recovery procedures

#### Application Services
- API Gateway security
- CloudFront distributions
- Load balancer configurations
- WAF rules and protection

#### Monitoring & Logging
- CloudTrail audit logging
- CloudWatch monitoring and alarms
- Log integrity validation
- Security event analysis

#### Additional Services
- KMS key management and encryption
- Route53 DNS security
- CloudFormation IaC security
- Multi-service integration and compliance

### Architecture Diagram Editor

- Visual diagram builder for documenting client infrastructure
- Pre-defined AWS component templates
- Connection mapping between services
- Save and load diagram states
- Export diagrams with audit reports

### Audit Session Management

- Save audit progress at any time
- Resume previous audit sessions
- Multiple concurrent audits support
- Automatic progress calculation

### Report Generation

Generate professional audit reports including:
- Executive summary with statistics
- Critical and high-risk findings
- Detailed findings by service
- Risk distribution analysis
- Remediation recommendations
- Compliance framework mapping

Export formats:
- **Markdown** - For documentation systems
- **PDF** - For formal client deliverables

## Installation

### Prerequisites

- Python 3.9 to 3.13 (recommended: **3.11**)
- pip package manager

### Quick Start

#### Try Online (No Installation)
Visit **[https://aws-security-audit-tool.streamlit.app](https://aws-security-audit-tool.streamlit.app)** - ready to use immediately!

#### Run Locally - Linux
```bash
git clone https://github.com/K3E9X/AWS-Security-Audit-Tool.git
cd AWS-Security-Audit-Tool
./run.sh
```

#### Run Locally - macOS
```bash
git clone https://github.com/K3E9X/AWS-Security-Audit-Tool.git
cd AWS-Security-Audit-Tool
./run-macos.sh
```

#### Run Locally - Windows
```bash
git clone https://github.com/K3E9X/AWS-Security-Audit-Tool.git
cd AWS-Security-Audit-Tool
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

### Standard Installation

```bash
# Clone the repository
git clone https://github.com/K3E9X/AWS-Security-Audit-Tool.git
cd AWS-Security-Audit-Tool

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Platform-Specific Notes

**macOS Users**: If you encounter compilation errors with numpy/pandas, use:
```bash
pip install -r requirements-macos.txt
```

**Python 3.14 Users**: See [FIX_PYTHON_314.md](FIX_PYTHON_314.md) for compatibility solutions.

For detailed installation instructions, see:
- [README_INSTALLATION.md](README_INSTALLATION.md) - Complete installation guide
- [README_MACOS.md](README_MACOS.md) - macOS-specific guide

## Usage

### Launch the Application

```bash
streamlit run app.py
```

The application will open automatically in your default browser at `http://localhost:8501`

### Conducting an Audit

1. **Start from Dashboard**
   - View overall statistics and progress
   - Understand the scope of the audit (100 questions)

2. **Select Service Category**
   - Use sidebar navigation to select AWS service
   - Available: IAM, VPC, EC2, S3, RDS, Lambda, API Gateway, CloudTrail, CloudFormation, CloudWatch, CloudFront, KMS, Containers, Route53

3. **Answer Questions**
   - Read technical details and verification steps
   - Mark status: Compliant / Non-Compliant / N/A / To Review
   - Assign risk level: Critical / High / Medium / Low
   - Add detailed notes and findings
   - Save each answer

4. **Document Architecture**
   - Navigate to Architecture Diagram
   - Add AWS components (VPC, EC2, RDS, S3, etc.)
   - Create connections between components
   - Save diagram for report inclusion

5. **Generate Report**
   - Navigate to Export Report
   - Enter client name and auditor details
   - Select report options
   - Export as Markdown or PDF

### Session Management

```bash
# Save current audit session
Click "Save Session" in sidebar

# Load previous session
Click "Load Session" in sidebar

# Sessions are stored in: sessions/audit_session_YYYYMMDD_HHMMSS.json
```

## Deployment

### Streamlit Cloud (Production)

The application is live on Streamlit Cloud:

**Live URL:** https://aws-security-audit-tool.streamlit.app

#### Deploy Your Own Instance

1. Fork this repository on GitHub
2. Go to [share.streamlit.io](https://share.streamlit.io/)
3. Connect your GitHub account
4. Deploy with these settings:
   - Repository: `your-username/AWS-Security-Audit-Tool`
   - Branch: `main`
   - Main file: `app.py`
   - **Python version: 3.11** (important!)
5. Click Deploy!

For detailed deployment instructions, see [DEPLOYMENT_STREAMLIT_CLOUD.md](DEPLOYMENT_STREAMLIT_CLOUD.md)

### Local Deployment

See [Installation](#installation) section above.

## Project Structure

```
AWS-Security-Audit-Tool/
├── app.py                              # Main Streamlit application
├── requirements.txt                    # Python dependencies (Streamlit Cloud)
├── requirements-macos.txt              # macOS-optimized dependencies
├── requirements-cloud.txt              # Alternative Cloud dependencies
├── packages.txt                        # System packages
├── .streamlit/
│   ├── config.toml                     # Streamlit configuration
│   └── secrets.toml                    # Secrets template
├── data/
│   ├── __init__.py
│   ├── aws_services_questions.py       # 100 security questions database
│   └── diagrams/                       # Saved architecture diagrams
├── utils/
│   ├── __init__.py
│   ├── session.py                      # Audit session management
│   ├── export.py                       # Report generation (MD/PDF)
│   └── diagram.py                      # Architecture diagram editor
├── sessions/                           # Saved audit sessions
├── reports/                            # Generated reports
├── run.sh                              # Linux launch script
├── run-macos.sh                        # macOS launch script
├── diagnose-macos.sh                   # macOS diagnostic tool
├── README.md                           # This file
├── README_INSTALLATION.md              # Installation guide
├── README_MACOS.md                     # macOS guide
├── FIX_PYTHON_314.md                   # Python 3.14 compatibility
├── DEPLOYMENT_STREAMLIT_CLOUD.md       # Cloud deployment guide
├── STREAMLIT_CLOUD_FIX.md              # Cloud troubleshooting
└── QUICKSTART.md                       # Quick start guide
```

## Question Categories

### Coverage by Service (100 Total Questions)

- **IAM Security** (7 questions) - Password policies, MFA, least privilege, access key rotation, roles, SCPs
- **VPC & Network Security** (7 questions) - Architecture, Security Groups, Flow Logs, NACLs, Endpoints, PrivateLink, Network Firewall
- **EC2 & Compute** (7 questions) - IMDSv2, EBS encryption, instance profiles, security groups, SSH keys, Systems Manager, patching
- **S3 & Storage** (7 questions) - Bucket policies, encryption, versioning, Object Lock, access logging, public access prevention
- **RDS & Databases** (7 questions) - Encryption, network isolation, backups, Multi-AZ, parameter groups, audit logging
- **Lambda & Serverless** (7 questions) - Function security, VPC config, secrets management
- **API Gateway** (7 questions) - Authentication, throttling, WAF integration, logging
- **CloudTrail** (7 questions) - Audit logging, integrity validation, multi-region trails
- **CloudFormation** (7 questions) - IaC security, drift detection, stack policies
- **CloudWatch** (7 questions) - Monitoring, alarms, metrics, log analysis
- **CloudFront** (7 questions) - CDN security, HTTPS enforcement, geo-restrictions, WAF
- **KMS & Encryption** (7 questions) - Key policies, rotation, multi-region keys
- **Containers (ECS/EKS)** (7 questions) - Image scanning, secrets management, network policies
- **Route53** (7 questions) - DNS security, DNSSEC, health checks, routing policies
- **Multi-Service** (7 questions) - Tagging, monitoring, incident response, compliance

## Compliance Frameworks

All questions are mapped to relevant compliance frameworks:

- **ISO 27001** - Information Security Management
- **SOC2** - Service Organization Control 2
- **PCI-DSS** - Payment Card Industry Data Security Standard
- **HIPAA** - Health Insurance Portability and Accountability Act
- **GDPR** - General Data Protection Regulation
- **CIS AWS Foundations Benchmark** - Industry security best practices
- **NIST** - National Institute of Standards and Technology
- **AWS Well-Architected Framework** - Security Pillar

## Technical Details

### Question Structure

Each question includes:

- **ID**: Unique identifier (e.g., IAM-001, VPC-002)
- **Question**: Clear, actionable security question
- **Description**: Context and importance
- **Severity**: CRITICAL, HIGH, MEDIUM, LOW
- **Category**: AWS service category
- **Technical Details**: In-depth technical explanation
- **Remediation Steps**: Step-by-step fix instructions with CLI commands
- **Verification Steps**: Commands to verify compliance
- **References**: Official AWS documentation links
- **Compliance Mapping**: Relevant frameworks

### Example Question Format

```python
Question(
    id="IAM-002",
    question="Is MFA enforced for all privileged users?",
    description="Verify multi-factor authentication is enabled...",
    severity="CRITICAL",
    category="IAM",
    compliance=["ISO 27001", "SOC2", "PCI-DSS", "HIPAA"],
    technical_details="""
    Acceptable MFA types:
    - Hardware MFA: YubiKey, Gemalto
    - Virtual MFA: Google Authenticator, Authy
    - U2F security keys

    MFA should be enforced via:
    - IAM policies with MFA conditions
    - SCP policies at organization level
    """,
    remediation=[
        "Enable MFA for root account via IAM Dashboard",
        "Create IAM policy requiring MFA for privileged operations",
        "Implement SCP to enforce MFA organization-wide"
    ],
    verification_steps=[
        "aws iam get-credential-report",
        "aws iam list-virtual-mfa-devices",
        "aws iam list-users --query 'Users[?not_null(MfaDevices)]'"
    ],
    references=[
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html",
        "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html"
    ]
)
```

### Technology Stack

- **Frontend:** Streamlit 1.32.2
- **Data Visualization:** Plotly 5.20.0
- **Data Processing:** Pandas 2.2.0, NumPy 1.26.4
- **Validation:** Pydantic 2.6.3
- **Report Generation:** ReportLab 4.1.0, Markdown 3.5.2
- **Diagram Editor:** Streamlit-agraph 0.0.45
- **Python:** 3.11+ (tested on 3.9-3.13)

## Use Cases

### Security Consultants
- Conduct client audits during workshops
- Generate professional reports
- Track findings and recommendations
- Document client architecture

### Internal Audit Teams
- Regular security assessments
- Compliance verification
- Track remediation progress
- Generate audit trails

### DevSecOps Teams
- Pre-deployment security checks
- Architecture review
- Security baseline verification
- Continuous compliance monitoring

### Cloud Architects
- Security architecture review
- Best practices validation
- Risk assessment and mitigation
- Knowledge base for security patterns

## Contributing

Contributions are welcome! To add new questions:

1. Edit `data/aws_services_questions.py`
2. Follow the existing question structure
3. Include comprehensive technical details
4. Add CLI verification commands
5. Link to official AWS documentation
6. Map to relevant compliance frameworks
7. Test the question in the interface

For issues, questions, or feature requests:
- GitHub Issues: https://github.com/K3E9X/AWS-Security-Audit-Tool/issues

## Best Practices

### During Client Workshops

1. **Preparation**
   - Review client's AWS architecture beforehand
   - Customize questions if needed
   - Prepare examples relevant to their industry

2. **During Audit**
   - Use Architecture Diagram to map infrastructure
   - Take detailed notes for each finding
   - Assign accurate risk levels
   - Save session frequently

3. **Post-Audit**
   - Review all findings
   - Generate comprehensive report
   - Share recommendations with prioritization
   - Schedule follow-up reviews

### Session Management

- Save sessions after each service category
- Use descriptive session names
- Export intermediate reports
- Keep backup copies of critical audits

## Troubleshooting

### Application won't start

```bash
# Check Python version
python --version  # Should be 3.9-3.13 (recommend 3.11)

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# Clear Streamlit cache
streamlit cache clear
```

### macOS compilation errors

```bash
# Use macOS-optimized requirements
pip install -r requirements-macos.txt

# Or run diagnostic
./diagnose-macos.sh
```

See [README_MACOS.md](README_MACOS.md) for detailed troubleshooting.

### Python 3.14 compatibility

Python 3.14 may have compatibility issues with pyarrow. See [FIX_PYTHON_314.md](FIX_PYTHON_314.md) for solutions.

### Port already in use

```bash
# Use different port
streamlit run app.py --server.port 8502
```

### Streamlit Cloud deployment

See [STREAMLIT_CLOUD_FIX.md](STREAMLIT_CLOUD_FIX.md) for common deployment problems and solutions.

## Documentation

Comprehensive documentation available:

- **[QUICKSTART.md](QUICKSTART.md)** - Quick start guide for all platforms
- **[README_INSTALLATION.md](README_INSTALLATION.md)** - Complete installation guide
- **[README_MACOS.md](README_MACOS.md)** - macOS-specific installation and troubleshooting
- **[FIX_PYTHON_314.md](FIX_PYTHON_314.md)** - Python 3.14 compatibility solutions
- **[DEPLOYMENT_STREAMLIT_CLOUD.md](DEPLOYMENT_STREAMLIT_CLOUD.md)** - Streamlit Cloud deployment guide
- **[STREAMLIT_CLOUD_FIX.md](STREAMLIT_CLOUD_FIX.md)** - Streamlit Cloud troubleshooting

## License

MIT License - See LICENSE file for details

## Support

- **Live Demo:** https://aws-security-audit-tool.streamlit.app
- **GitHub Issues:** https://github.com/K3E9X/AWS-Security-Audit-Tool/issues
- **Documentation:** See docs listed above

## Acknowledgments

- AWS Security Best Practices documentation
- CIS AWS Foundations Benchmark
- AWS Well-Architected Framework - Security Pillar
- Streamlit for the amazing framework
- Security community contributions and feedback

---

**Built for security professionals, by security professionals**

*Professional AWS security auditing made simple, comprehensive, and effective*

---

## Statistics

- **100 Security Questions** covering 15 AWS services
- **8 Compliance Frameworks** mapped
- **Multi-platform Support** (Linux, macOS, Windows)
- **Cloud Deployed** on Streamlit Cloud
- **Open Source** with MIT License
- **Production Ready** with comprehensive documentation

---

**Ready to conduct your first AWS security audit?**

👉 **[Start Now on Streamlit Cloud](https://aws-security-audit-tool.streamlit.app)** 🚀
