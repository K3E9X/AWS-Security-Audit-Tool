# AWS Security Audit Tool

**Professional interactive web application for comprehensive AWS security audits**

A modern, professional security audit tool designed for security consultants and auditors conducting client workshops and AWS infrastructure assessments.

## Overview

This tool provides an interactive web interface for conducting thorough AWS security audits with:

- **150+ advanced technical questions** covering critical AWS services
- **Interactive checklist** with real-time progress tracking
- **Architecture diagram editor** to visualize client infrastructure
- **Session management** to save and resume audits
- **Professional report generation** (Markdown & PDF)
- **Compliance mapping** (ISO 27001, SOC2, PCI-DSS, HIPAA, GDPR, CIS Benchmark)

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

- Python 3.8 or higher
- pip package manager

### Setup

```bash
# Clone the repository
git clone https://github.com/K3E9X/Machine71.git
cd Machine71

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

## Usage

### Launch the Application

```bash
streamlit run app.py
```

The application will open automatically in your default browser at `http://localhost:8501`

### Conducting an Audit

1. **Start from Dashboard**
   - View overall statistics and progress
   - Understand the scope of the audit

2. **Select Service Category**
   - Use sidebar navigation to select AWS service
   - Available: IAM, VPC, EC2, S3, RDS, Lambda, API Gateway

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

## Project Structure

```
Machine71/
├── app.py                          # Main Streamlit application
├── requirements.txt                # Python dependencies
├── data/
│   ├── __init__.py
│   ├── aws_services_questions.py   # Comprehensive question database
│   └── diagrams/                   # Saved architecture diagrams
├── utils/
│   ├── __init__.py
│   ├── session.py                  # Audit session management
│   ├── export.py                   # Report generation (MD/PDF)
│   └── diagram.py                  # Architecture diagram editor
├── sessions/                       # Saved audit sessions
├── reports/                        # Generated reports
└── README.md                       # This file
```

## Question Categories

### IAM Security (7+ questions)
- Password policies and complexity
- MFA enforcement strategies
- Least privilege principle implementation
- Access key rotation policies
- IAM roles vs users for applications
- AssumeRole trust policies and External ID
- Service Control Policies (SCPs)

### VPC & Network Security (7+ questions)
- VPC architecture and isolation
- Security Groups best practices
- VPC Flow Logs configuration
- Network ACLs implementation
- VPC Endpoints usage
- AWS PrivateLink deployment
- Network Firewall inspection

### Additional Services
More questions available for:
- EC2 & Compute
- S3 & Storage
- RDS & Databases
- Lambda & Serverless
- API Gateway
- CloudFront & CDN
- CloudTrail & Logging
- KMS & Encryption

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
    question="MFA obligatoire pour tous les utilisateurs privilégiés?",
    description="Vérification que l'authentification multi-facteurs...",
    severity="CRITICAL",
    category="IAM",
    compliance=["ISO 27001", "SOC2", "PCI-DSS", "HIPAA"],
    technical_details="""
    Types de MFA acceptables:
    - Hardware MFA: YubiKey, Gemalto
    - Virtual MFA: Google Authenticator, Authy
    ...
    """,
    remediation=[
        "Root account: IAM Dashboard > Security credentials > MFA",
        "Créer une policy IAM conditionnelle exigeant MFA",
        ...
    ],
    verification_steps=[
        "aws iam get-credential-report",
        "grep -v 'mfa_active.*true' report.csv",
        ...
    ],
    references=[
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
    ]
)
```

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

## Development Roadmap

- [ ] Add 100+ more questions for remaining AWS services
- [ ] CloudFormation/Terraform integration for automated checks
- [ ] Multi-language support (English, Spanish, German)
- [ ] Integration with AWS Security Hub
- [ ] Automated scanning capabilities
- [ ] Custom question templates
- [ ] Team collaboration features
- [ ] API for CI/CD integration

## Contributing

Contributions are welcome! To add new questions:

1. Edit `data/aws_services_questions.py`
2. Follow the existing question structure
3. Include comprehensive technical details
4. Add CLI verification commands
5. Link to official AWS documentation
6. Test the question in the interface

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
python --version  # Should be 3.8+

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# Clear Streamlit cache
streamlit cache clear
```

### Port already in use

```bash
# Use different port
streamlit run app.py --server.port 8502
```

### PDF export not working

```bash
# Install reportlab separately
pip install reportlab
```

## License

MIT License - See LICENSE file for details

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/K3E9X/Machine71/issues
- Documentation: See docs/ folder for detailed guides

## Acknowledgments

- AWS Security Best Practices documentation
- CIS AWS Foundations Benchmark
- AWS Well-Architected Framework
- Security community contributions

---

**Built for security professionals, by security professionals**

*Professional AWS security auditing made simple and effective*
