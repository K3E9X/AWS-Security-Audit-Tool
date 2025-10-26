# AWS Security Audit API

API REST complète pour obtenir des questions d'audit de sécurité lors de l'évaluation d'infrastructures SaaS hébergées sur AWS.

## Description

Cet outil fournit une base de données exhaustive de questions d'audit de sécurité AWS, organisées par catégories et niveaux de sévérité. Il aide les auditeurs de sécurité, consultants, et équipes DevSecOps à évaluer la posture de sécurité d'applications SaaS déployées sur AWS.

### Caractéristiques principales

- **70+ questions d'audit** couvrant tous les aspects de sécurité AWS
- **10 catégories** : IAM, Network, Encryption, Logging, Compliance, Storage, Database, Application, Incident Response, Cost Optimization
- **5 niveaux de sévérité** : Critical, High, Medium, Low, Info
- **Conformité** : ISO 27001, SOC2, PCI-DSS, HIPAA, GDPR, CIS AWS Foundations, OWASP
- **API REST complète** avec documentation interactive (Swagger/OpenAPI)
- **Filtres multiples** : par catégorie, sévérité, service AWS, framework de conformité
- **Détails complets** : description, étapes de remédiation, références AWS

## Installation

### Prérequis

- Python 3.8+
- pip

### Installation des dépendances

```bash
# Cloner le repository
git clone <repository-url>
cd Machine71

# Créer un environnement virtuel (recommandé)
python -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt
```

## Démarrage rapide

### Lancer l'API

```bash
python main.py
```

L'API sera accessible sur `http://localhost:8000`

### Documentation interactive

Une fois l'API lancée, accédez à la documentation interactive Swagger UI :

```
http://localhost:8000/docs
```

Ou la documentation ReDoc :

```
http://localhost:8000/redoc
```

## Utilisation

### Endpoints disponibles

#### 1. Informations générales

```bash
# Point d'entrée de l'API
GET /

# Health check
GET /health
```

#### 2. Catégories

```bash
# Lister toutes les catégories
GET /categories
```

**Exemple de réponse :**
```json
{
  "categories": [
    {
      "category": "iam",
      "name": "IAM - Identity and Access Management",
      "description": "Gestion des identités, permissions, et contrôles d'accès",
      "question_count": 7
    },
    ...
  ]
}
```

#### 3. Questions d'audit

```bash
# Récupérer toutes les questions
GET /questions

# Filtrer par catégorie
GET /questions?category=iam

# Filtrer par sévérité
GET /questions?severity=critical

# Filtrer par service AWS
GET /questions?service=S3

# Filtrer par framework de conformité
GET /questions?compliance=PCI-DSS

# Combiner plusieurs filtres
GET /questions?category=network&severity=critical

# Limiter le nombre de résultats
GET /questions?limit=10
```

**Exemple de réponse :**
```json
{
  "total": 70,
  "category": null,
  "questions": [
    {
      "id": "IAM-001",
      "category": "iam",
      "question": "Le MFA est-il activé pour le compte root AWS?",
      "description": "Le compte root a un accès complet à tous les services...",
      "severity": "critical",
      "aws_services": ["IAM"],
      "compliance_frameworks": ["ISO 27001", "SOC2", "PCI-DSS", "HIPAA"],
      "remediation_steps": [
        "Se connecter avec le compte root",
        "Accéder à 'Security Credentials'",
        "Activer MFA virtuel ou matériel"
      ],
      "references": [
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
      ]
    }
  ]
}
```

#### 4. Question spécifique

```bash
# Récupérer une question par son ID
GET /questions/IAM-001
```

#### 5. Questions par catégorie

```bash
# Récupérer toutes les questions d'une catégorie
GET /questions/category/iam
GET /questions/category/network
GET /questions/category/encryption
```

#### 6. Questions par sévérité

```bash
# Récupérer les questions par niveau de sévérité
GET /severity/critical
GET /severity/high
GET /severity/medium
```

#### 7. Questions par service AWS

```bash
# Récupérer les questions concernant un service
GET /service/S3
GET /service/EC2
GET /service/RDS
```

#### 8. Questions par framework de conformité

```bash
# Récupérer les questions liées à un framework
GET /compliance/PCI-DSS
GET /compliance/ISO 27001
GET /compliance/HIPAA
```

#### 9. Statistiques

```bash
# Récupérer des statistiques globales
GET /stats
```

**Exemple de réponse :**
```json
{
  "total_questions": 70,
  "by_category": {
    "iam": 7,
    "network": 7,
    "encryption": 6,
    ...
  },
  "by_severity": {
    "critical": 18,
    "high": 25,
    "medium": 20,
    ...
  },
  "aws_services_covered": ["IAM", "S3", "EC2", "RDS", ...],
  "compliance_frameworks": ["ISO 27001", "SOC2", "PCI-DSS", ...],
  "total_services": 35,
  "total_frameworks": 8
}
```

## Exemples d'utilisation

### Avec curl

```bash
# Récupérer toutes les questions critiques
curl "http://localhost:8000/questions?severity=critical"

# Récupérer les questions IAM
curl "http://localhost:8000/questions?category=iam"

# Récupérer une question spécifique
curl "http://localhost:8000/questions/IAM-001"

# Récupérer les statistiques
curl "http://localhost:8000/stats"
```

### Avec Python

```python
import requests

# Récupérer les questions critiques de sécurité réseau
response = requests.get(
    "http://localhost:8000/questions",
    params={
        "category": "network",
        "severity": "critical"
    }
)

data = response.json()
print(f"Nombre de questions: {data['total']}")

for question in data['questions']:
    print(f"\n[{question['id']}] {question['question']}")
    print(f"Services: {', '.join(question['aws_services'])}")
```

### Script d'exemple complet

Un script d'exemple complet est fourni dans `example_usage.py` :

```bash
python example_usage.py
```

Ce script démontre :
- Comment interroger l'API
- Comment filtrer les questions
- Comment générer une checklist d'audit complète

## Catégories d'audit

### 1. IAM (Identity and Access Management)
Questions sur la gestion des identités, permissions, MFA, rotation des clés, principe du moindre privilège.

### 2. Network Security
Sécurité réseau, VPC, Security Groups, NACLs, WAF, protection DDoS.

### 3. Encryption
Chiffrement des données au repos et en transit (S3, EBS, RDS, SSL/TLS).

### 4. Logging & Monitoring
CloudTrail, CloudWatch, VPC Flow Logs, GuardDuty, détection des menaces.

### 5. Compliance & Governance
AWS Organizations, Service Control Policies, AWS Config, Security Hub, backups.

### 6. Storage Security
Sécurité S3 (encryption, accès public, versioning, logging).

### 7. Database Security
Sécurité RDS et DynamoDB (encryption, isolation réseau, backups).

### 8. Application Security
Lambda, API Gateway, ECR, gestion des secrets, scanning de vulnérabilités.

### 9. Incident Response
Préparation et réponse aux incidents, forensics, contacts de sécurité.

### 10. Cost Optimization (Security perspective)
Détection d'activités anormales via les coûts, ressources orphelines.

## Frameworks de conformité supportés

- **ISO 27001** - Norme internationale de gestion de la sécurité de l'information
- **SOC2** - Service Organization Control 2
- **PCI-DSS** - Payment Card Industry Data Security Standard
- **HIPAA** - Health Insurance Portability and Accountability Act
- **GDPR** - General Data Protection Regulation
- **CIS AWS Foundations Benchmark** - Best practices de sécurité AWS
- **OWASP** - Open Web Application Security Project
- **OWASP API Security** - Sécurité des APIs

## Services AWS couverts

IAM, EC2, VPC, S3, RDS, DynamoDB, CloudTrail, CloudWatch, KMS, Lambda, API Gateway, CloudFront, ALB, EBS, EFS, GuardDuty, Security Hub, Config, Organizations, WAF, Secrets Manager, Systems Manager, ECR, ECS, EKS, Route53, SNS, Budgets, et plus.

## Structure du projet

```
Machine71/
├── main.py                 # Application FastAPI principale
├── models.py              # Modèles Pydantic (Question, Category, etc.)
├── audit_questions.py     # Base de données des questions d'audit
├── requirements.txt       # Dépendances Python
├── example_usage.py       # Script d'exemple d'utilisation
├── .env.example          # Exemple de configuration
├── .gitignore            # Fichiers à ignorer par Git
└── README.md             # Cette documentation
```

## Configuration

Créer un fichier `.env` à partir de `.env.example` :

```bash
cp .env.example .env
```

Variables disponibles :
- `API_HOST` : Hôte de l'API (défaut: 0.0.0.0)
- `API_PORT` : Port de l'API (défaut: 8000)
- `API_RELOAD` : Auto-reload en dev (défaut: True)
- `ENVIRONMENT` : Environnement (development/production)
- `LOG_LEVEL` : Niveau de log (info/debug/warning)

## Déploiement en production

### Avec Uvicorn

```bash
# Installation de uvicorn avec support production
pip install uvicorn[standard]

# Lancement en production
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Avec Docker

Créer un `Dockerfile` :

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

Build et run :

```bash
docker build -t aws-security-audit-api .
docker run -p 8000:8000 aws-security-audit-api
```

### Avec Docker Compose

Créer un `docker-compose.yml` :

```yaml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - ENVIRONMENT=production
      - LOG_LEVEL=info
    restart: unless-stopped
```

```bash
docker-compose up -d
```

## Utilisation pour un audit

### 1. Préparation de l'audit

```bash
# Récupérer toutes les catégories pour planifier l'audit
curl http://localhost:8000/categories
```

### 2. Audit par priorité

```bash
# Commencer par les questions critiques
curl "http://localhost:8000/questions?severity=critical"

# Puis high
curl "http://localhost:8000/questions?severity=high"
```

### 3. Audit par domaine

```bash
# Audit IAM
curl "http://localhost:8000/questions/category/iam"

# Audit Network
curl "http://localhost:8000/questions/category/network"
```

### 4. Audit de conformité

```bash
# Audit PCI-DSS
curl "http://localhost:8000/compliance/PCI-DSS"

# Audit HIPAA
curl "http://localhost:8000/compliance/HIPAA"
```

### 5. Générer un rapport

Utiliser le script `example_usage.py` pour générer une checklist complète :

```bash
python example_usage.py > rapport_audit.txt
```

## Contribution

Les contributions sont les bienvenues ! Pour ajouter de nouvelles questions :

1. Éditer `audit_questions.py`
2. Ajouter une nouvelle `AuditQuestion` dans la liste `AUDIT_QUESTIONS`
3. Suivre le format existant avec tous les champs requis
4. Tester l'API

Exemple de nouvelle question :

```python
AuditQuestion(
    id="IAM-008",
    category=AuditCategory.IAM,
    question="Votre question ici?",
    description="Description détaillée",
    severity=SeverityLevel.HIGH,
    aws_services=["IAM"],
    compliance_frameworks=["ISO 27001"],
    remediation_steps=[
        "Étape 1",
        "Étape 2"
    ],
    references=["https://docs.aws.amazon.com/..."]
)
```

## Licence

MIT License

## Support

Pour toute question ou suggestion :
- Créer une issue sur GitHub
- Email : security-audit@example.com

## Ressources

- [AWS Security Best Practices](https://aws.amazon.com/security/best-practices/)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Well-Architected Framework - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [AWS Security Documentation](https://docs.aws.amazon.com/security/)

## Changelog

### Version 1.0.0 (2025-10-26)

- Version initiale
- 70+ questions d'audit
- 10 catégories de sécurité
- Support de 8 frameworks de conformité
- API REST complète avec filtres
- Documentation interactive Swagger/OpenAPI
