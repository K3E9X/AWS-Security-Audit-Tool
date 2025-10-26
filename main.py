from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from typing import Optional, List
import uvicorn

from models import (
    AuditQuestion,
    AuditQuestionsResponse,
    CategoriesResponse,
    AuditCategory,
    SeverityLevel
)
from audit_questions import (
    get_all_questions,
    get_questions_by_category,
    get_questions_by_severity,
    get_questions_by_service,
    get_questions_by_compliance,
    get_category_info
)

# Création de l'application FastAPI
app = FastAPI(
    title="AWS Security Audit API",
    description="""
    API REST pour obtenir des questions d'audit de sécurité AWS.

    Cet outil aide les auditeurs à évaluer la posture de sécurité d'infrastructures SaaS hébergées sur AWS.

    ## Fonctionnalités

    * **Récupérer toutes les questions d'audit**
    * **Filtrer par catégorie** (IAM, Network, Encryption, etc.)
    * **Filtrer par niveau de sévérité** (Critical, High, Medium, Low)
    * **Filtrer par service AWS** (S3, EC2, RDS, etc.)
    * **Filtrer par framework de conformité** (ISO 27001, SOC2, PCI-DSS, GDPR, etc.)
    * **Consulter les catégories disponibles**

    ## Catégories d'audit

    1. **IAM** - Identity and Access Management
    2. **Network** - Sécurité réseau (VPC, Security Groups, WAF)
    3. **Encryption** - Chiffrement des données
    4. **Logging** - Journalisation et monitoring
    5. **Compliance** - Conformité et gouvernance
    6. **Storage** - Sécurité du stockage (S3, EBS)
    7. **Database** - Sécurité des bases de données
    8. **Application** - Sécurité applicative (Lambda, API Gateway)
    9. **Incident Response** - Préparation aux incidents
    10. **Cost Optimization** - Optimisation des coûts (perspective sécurité)

    ## Frameworks de conformité supportés

    * ISO 27001
    * SOC2
    * PCI-DSS
    * HIPAA
    * GDPR
    * CIS AWS Foundations Benchmark
    * OWASP
    """,
    version="1.0.0",
    contact={
        "name": "API Support",
        "email": "security-audit@example.com",
    },
    license_info={
        "name": "MIT",
    },
)


@app.get("/", tags=["General"])
async def root():
    """
    Point d'entrée de l'API - Informations générales
    """
    return {
        "message": "AWS Security Audit API",
        "version": "1.0.0",
        "description": "API pour obtenir des questions d'audit de sécurité AWS",
        "documentation": "/docs",
        "endpoints": {
            "questions": "/questions",
            "categories": "/categories",
            "health": "/health"
        }
    }


@app.get("/health", tags=["General"])
async def health_check():
    """
    Health check endpoint pour vérifier que l'API fonctionne
    """
    return {
        "status": "healthy",
        "total_questions": len(get_all_questions())
    }


@app.get("/categories", response_model=CategoriesResponse, tags=["Categories"])
async def get_categories():
    """
    Récupère la liste de toutes les catégories d'audit disponibles avec leur description

    Returns:
        Liste des catégories avec:
        - Nom de la catégorie
        - Description
        - Nombre de questions
    """
    return CategoriesResponse(categories=get_category_info())


@app.get("/questions", response_model=AuditQuestionsResponse, tags=["Questions"])
async def get_questions(
    category: Optional[AuditCategory] = Query(
        None,
        description="Filtrer par catégorie (iam, network, encryption, etc.)"
    ),
    severity: Optional[SeverityLevel] = Query(
        None,
        description="Filtrer par niveau de sévérité (critical, high, medium, low, info)"
    ),
    service: Optional[str] = Query(
        None,
        description="Filtrer par service AWS (ex: S3, EC2, RDS)"
    ),
    compliance: Optional[str] = Query(
        None,
        description="Filtrer par framework de conformité (ex: ISO 27001, SOC2, PCI-DSS)"
    ),
    limit: Optional[int] = Query(
        None,
        ge=1,
        le=1000,
        description="Nombre maximum de questions à retourner"
    )
):
    """
    Récupère les questions d'audit de sécurité AWS avec filtres optionnels

    ## Exemples d'utilisation:

    - `/questions` - Toutes les questions
    - `/questions?category=iam` - Questions IAM uniquement
    - `/questions?severity=critical` - Questions critiques uniquement
    - `/questions?service=S3` - Questions concernant S3
    - `/questions?compliance=PCI-DSS` - Questions liées à PCI-DSS
    - `/questions?category=network&severity=critical` - Combinaison de filtres

    Args:
        category: Filtrer par catégorie
        severity: Filtrer par sévérité
        service: Filtrer par service AWS
        compliance: Filtrer par framework de conformité
        limit: Nombre maximum de résultats

    Returns:
        Liste de questions d'audit avec métadonnées
    """
    questions = get_all_questions()

    # Application des filtres
    if category:
        questions = [q for q in questions if q.category == category]

    if severity:
        questions = [q for q in questions if q.severity == severity]

    if service:
        questions = [q for q in questions if service in q.aws_services]

    if compliance:
        questions = [q for q in questions if compliance in q.compliance_frameworks]

    # Application de la limite
    if limit:
        questions = questions[:limit]

    return AuditQuestionsResponse(
        total=len(questions),
        category=category,
        questions=questions
    )


@app.get("/questions/{question_id}", response_model=AuditQuestion, tags=["Questions"])
async def get_question_by_id(question_id: str):
    """
    Récupère une question spécifique par son ID

    Args:
        question_id: Identifiant de la question (ex: IAM-001, NET-002)

    Returns:
        Question d'audit complète

    Raises:
        HTTPException: 404 si la question n'existe pas
    """
    questions = get_all_questions()
    question = next((q for q in questions if q.id == question_id), None)

    if not question:
        raise HTTPException(
            status_code=404,
            detail=f"Question avec ID '{question_id}' non trouvée"
        )

    return question


@app.get("/questions/category/{category}", response_model=AuditQuestionsResponse, tags=["Questions"])
async def get_questions_for_category(category: AuditCategory):
    """
    Récupère toutes les questions d'une catégorie spécifique

    Args:
        category: Catégorie d'audit (iam, network, encryption, etc.)

    Returns:
        Liste de questions pour cette catégorie
    """
    questions = get_questions_by_category(category)

    return AuditQuestionsResponse(
        total=len(questions),
        category=category,
        questions=questions
    )


@app.get("/severity/{severity_level}", response_model=AuditQuestionsResponse, tags=["Severity"])
async def get_questions_by_severity_level(severity_level: SeverityLevel):
    """
    Récupère toutes les questions d'un niveau de sévérité spécifique

    Args:
        severity_level: Niveau de sévérité (critical, high, medium, low, info)

    Returns:
        Liste de questions avec ce niveau de sévérité
    """
    questions = get_questions_by_severity(severity_level)

    return AuditQuestionsResponse(
        total=len(questions),
        category=None,
        questions=questions
    )


@app.get("/service/{service_name}", response_model=AuditQuestionsResponse, tags=["Services"])
async def get_questions_for_service(service_name: str):
    """
    Récupère toutes les questions concernant un service AWS spécifique

    Args:
        service_name: Nom du service AWS (ex: S3, EC2, RDS, IAM)

    Returns:
        Liste de questions concernant ce service
    """
    questions = get_questions_by_service(service_name)

    if not questions:
        raise HTTPException(
            status_code=404,
            detail=f"Aucune question trouvée pour le service '{service_name}'"
        )

    return AuditQuestionsResponse(
        total=len(questions),
        category=None,
        questions=questions
    )


@app.get("/compliance/{framework}", response_model=AuditQuestionsResponse, tags=["Compliance"])
async def get_questions_for_compliance(framework: str):
    """
    Récupère toutes les questions liées à un framework de conformité

    Frameworks supportés:
    - ISO 27001
    - SOC2
    - PCI-DSS
    - HIPAA
    - GDPR
    - CIS AWS Foundations
    - OWASP
    - OWASP API Security

    Args:
        framework: Nom du framework de conformité

    Returns:
        Liste de questions liées à ce framework
    """
    questions = get_questions_by_compliance(framework)

    if not questions:
        raise HTTPException(
            status_code=404,
            detail=f"Aucune question trouvée pour le framework '{framework}'"
        )

    return AuditQuestionsResponse(
        total=len(questions),
        category=None,
        questions=questions
    )


@app.get("/stats", tags=["Statistics"])
async def get_statistics():
    """
    Récupère des statistiques sur les questions d'audit

    Returns:
        Statistiques complètes sur:
        - Nombre total de questions
        - Répartition par catégorie
        - Répartition par sévérité
        - Services AWS couverts
        - Frameworks de conformité
    """
    all_questions = get_all_questions()

    # Statistiques par catégorie
    category_stats = {}
    for cat in AuditCategory:
        category_stats[cat.value] = len(get_questions_by_category(cat))

    # Statistiques par sévérité
    severity_stats = {}
    for sev in SeverityLevel:
        severity_stats[sev.value] = len(get_questions_by_severity(sev))

    # Services AWS uniques
    all_services = set()
    for q in all_questions:
        all_services.update(q.aws_services)

    # Frameworks de conformité uniques
    all_frameworks = set()
    for q in all_questions:
        all_frameworks.update(q.compliance_frameworks)

    return {
        "total_questions": len(all_questions),
        "by_category": category_stats,
        "by_severity": severity_stats,
        "aws_services_covered": sorted(list(all_services)),
        "compliance_frameworks": sorted(list(all_frameworks)),
        "total_services": len(all_services),
        "total_frameworks": len(all_frameworks)
    }


if __name__ == "__main__":
    # Lancement du serveur en mode développement
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
