from pydantic import BaseModel, Field
from typing import List, Optional
from enum import Enum


class SeverityLevel(str, Enum):
    """Niveau de sévérité pour les questions d'audit"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AuditCategory(str, Enum):
    """Catégories d'audit de sécurité AWS"""
    IAM = "iam"
    NETWORK = "network"
    ENCRYPTION = "encryption"
    LOGGING = "logging"
    COMPLIANCE = "compliance"
    STORAGE = "storage"
    DATABASE = "database"
    APPLICATION = "application"
    INCIDENT_RESPONSE = "incident_response"
    COST_OPTIMIZATION = "cost_optimization"


class AuditQuestion(BaseModel):
    """Modèle pour une question d'audit de sécurité"""
    id: str = Field(..., description="Identifiant unique de la question")
    category: AuditCategory = Field(..., description="Catégorie de la question")
    question: str = Field(..., description="Question d'audit")
    description: str = Field(..., description="Description détaillée")
    severity: SeverityLevel = Field(..., description="Niveau de sévérité")
    aws_services: List[str] = Field(..., description="Services AWS concernés")
    compliance_frameworks: List[str] = Field(
        default_factory=list,
        description="Frameworks de conformité (ISO 27001, SOC2, GDPR, etc.)"
    )
    remediation_steps: Optional[List[str]] = Field(
        default=None,
        description="Étapes de remédiation recommandées"
    )
    references: Optional[List[str]] = Field(
        default=None,
        description="Liens vers documentation AWS"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "id": "IAM-001",
                "category": "iam",
                "question": "MFA est-il activé pour tous les utilisateurs IAM?",
                "description": "Vérifier que l'authentification multi-facteurs est obligatoire",
                "severity": "critical",
                "aws_services": ["IAM"],
                "compliance_frameworks": ["ISO 27001", "SOC2"],
                "remediation_steps": [
                    "Activer MFA pour le compte root",
                    "Créer une politique IAM exigeant MFA"
                ],
                "references": [
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
                ]
            }
        }


class AuditQuestionsResponse(BaseModel):
    """Réponse contenant plusieurs questions d'audit"""
    total: int = Field(..., description="Nombre total de questions")
    category: Optional[AuditCategory] = Field(None, description="Catégorie filtrée")
    questions: List[AuditQuestion] = Field(..., description="Liste des questions")


class CategoriesResponse(BaseModel):
    """Réponse listant les catégories disponibles"""
    categories: List[dict] = Field(..., description="Liste des catégories avec descriptions")
