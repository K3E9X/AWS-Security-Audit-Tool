from models import AuditQuestion, AuditCategory, SeverityLevel
from typing import List, Dict


# Base de données complète des questions d'audit de sécurité AWS
AUDIT_QUESTIONS: List[AuditQuestion] = [

    # ==================== IAM (Identity and Access Management) ====================
    AuditQuestion(
        id="IAM-001",
        category=AuditCategory.IAM,
        question="Le MFA est-il activé pour le compte root AWS?",
        description="Le compte root a un accès complet à tous les services. Il DOIT être protégé par MFA.",
        severity=SeverityLevel.CRITICAL,
        aws_services=["IAM"],
        compliance_frameworks=["ISO 27001", "SOC2", "PCI-DSS", "HIPAA"],
        remediation_steps=[
            "Se connecter avec le compte root",
            "Accéder à 'Security Credentials'",
            "Activer MFA virtuel ou matériel"
        ],
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"]
    ),

    AuditQuestion(
        id="IAM-002",
        category=AuditCategory.IAM,
        question="Le compte root est-il utilisé uniquement pour les tâches nécessitant explicitement root?",
        description="L'utilisation quotidienne du compte root doit être évitée. Utiliser des comptes IAM avec privilèges appropriés.",
        severity=SeverityLevel.CRITICAL,
        aws_services=["IAM", "CloudTrail"],
        compliance_frameworks=["ISO 27001", "SOC2", "CIS AWS Foundations"],
        remediation_steps=[
            "Créer des utilisateurs IAM administratifs",
            "Verrouiller les clés d'accès root",
            "Monitorer l'utilisation root via CloudTrail"
        ],
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"]
    ),

    AuditQuestion(
        id="IAM-003",
        category=AuditCategory.IAM,
        question="Le MFA est-il activé pour tous les utilisateurs IAM avec accès console?",
        description="Tous les utilisateurs avec accès à la console AWS doivent avoir MFA activé.",
        severity=SeverityLevel.CRITICAL,
        aws_services=["IAM"],
        compliance_frameworks=["ISO 27001", "SOC2", "GDPR"],
        remediation_steps=[
            "Créer une politique IAM conditionnelle exigeant MFA",
            "Auditer les utilisateurs sans MFA",
            "Forcer l'activation MFA lors de la première connexion"
        ],
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_users-self-manage-mfa-and-creds.html"]
    ),

    AuditQuestion(
        id="IAM-004",
        category=AuditCategory.IAM,
        question="Les clés d'accès AWS non utilisées sont-elles identifiées et supprimées?",
        description="Les clés d'accès inactives depuis plus de 90 jours doivent être désactivées ou supprimées.",
        severity=SeverityLevel.HIGH,
        aws_services=["IAM"],
        compliance_frameworks=["CIS AWS Foundations", "SOC2"],
        remediation_steps=[
            "Générer un rapport de credentials IAM",
            "Identifier les clés avec Last Used > 90 jours",
            "Désactiver puis supprimer après validation"
        ],
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html"]
    ),

    AuditQuestion(
        id="IAM-005",
        category=AuditCategory.IAM,
        question="Les politiques IAM suivent-elles le principe du moindre privilège?",
        description="Vérifier que les utilisateurs et rôles ont uniquement les permissions nécessaires.",
        severity=SeverityLevel.HIGH,
        aws_services=["IAM", "IAM Access Analyzer"],
        compliance_frameworks=["ISO 27001", "SOC2", "GDPR"],
        remediation_steps=[
            "Utiliser IAM Access Analyzer pour identifier les permissions excessives",
            "Réviser les politiques avec wildcards (*)",
            "Implémenter des politiques basées sur les conditions"
        ],
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"]
    ),

    AuditQuestion(
        id="IAM-006",
        category=AuditCategory.IAM,
        question="Les rôles IAM sont-ils utilisés pour les applications EC2 au lieu de clés d'accès codées en dur?",
        description="Les applications sur EC2 doivent utiliser des rôles IAM via instance profiles.",
        severity=SeverityLevel.CRITICAL,
        aws_services=["IAM", "EC2"],
        compliance_frameworks=["CIS AWS Foundations", "SOC2"],
        remediation_steps=[
            "Créer un rôle IAM avec les permissions nécessaires",
            "Attacher le rôle aux instances EC2",
            "Supprimer les clés d'accès codées en dur du code"
        ],
        references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html"]
    ),

    AuditQuestion(
        id="IAM-007",
        category=AuditCategory.IAM,
        question="Les politiques de rotation de mots de passe sont-elles configurées?",
        description="Politique de mots de passe forte avec rotation régulière (90 jours recommandé).",
        severity=SeverityLevel.MEDIUM,
        aws_services=["IAM"],
        compliance_frameworks=["ISO 27001", "PCI-DSS", "HIPAA"],
        remediation_steps=[
            "Configurer la politique de mot de passe IAM",
            "Définir longueur minimale (14 caractères)",
            "Activer expiration à 90 jours"
        ],
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"]
    ),

    # ==================== NETWORK SECURITY ====================
    AuditQuestion(
        id="NET-001",
        category=AuditCategory.NETWORK,
        question="Les Security Groups suivent-ils le principe du moindre accès?",
        description="Aucun Security Group ne doit avoir 0.0.0.0/0 sur les ports sensibles (SSH, RDP, bases de données).",
        severity=SeverityLevel.CRITICAL,
        aws_services=["EC2", "VPC"],
        compliance_frameworks=["CIS AWS Foundations", "PCI-DSS"],
        remediation_steps=[
            "Auditer tous les Security Groups",
            "Restreindre 0.0.0.0/0 aux ports web uniquement (80, 443)",
            "Utiliser des plages IP spécifiques pour SSH/RDP"
        ],
        references=["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"]
    ),

    AuditQuestion(
        id="NET-002",
        category=AuditCategory.NETWORK,
        question="Le port SSH (22) est-il exposé à Internet (0.0.0.0/0)?",
        description="SSH ne doit jamais être accessible publiquement. Utiliser un bastion host ou VPN.",
        severity=SeverityLevel.CRITICAL,
        aws_services=["EC2", "VPC"],
        compliance_frameworks=["CIS AWS Foundations", "PCI-DSS", "SOC2"],
        remediation_steps=[
            "Identifier les SG avec SSH ouvert à 0.0.0.0/0",
            "Restreindre aux IPs du bureau/VPN",
            "Implémenter AWS Systems Manager Session Manager"
        ],
        references=["https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html"]
    ),

    AuditQuestion(
        id="NET-003",
        category=AuditCategory.NETWORK,
        question="Le port RDP (3389) est-il exposé à Internet (0.0.0.0/0)?",
        description="RDP ne doit jamais être accessible publiquement. Risque majeur de brute force.",
        severity=SeverityLevel.CRITICAL,
        aws_services=["EC2", "VPC"],
        compliance_frameworks=["CIS AWS Foundations", "PCI-DSS"],
        remediation_steps=[
            "Identifier les SG avec RDP ouvert à 0.0.0.0/0",
            "Utiliser AWS Systems Manager ou bastion Windows",
            "Activer Network Level Authentication"
        ],
        references=["https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/connecting_to_windows_instance.html"]
    ),

    AuditQuestion(
        id="NET-004",
        category=AuditCategory.NETWORK,
        question="Les VPC ont-ils des Flow Logs activés?",
        description="VPC Flow Logs permettent de monitorer le trafic réseau pour détecter des anomalies.",
        severity=SeverityLevel.HIGH,
        aws_services=["VPC", "CloudWatch"],
        compliance_frameworks=["PCI-DSS", "HIPAA", "SOC2"],
        remediation_steps=[
            "Activer Flow Logs pour chaque VPC",
            "Envoyer les logs vers CloudWatch ou S3",
            "Configurer des alarmes pour trafic suspect"
        ],
        references=["https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html"]
    ),

    AuditQuestion(
        id="NET-005",
        category=AuditCategory.NETWORK,
        question="Les bases de données sont-elles isolées dans des subnets privés?",
        description="RDS, DynamoDB doivent être dans des subnets sans route vers Internet Gateway.",
        severity=SeverityLevel.CRITICAL,
        aws_services=["RDS", "VPC", "DynamoDB"],
        compliance_frameworks=["PCI-DSS", "HIPAA"],
        remediation_steps=[
            "Créer des subnets privés sans route IGW",
            "Déplacer les bases de données vers subnets privés",
            "Utiliser NAT Gateway si accès sortant nécessaire"
        ],
        references=["https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Scenario2.html"]
    ),

    AuditQuestion(
        id="NET-006",
        category=AuditCategory.NETWORK,
        question="Network ACLs sont-elles configurées en plus des Security Groups?",
        description="Defense in depth: utiliser NACLs comme couche supplémentaire de sécurité.",
        severity=SeverityLevel.MEDIUM,
        aws_services=["VPC"],
        compliance_frameworks=["ISO 27001", "SOC2"],
        remediation_steps=[
            "Configurer des NACLs pour les subnets sensibles",
            "Bloquer les ranges IP malveillants connus",
            "Implémenter des règles deny explicites"
        ],
        references=["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html"]
    ),

    AuditQuestion(
        id="NET-007",
        category=AuditCategory.NETWORK,
        question="AWS WAF est-il déployé devant les applications web publiques?",
        description="Protection contre OWASP Top 10, SQL injection, XSS, etc.",
        severity=SeverityLevel.HIGH,
        aws_services=["WAF", "CloudFront", "ALB"],
        compliance_frameworks=["PCI-DSS", "OWASP"],
        remediation_steps=[
            "Créer une Web ACL WAF",
            "Appliquer les managed rules AWS (Core, SQL injection)",
            "Attacher WAF à CloudFront ou ALB"
        ],
        references=["https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html"]
    ),

    # ==================== ENCRYPTION ====================
    AuditQuestion(
        id="ENC-001",
        category=AuditCategory.ENCRYPTION,
        question="Les buckets S3 ont-ils le chiffrement activé par défaut?",
        description="Tous les objets S3 doivent être chiffrés au repos (SSE-S3, SSE-KMS, ou SSE-C).",
        severity=SeverityLevel.CRITICAL,
        aws_services=["S3", "KMS"],
        compliance_frameworks=["PCI-DSS", "HIPAA", "GDPR"],
        remediation_steps=[
            "Activer Default Encryption sur tous les buckets",
            "Utiliser SSE-KMS pour contrôle d'accès granulaire",
            "Créer une politique S3 refusant PUT sans encryption header"
        ],
        references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html"]
    ),

    AuditQuestion(
        id="ENC-002",
        category=AuditCategory.ENCRYPTION,
        question="Les volumes EBS sont-ils chiffrés?",
        description="Tous les volumes EBS doivent être chiffrés, notamment ceux contenant des données sensibles.",
        severity=SeverityLevel.CRITICAL,
        aws_services=["EBS", "KMS"],
        compliance_frameworks=["PCI-DSS", "HIPAA", "GDPR"],
        remediation_steps=[
            "Activer le chiffrement EBS par défaut",
            "Auditer les volumes non chiffrés",
            "Créer des snapshots chiffrés et recréer les volumes"
        ],
        references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"]
    ),

    AuditQuestion(
        id="ENC-003",
        category=AuditCategory.ENCRYPTION,
        question="Les bases de données RDS utilisent-elles le chiffrement au repos?",
        description="Activer le chiffrement transparent (TDE) pour toutes les instances RDS.",
        severity=SeverityLevel.CRITICAL,
        aws_services=["RDS", "KMS"],
        compliance_frameworks=["PCI-DSS", "HIPAA"],
        remediation_steps=[
            "Activer encryption lors de la création RDS",
            "Pour instances existantes: créer snapshot chiffré puis restaurer",
            "Utiliser des clés KMS customer-managed"
        ],
        references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"]
    ),

    AuditQuestion(
        id="ENC-004",
        category=AuditCategory.ENCRYPTION,
        question="TLS/SSL est-il imposé pour toutes les communications client-serveur?",
        description="Forcer HTTPS pour CloudFront, ALB, API Gateway. Pas de HTTP non chiffré.",
        severity=SeverityLevel.HIGH,
        aws_services=["CloudFront", "ALB", "API Gateway"],
        compliance_frameworks=["PCI-DSS", "HIPAA", "GDPR"],
        remediation_steps=[
            "Configurer CloudFront pour rediriger HTTP vers HTTPS",
            "Créer des listeners HTTPS uniquement sur ALB",
            "Désactiver les versions TLS < 1.2"
        ],
        references=["https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html"]
    ),

    AuditQuestion(
        id="ENC-005",
        category=AuditCategory.ENCRYPTION,
        question="Les clés KMS ont-elles une rotation automatique activée?",
        description="Rotation annuelle automatique des clés KMS customer-managed.",
        severity=SeverityLevel.MEDIUM,
        aws_services=["KMS"],
        compliance_frameworks=["ISO 27001", "SOC2"],
        remediation_steps=[
            "Activer automatic key rotation dans KMS",
            "Documenter la politique de rotation",
            "Monitorer l'utilisation des anciennes clés"
        ],
        references=["https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html"]
    ),

    AuditQuestion(
        id="ENC-006",
        category=AuditCategory.ENCRYPTION,
        question="Les snapshots RDS et EBS sont-ils chiffrés?",
        description="Les snapshots doivent hériter du chiffrement ou être explicitement chiffrés.",
        severity=SeverityLevel.HIGH,
        aws_services=["RDS", "EBS", "KMS"],
        compliance_frameworks=["PCI-DSS", "HIPAA"],
        remediation_steps=[
            "Vérifier l'encryption status des snapshots",
            "Copier les snapshots non chiffrés avec encryption",
            "Supprimer les snapshots non chiffrés"
        ],
        references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSSnapshots.html#encryption-support"]
    ),

    # ==================== LOGGING & MONITORING ====================
    AuditQuestion(
        id="LOG-001",
        category=AuditCategory.LOGGING,
        question="CloudTrail est-il activé dans toutes les régions?",
        description="CloudTrail doit logger toutes les actions API AWS pour audit et forensics.",
        severity=SeverityLevel.CRITICAL,
        aws_services=["CloudTrail", "S3"],
        compliance_frameworks=["PCI-DSS", "HIPAA", "SOC2", "ISO 27001"],
        remediation_steps=[
            "Créer un trail multi-région",
            "Activer log file validation",
            "Chiffrer les logs avec KMS",
            "Envoyer vers un bucket S3 dédié"
        ],
        references=["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html"]
    ),

    AuditQuestion(
        id="LOG-002",
        category=AuditCategory.LOGGING,
        question="Les logs CloudTrail sont-ils protégés contre la suppression/modification?",
        description="Bucket S3 CloudTrail doit avoir MFA Delete et Object Lock.",
        severity=SeverityLevel.CRITICAL,
        aws_services=["CloudTrail", "S3"],
        compliance_frameworks=["PCI-DSS", "SOC2"],
        remediation_steps=[
            "Activer MFA Delete sur le bucket CloudTrail",
            "Configurer S3 Object Lock (Compliance mode)",
            "Restreindre les permissions de suppression"
        ],
        references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html"]
    ),

    AuditQuestion(
        id="LOG-003",
        category=AuditCategory.LOGGING,
        question="AWS Config est-il activé pour tracker les changements de configuration?",
        description="AWS Config enregistre l'historique des configurations pour compliance et troubleshooting.",
        severity=SeverityLevel.HIGH,
        aws_services=["Config"],
        compliance_frameworks=["PCI-DSS", "HIPAA", "SOC2"],
        remediation_steps=[
            "Activer AWS Config dans toutes les régions",
            "Enregistrer tous les types de ressources",
            "Configurer des Config Rules pour compliance"
        ],
        references=["https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html"]
    ),

    AuditQuestion(
        id="LOG-004",
        category=AuditCategory.LOGGING,
        question="Des alarmes CloudWatch sont-elles configurées pour les événements de sécurité critiques?",
        description="Alertes pour: tentatives de connexion root, changements IAM, modifications Security Groups, etc.",
        severity=SeverityLevel.HIGH,
        aws_services=["CloudWatch", "SNS"],
        compliance_frameworks=["CIS AWS Foundations", "SOC2"],
        remediation_steps=[
            "Créer des metric filters sur CloudTrail logs",
            "Configurer des alarmes CloudWatch",
            "Envoyer notifications via SNS/Email/Slack"
        ],
        references=["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html"]
    ),

    AuditQuestion(
        id="LOG-005",
        category=AuditCategory.LOGGING,
        question="Les logs d'applications sont-ils centralisés et analysés?",
        description="Utiliser CloudWatch Logs ou solution SIEM pour agréger et analyser les logs.",
        severity=SeverityLevel.MEDIUM,
        aws_services=["CloudWatch", "CloudWatch Logs"],
        compliance_frameworks=["ISO 27001", "SOC2"],
        remediation_steps=[
            "Installer CloudWatch Agent sur EC2",
            "Centraliser logs dans CloudWatch Logs",
            "Configurer retention et archivage S3"
        ],
        references=["https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/WhatIsCloudWatchLogs.html"]
    ),

    AuditQuestion(
        id="LOG-006",
        category=AuditCategory.LOGGING,
        question="GuardDuty est-il activé pour la détection des menaces?",
        description="GuardDuty analyse CloudTrail, VPC Flow Logs, et DNS logs pour détecter les menaces.",
        severity=SeverityLevel.HIGH,
        aws_services=["GuardDuty"],
        compliance_frameworks=["PCI-DSS", "ISO 27001"],
        remediation_steps=[
            "Activer GuardDuty dans toutes les régions",
            "Configurer notifications SNS pour findings",
            "Intégrer avec Security Hub"
        ],
        references=["https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html"]
    ),

    # ==================== COMPLIANCE & GOVERNANCE ====================
    AuditQuestion(
        id="COM-001",
        category=AuditCategory.COMPLIANCE,
        question="Les ressources AWS sont-elles correctement taguées?",
        description="Tags obligatoires: Environment, Owner, CostCenter, Project, Compliance.",
        severity=SeverityLevel.MEDIUM,
        aws_services=["Resource Groups", "Tag Editor"],
        compliance_frameworks=["ISO 27001", "SOC2"],
        remediation_steps=[
            "Définir une stratégie de tagging",
            "Utiliser AWS Tag Policies (Organizations)",
            "Auditer les ressources non taguées régulièrement"
        ],
        references=["https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html"]
    ),

    AuditQuestion(
        id="COM-002",
        category=AuditCategory.COMPLIANCE,
        question="AWS Organizations est-il utilisé pour gérer plusieurs comptes?",
        description="Isoler production/dev/test dans des comptes séparés avec SCPs.",
        severity=SeverityLevel.HIGH,
        aws_services=["Organizations"],
        compliance_frameworks=["ISO 27001", "SOC2", "CIS AWS Foundations"],
        remediation_steps=[
            "Créer une organization AWS",
            "Structurer en OUs (Prod, Dev, Test, Security)",
            "Appliquer des Service Control Policies"
        ],
        references=["https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html"]
    ),

    AuditQuestion(
        id="COM-003",
        category=AuditCategory.COMPLIANCE,
        question="Service Control Policies (SCPs) sont-elles utilisées pour limiter les actions?",
        description="SCPs doivent empêcher la désactivation de CloudTrail, GuardDuty, Config.",
        severity=SeverityLevel.HIGH,
        aws_services=["Organizations"],
        compliance_frameworks=["CIS AWS Foundations", "SOC2"],
        remediation_steps=[
            "Créer SCPs pour protéger les services de sécurité",
            "Empêcher la création de ressources dans régions non autorisées",
            "Bloquer la désactivation du chiffrement"
        ],
        references=["https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html"]
    ),

    AuditQuestion(
        id="COM-004",
        category=AuditCategory.COMPLIANCE,
        question="AWS Security Hub est-il activé pour une vue centralisée de la sécurité?",
        description="Security Hub agrège les findings de GuardDuty, Inspector, Macie, etc.",
        severity=SeverityLevel.HIGH,
        aws_services=["Security Hub"],
        compliance_frameworks=["ISO 27001", "SOC2", "PCI-DSS"],
        remediation_steps=[
            "Activer Security Hub",
            "Activer les standards (CIS, PCI-DSS, AWS Best Practices)",
            "Intégrer avec GuardDuty, Config, Macie"
        ],
        references=["https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html"]
    ),

    AuditQuestion(
        id="COM-005",
        category=AuditCategory.COMPLIANCE,
        question="Des backups réguliers sont-ils configurés avec AWS Backup?",
        description="Stratégie de backup automatique pour RDS, EBS, EFS, DynamoDB.",
        severity=SeverityLevel.HIGH,
        aws_services=["AWS Backup"],
        compliance_frameworks=["ISO 27001", "SOC2", "GDPR"],
        remediation_steps=[
            "Créer un Backup Plan dans AWS Backup",
            "Définir fréquence et rétention",
            "Tester la restauration régulièrement"
        ],
        references=["https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html"]
    ),

    # ==================== STORAGE SECURITY ====================
    AuditQuestion(
        id="STO-001",
        category=AuditCategory.STORAGE,
        question="Les buckets S3 bloquent-ils l'accès public par défaut?",
        description="Activer Block Public Access au niveau compte et bucket.",
        severity=SeverityLevel.CRITICAL,
        aws_services=["S3"],
        compliance_frameworks=["CIS AWS Foundations", "GDPR"],
        remediation_steps=[
            "Activer Block Public Access au niveau compte",
            "Auditer tous les buckets publics",
            "Utiliser CloudFront pour servir du contenu public"
        ],
        references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"]
    ),

    AuditQuestion(
        id="STO-002",
        category=AuditCategory.STORAGE,
        question="Les buckets S3 ont-ils la journalisation d'accès activée?",
        description="S3 Access Logs pour tracer toutes les requêtes (GET, PUT, DELETE).",
        severity=SeverityLevel.MEDIUM,
        aws_services=["S3"],
        compliance_frameworks=["PCI-DSS", "HIPAA"],
        remediation_steps=[
            "Activer Server Access Logging",
            "Créer un bucket dédié pour les logs",
            "Configurer lifecycle pour archiver/supprimer"
        ],
        references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html"]
    ),

    AuditQuestion(
        id="STO-003",
        category=AuditCategory.STORAGE,
        question="S3 Versioning est-il activé pour les données critiques?",
        description="Protection contre suppressions accidentelles et ransomware.",
        severity=SeverityLevel.HIGH,
        aws_services=["S3"],
        compliance_frameworks=["ISO 27001", "SOC2"],
        remediation_steps=[
            "Activer Versioning sur buckets critiques",
            "Configurer MFA Delete",
            "Définir lifecycle pour gérer les versions anciennes"
        ],
        references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"]
    ),

    AuditQuestion(
        id="STO-004",
        category=AuditCategory.STORAGE,
        question="Les politiques de bucket S3 sont-elles restrictives?",
        description="Pas de Principal: '*' sans conditions strictes. Utiliser IAM policies quand possible.",
        severity=SeverityLevel.HIGH,
        aws_services=["S3", "IAM"],
        compliance_frameworks=["CIS AWS Foundations"],
        remediation_steps=[
            "Auditer toutes les bucket policies",
            "Remplacer Principal:* par des rôles/utilisateurs spécifiques",
            "Ajouter des conditions (IP, VPC endpoint)"
        ],
        references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html"]
    ),

    # ==================== DATABASE SECURITY ====================
    AuditQuestion(
        id="DB-001",
        category=AuditCategory.DATABASE,
        question="Les bases RDS sont-elles accessibles uniquement depuis le VPC?",
        description="Publicly Accessible doit être 'No' pour toutes les instances RDS.",
        severity=SeverityLevel.CRITICAL,
        aws_services=["RDS", "VPC"],
        compliance_frameworks=["PCI-DSS", "HIPAA"],
        remediation_steps=[
            "Modifier l'instance RDS pour désactiver Public Access",
            "Placer dans subnet privé",
            "Utiliser VPN ou bastion pour accès administratif"
        ],
        references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_CommonTasks.Connect.html"]
    ),

    AuditQuestion(
        id="DB-002",
        category=AuditCategory.DATABASE,
        question="Les backups automatiques RDS sont-ils activés avec rétention adéquate?",
        description="Backup retention minimum 7 jours, idéalement 30 jours.",
        severity=SeverityLevel.HIGH,
        aws_services=["RDS"],
        compliance_frameworks=["ISO 27001", "SOC2"],
        remediation_steps=[
            "Activer automated backups",
            "Configurer retention à 30 jours",
            "Tester la restauration des backups"
        ],
        references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html"]
    ),

    AuditQuestion(
        id="DB-003",
        category=AuditCategory.DATABASE,
        question="Les logs de base de données sont-ils exportés vers CloudWatch?",
        description="Activer export des logs (error, slow query, audit) vers CloudWatch.",
        severity=SeverityLevel.MEDIUM,
        aws_services=["RDS", "CloudWatch"],
        compliance_frameworks=["PCI-DSS", "HIPAA"],
        remediation_steps=[
            "Activer CloudWatch Logs export",
            "Configurer retention",
            "Créer des alarmes pour erreurs critiques"
        ],
        references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.html"]
    ),

    AuditQuestion(
        id="DB-004",
        category=AuditCategory.DATABASE,
        question="DynamoDB tables utilisent-elles le chiffrement au repos?",
        description="Encryption at rest avec AWS KMS pour toutes les tables DynamoDB.",
        severity=SeverityLevel.HIGH,
        aws_services=["DynamoDB", "KMS"],
        compliance_frameworks=["PCI-DSS", "HIPAA", "GDPR"],
        remediation_steps=[
            "Activer encryption lors création table",
            "Pour tables existantes: backup puis recréer avec encryption",
            "Utiliser customer-managed KMS keys"
        ],
        references=["https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html"]
    ),

    AuditQuestion(
        id="DB-005",
        category=AuditCategory.DATABASE,
        question="Point-in-time recovery est-il activé pour DynamoDB?",
        description="Protection contre corruptions de données et suppressions accidentelles.",
        severity=SeverityLevel.MEDIUM,
        aws_services=["DynamoDB"],
        compliance_frameworks=["ISO 27001", "SOC2"],
        remediation_steps=[
            "Activer Point-in-Time Recovery",
            "Documenter la procédure de restauration",
            "Tester la restauration"
        ],
        references=["https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html"]
    ),

    # ==================== APPLICATION SECURITY ====================
    AuditQuestion(
        id="APP-001",
        category=AuditCategory.APPLICATION,
        question="Les fonctions Lambda ont-elles des rôles IAM dédiés avec permissions minimales?",
        description="Une fonction = un rôle IAM avec uniquement les permissions nécessaires.",
        severity=SeverityLevel.HIGH,
        aws_services=["Lambda", "IAM"],
        compliance_frameworks=["CIS AWS Foundations", "SOC2"],
        remediation_steps=[
            "Créer un rôle IAM par fonction Lambda",
            "Éviter les managed policies trop larges",
            "Utiliser des policies inline spécifiques"
        ],
        references=["https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html"]
    ),

    AuditQuestion(
        id="APP-002",
        category=AuditCategory.APPLICATION,
        question="Les variables d'environnement Lambda contenant des secrets sont-elles chiffrées?",
        description="Utiliser AWS Secrets Manager ou Parameter Store au lieu de variables env en clair.",
        severity=SeverityLevel.CRITICAL,
        aws_services=["Lambda", "Secrets Manager", "Systems Manager"],
        compliance_frameworks=["PCI-DSS", "HIPAA"],
        remediation_steps=[
            "Migrer les secrets vers Secrets Manager",
            "Utiliser le SDK AWS pour récupérer les secrets",
            "Activer encryption at rest pour env vars restantes"
        ],
        references=["https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html"]
    ),

    AuditQuestion(
        id="APP-003",
        category=AuditCategory.APPLICATION,
        question="API Gateway utilise-t-il des mécanismes d'authentification/autorisation?",
        description="IAM, Cognito User Pools, ou Lambda Authorizers pour sécuriser les APIs.",
        severity=SeverityLevel.CRITICAL,
        aws_services=["API Gateway", "Cognito", "Lambda"],
        compliance_frameworks=["OWASP API Security", "SOC2"],
        remediation_steps=[
            "Configurer un authorizer (Cognito ou Lambda)",
            "Activer API Keys pour rate limiting",
            "Implémenter OAuth 2.0 / JWT validation"
        ],
        references=["https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-to-api.html"]
    ),

    AuditQuestion(
        id="APP-004",
        category=AuditCategory.APPLICATION,
        question="Les logs API Gateway sont-ils activés et analysés?",
        description="Access logs et execution logs pour debugging et audit.",
        severity=SeverityLevel.MEDIUM,
        aws_services=["API Gateway", "CloudWatch"],
        compliance_frameworks=["PCI-DSS", "SOC2"],
        remediation_steps=[
            "Activer CloudWatch Logs pour API Gateway",
            "Configurer Access Logging avec format JSON",
            "Créer des alarmes pour erreurs 4xx/5xx"
        ],
        references=["https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html"]
    ),

    AuditQuestion(
        id="APP-005",
        category=AuditCategory.APPLICATION,
        question="Les images de conteneurs (ECR) sont-elles scannées pour vulnérabilités?",
        description="Scan automatique à chaque push dans ECR pour détecter CVEs.",
        severity=SeverityLevel.HIGH,
        aws_services=["ECR", "ECS", "EKS"],
        compliance_frameworks=["ISO 27001", "SOC2"],
        remediation_steps=[
            "Activer Image Scanning dans ECR",
            "Configurer scan on push",
            "Implémenter une politique: pas de deploy si vulnérabilités critiques"
        ],
        references=["https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html"]
    ),

    # ==================== INCIDENT RESPONSE ====================
    AuditQuestion(
        id="IR-001",
        category=AuditCategory.INCIDENT_RESPONSE,
        question="Un plan de réponse aux incidents est-il documenté et testé?",
        description="Procédures pour compte compromis, data breach, ransomware, etc.",
        severity=SeverityLevel.HIGH,
        aws_services=["Multiple"],
        compliance_frameworks=["ISO 27001", "SOC2", "GDPR"],
        remediation_steps=[
            "Documenter le plan de réponse aux incidents",
            "Définir les rôles et responsabilités",
            "Tester via des simulations (GameDays)"
        ],
        references=["https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/"]
    ),

    AuditQuestion(
        id="IR-002",
        category=AuditCategory.INCIDENT_RESPONSE,
        question="Des snapshots forensiques peuvent-ils être créés rapidement?",
        description="Procédure pour isoler et capturer l'état d'instances compromises.",
        severity=SeverityLevel.MEDIUM,
        aws_services=["EC2", "EBS"],
        compliance_frameworks=["ISO 27001", "SOC2"],
        remediation_steps=[
            "Créer des runbooks pour isolation d'instance",
            "Automatiser la création de snapshots EBS",
            "Tagger les ressources pour investigation"
        ],
        references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-creating-snapshot.html"]
    ),

    AuditQuestion(
        id="IR-003",
        category=AuditCategory.INCIDENT_RESPONSE,
        question="Les contacts de sécurité AWS sont-ils configurés?",
        description="Contacts pour notifications de sécurité AWS (abuse, vulnerabilities).",
        severity=SeverityLevel.MEDIUM,
        aws_services=["Account"],
        compliance_frameworks=["ISO 27001", "SOC2"],
        remediation_steps=[
            "Configurer Alternate Security Contacts",
            "Utiliser une DL d'équipe sécurité",
            "Tester la réception des notifications"
        ],
        references=["https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/manage-account-payment.html"]
    ),

    # ==================== COST OPTIMIZATION (Security perspective) ====================
    AuditQuestion(
        id="COST-001",
        category=AuditCategory.COST_OPTIMIZATION,
        question="Des budgets et alarmes sont-ils configurés pour détecter des activités anormales?",
        description="Spike de coûts peut indiquer minage de crypto ou ressources compromises.",
        severity=SeverityLevel.MEDIUM,
        aws_services=["Budgets", "Cost Explorer"],
        compliance_frameworks=["ISO 27001"],
        remediation_steps=[
            "Créer des budgets AWS avec alertes",
            "Configurer des alarmes pour augmentation > 20%",
            "Monitorer les services non autorisés"
        ],
        references=["https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html"]
    ),

    AuditQuestion(
        id="COST-002",
        category=AuditCategory.COST_OPTIMIZATION,
        question="Les ressources inutilisées sont-elles identifiées et supprimées?",
        description="Ressources orphelines = surface d'attaque inutile + coûts.",
        severity=SeverityLevel.LOW,
        aws_services=["Trusted Advisor", "Compute Optimizer"],
        compliance_frameworks=["ISO 27001"],
        remediation_steps=[
            "Utiliser AWS Trusted Advisor",
            "Identifier EBS, EIPs, snapshots non attachés",
            "Automatiser le nettoyage avec Lambda"
        ],
        references=["https://aws.amazon.com/premiumsupport/technology/trusted-advisor/"]
    ),
]


def get_all_questions() -> List[AuditQuestion]:
    """Retourne toutes les questions d'audit"""
    return AUDIT_QUESTIONS


def get_questions_by_category(category: AuditCategory) -> List[AuditQuestion]:
    """Filtre les questions par catégorie"""
    return [q for q in AUDIT_QUESTIONS if q.category == category]


def get_questions_by_severity(severity: SeverityLevel) -> List[AuditQuestion]:
    """Filtre les questions par niveau de sévérité"""
    return [q for q in AUDIT_QUESTIONS if q.severity == severity]


def get_questions_by_service(service: str) -> List[AuditQuestion]:
    """Filtre les questions par service AWS"""
    return [q for q in AUDIT_QUESTIONS if service in q.aws_services]


def get_questions_by_compliance(framework: str) -> List[AuditQuestion]:
    """Filtre les questions par framework de conformité"""
    return [q for q in AUDIT_QUESTIONS if framework in q.compliance_frameworks]


def get_category_info() -> List[Dict]:
    """Retourne les informations sur toutes les catégories"""
    return [
        {
            "category": AuditCategory.IAM,
            "name": "IAM - Identity and Access Management",
            "description": "Gestion des identités, permissions, et contrôles d'accès",
            "question_count": len(get_questions_by_category(AuditCategory.IAM))
        },
        {
            "category": AuditCategory.NETWORK,
            "name": "Network Security",
            "description": "Sécurité réseau, VPC, Security Groups, WAF",
            "question_count": len(get_questions_by_category(AuditCategory.NETWORK))
        },
        {
            "category": AuditCategory.ENCRYPTION,
            "name": "Encryption",
            "description": "Chiffrement des données au repos et en transit",
            "question_count": len(get_questions_by_category(AuditCategory.ENCRYPTION))
        },
        {
            "category": AuditCategory.LOGGING,
            "name": "Logging & Monitoring",
            "description": "Journalisation, surveillance, et détection des menaces",
            "question_count": len(get_questions_by_category(AuditCategory.LOGGING))
        },
        {
            "category": AuditCategory.COMPLIANCE,
            "name": "Compliance & Governance",
            "description": "Conformité réglementaire et gouvernance",
            "question_count": len(get_questions_by_category(AuditCategory.COMPLIANCE))
        },
        {
            "category": AuditCategory.STORAGE,
            "name": "Storage Security",
            "description": "Sécurité du stockage (S3, EBS, EFS)",
            "question_count": len(get_questions_by_category(AuditCategory.STORAGE))
        },
        {
            "category": AuditCategory.DATABASE,
            "name": "Database Security",
            "description": "Sécurité des bases de données (RDS, DynamoDB)",
            "question_count": len(get_questions_by_category(AuditCategory.DATABASE))
        },
        {
            "category": AuditCategory.APPLICATION,
            "name": "Application Security",
            "description": "Sécurité applicative (Lambda, API Gateway, Containers)",
            "question_count": len(get_questions_by_category(AuditCategory.APPLICATION))
        },
        {
            "category": AuditCategory.INCIDENT_RESPONSE,
            "name": "Incident Response",
            "description": "Préparation et réponse aux incidents de sécurité",
            "question_count": len(get_questions_by_category(AuditCategory.INCIDENT_RESPONSE))
        },
        {
            "category": AuditCategory.COST_OPTIMIZATION,
            "name": "Cost Optimization (Security)",
            "description": "Optimisation des coûts avec perspective sécurité",
            "question_count": len(get_questions_by_category(AuditCategory.COST_OPTIMIZATION))
        },
    ]
