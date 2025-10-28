"""
Base de données complète de questions techniques pour l'audit de sécurité AWS
Questions approfondies et techniques pour professionnels de la sécurité
"""

from typing import List, Dict
from pydantic import BaseModel


class Question(BaseModel):
    id: str
    question: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str
    compliance: List[str]
    technical_details: str
    remediation: List[str]
    verification_steps: List[str]
    references: List[str]


# ==================== IAM (Identity and Access Management) ====================
IAM_QUESTIONS = [
    Question(
        id="IAM-001",
        question="Politique de mot de passe IAM : complexité, expiration, historique et verrouillage configurés ?",
        description="Vérifier que la politique de mot de passe IAM respecte les standards de sécurité avec complexité minimale, rotation obligatoire, historique et verrouillage après tentatives échouées",
        severity="HIGH",
        category="IAM",
        compliance=["ISO 27001", "SOC2", "PCI-DSS", "NIST"],
        technical_details="""
        Configuration minimale requise:
        - Longueur minimale: 14 caractères (recommandé: 16+)
        - Complexité: majuscules, minuscules, chiffres, symboles
        - Expiration: 90 jours maximum
        - Historique: minimum 24 mots de passe
        - Prévention de réutilisation
        - Pas de mot de passe par défaut
        """,
        remediation=[
            "Accéder à IAM > Account Settings > Password Policy",
            "Configurer: Minimum length = 16 characters",
            "Activer: Require at least one uppercase letter",
            "Activer: Require at least one lowercase letter",
            "Activer: Require at least one number",
            "Activer: Require at least one non-alphanumeric character",
            "Configurer: Password expiration = 90 days",
            "Configurer: Password reuse prevention = 24",
            "Activer: Prevent password reuse"
        ],
        verification_steps=[
            "CLI: aws iam get-account-password-policy",
            "Vérifier MinimumPasswordLength >= 14",
            "Vérifier RequireSymbols = true",
            "Vérifier RequireNumbers = true",
            "Vérifier RequireUppercaseCharacters = true",
            "Vérifier RequireLowercaseCharacters = true",
            "Vérifier MaxPasswordAge <= 90",
            "Vérifier PasswordReusePrevention >= 24"
        ],
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html",
            "https://www.cisecurity.org/benchmark/amazon_web_services"
        ]
    ),

    Question(
        id="IAM-002",
        question="MFA obligatoire pour tous les utilisateurs privilégiés (root, admin, opérations) ?",
        description="Vérification que l'authentification multi-facteurs (MFA) est activée et obligatoire pour tous les comptes à privilèges, y compris root",
        severity="CRITICAL",
        category="IAM",
        compliance=["ISO 27001", "SOC2", "PCI-DSS", "HIPAA", "CIS Benchmark"],
        technical_details="""
        Types de MFA acceptables:
        - Hardware MFA: YubiKey, Gemalto
        - Virtual MFA: Google Authenticator, Authy, Microsoft Authenticator
        - U2F tokens

        Comptes concernés:
        - Root account (obligatoire)
        - IAM users avec AdministratorAccess
        - IAM users avec PowerUserAccess
        - Utilisateurs accédant à la console
        - Utilisateurs pouvant modifier les security groups
        - Utilisateurs pouvant gérer IAM
        """,
        remediation=[
            "Root account: IAM Dashboard > Security credentials > MFA > Activate MFA",
            "Créer une policy IAM conditionnelle exigeant MFA:",
            "  Deny all actions if aws:MultiFactorAuthPresent != true",
            "Appliquer la policy à tous les rôles/users privilégiés",
            "Automatiser la détection: AWS Config Rule 'iam-user-mfa-enabled'",
            "Implémenter un processus d'on-boarding avec MFA obligatoire",
            "Audit mensuel: aws iam get-credential-report | grep -v 'mfa_active.*true'"
        ],
        verification_steps=[
            "aws iam get-credential-report --query 'Content' --output text | base64 -d > report.csv",
            "grep -v 'mfa_active.*true' report.csv",
            "aws iam list-virtual-mfa-devices",
            "aws iam list-users | jq '.Users[].UserName' | xargs -I {} aws iam list-mfa-devices --user-name {}",
            "Vérifier que chaque utilisateur admin a un MFA device assigné"
        ],
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_users-self-manage-mfa-and-creds.html"
        ]
    ),

    Question(
        id="IAM-003",
        question="Principe du moindre privilège appliqué : IAM Access Analyzer, Access Advisor utilisés régulièrement ?",
        description="Audit des permissions IAM pour identifier et supprimer les privilèges excessifs en utilisant IAM Access Analyzer et Access Advisor",
        severity="HIGH",
        category="IAM",
        compliance=["ISO 27001", "SOC2", "NIST", "CIS Benchmark"],
        technical_details="""
        Méthodologie d'audit:
        1. IAM Access Analyzer: Identifie les ressources partagées en dehors de la zone de confiance
        2. Access Advisor: Montre les services auxquels un principal a accédé dans les 400 derniers jours
        3. Policy Simulator: Teste les permissions effectives
        4. CloudTrail: Analyse l'utilisation réelle des permissions

        Flags critiques:
        - Wildcard (*) dans Resource ou Action
        - AdministratorAccess ou PowerUserAccess attachés à des utilisateurs quotidiens
        - Permissions S3:* ou IAM:* sans conditions restrictives
        - Cross-account assume role sans External ID
        - Policies avec Effect: Allow sur sensitive actions sans conditions MFA
        """,
        remediation=[
            "Activer IAM Access Analyzer dans toutes les régions",
            "Créer un analyzer: aws accessanalyzer create-analyzer --analyzer-name org-analyzer --type ORGANIZATION",
            "Reviewer findings mensuellement: aws accessanalyzer list-findings",
            "Utiliser Access Advisor pour chaque role/user:",
            "  aws iam generate-service-last-accessed-details --arn <role-arn>",
            "  Attendre le rapport: aws iam get-service-last-accessed-details --job-id <id>",
            "Supprimer les permissions non utilisées depuis 90+ jours",
            "Remplacer les managed policies larges par des policies custom restrictives",
            "Implémenter IAM policy conditions (IpAddress, MFA, SourceVpc, etc.)",
            "Utiliser Permission Boundaries pour limiter l'escalade de privilèges"
        ],
        verification_steps=[
            "aws accessanalyzer list-analyzers",
            "aws accessanalyzer list-findings --analyzer-arn <arn> --filter '{\"status\":{\"eq\":[\"ACTIVE\"]}}'",
            "aws iam list-policies --scope Local --only-attached | jq '.Policies[] | select(.PolicyName | contains(\"*\"))'",
            "Script d'audit: Pour chaque role, vérifier last accessed > 90 jours",
            "Vérifier l'absence de inline policies sur les users (préférer group policies)"
        ],
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_access-advisor.html"
        ]
    ),

    Question(
        id="IAM-004",
        question="Rotation automatique des clés d'accès IAM : processus et durée maximale d'utilisation ?",
        description="Vérifier que les access keys sont rotées automatiquement et qu'aucune clé n'est utilisée au-delà de 90 jours",
        severity="CRITICAL",
        category="IAM",
        compliance=["PCI-DSS", "SOC2", "HIPAA", "CIS Benchmark"],
        technical_details="""
        Standards de rotation:
        - Rotation obligatoire: tous les 90 jours maximum
        - Rotation recommandée: tous les 30 jours
        - Clés root: doivent être supprimées (utiliser IAM roles)
        - Clés non utilisées depuis 30 jours: à désactiver
        - Clés non utilisées depuis 90 jours: à supprimer

        Processus de rotation sécurisé:
        1. Créer nouvelle access key
        2. Tester nouvelle clé dans environnement non-prod
        3. Mettre à jour applications/services
        4. Vérifier fonctionnement pendant 24-48h
        5. Désactiver ancienne clé (ne pas supprimer immédiatement)
        6. Monitorer les erreurs pendant 7 jours
        7. Supprimer ancienne clé si aucun problème
        """,
        remediation=[
            "Automatiser la détection de clés anciennes avec AWS Config:",
            "  Rule: access-keys-rotated (maxAccessKeyAge: 90)",
            "Créer un Lambda function pour rotation automatique:",
            "  1. Lister users: aws iam list-users",
            "  2. Pour chaque user: aws iam list-access-keys --user-name <user>",
            "  3. Check age: compare CreateDate avec current date",
            "  4. Si > 90 jours: envoyer alerte SNS",
            "Créer une policy SCP empêchant l'utilisation de clés > 90 jours",
            "Implémenter AWS Secrets Manager pour gérer les credentials",
            "Migrer vers IAM Roles pour EC2/Lambda (éliminer besoin de clés statiques)",
            "Documentation: créer runbook pour rotation manuelle en urgence"
        ],
        verification_steps=[
            "aws iam generate-credential-report",
            "aws iam get-credential-report --query 'Content' --output text | base64 -d > credentials.csv",
            "awk -F',' '$10 != \"N/A\" && $10 != \"false\" {print $1,$10}' credentials.csv",
            "aws iam list-access-keys --user-name <user>",
            "aws iam get-access-key-last-used --access-key-id <key>",
            "Calculer l'âge: (current_date - CreateDate) > 90 jours"
        ],
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
            "https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html"
        ]
    ),

    Question(
        id="IAM-005",
        question="Utilisation de rôles IAM au lieu de users pour applications et services EC2/Lambda/ECS ?",
        description="Vérifier que toutes les applications utilisent des IAM roles via instance profiles plutôt que des access keys hardcodées",
        severity="CRITICAL",
        category="IAM",
        compliance=["CIS Benchmark", "AWS Well-Architected", "SOC2"],
        technical_details="""
        Problèmes des access keys hardcodées:
        - Rotation complexe et risquée
        - Risque de leak dans code source / logs
        - Pas de rotation automatique
        - Difficile à révoquer en urgence
        - Pas de temporary credentials

        Avantages des IAM Roles:
        - Credentials temporaires (auto-renouvelés)
        - Pas de stockage de credentials
        - Révocation instantanée via policy update
        - Audit via AssumeRole CloudTrail events
        - Integration native avec EC2/Lambda/ECS

        Services devant TOUJOURS utiliser roles:
        - EC2 instances → Instance Profile
        - Lambda functions → Execution Role
        - ECS tasks → Task Role + Execution Role
        - EKS pods → IRSA (IAM Roles for Service Accounts)
        - CodeBuild/CodePipeline → Service Role
        """,
        remediation=[
            "Audit: Lister toutes les access keys:",
            "  aws iam list-users | jq -r '.Users[].UserName' | while read user; do aws iam list-access-keys --user-name $user; done",
            "Pour chaque application EC2:",
            "  1. Créer IAM role avec trust policy pour ec2.amazonaws.com",
            "  2. Attacher policies nécessaires au role",
            "  3. Créer instance profile: aws iam create-instance-profile",
            "  4. Associer role au profile: aws iam add-role-to-instance-profile",
            "  5. Attacher profile à l'instance: aws ec2 associate-iam-instance-profile",
            "  6. Modifier application pour utiliser SDK sans credentials (auto-détection)",
            "  7. Tester fonctionnement",
            "  8. Supprimer access keys de l'application",
            "Pour Lambda: Spécifier role dans la configuration de la fonction",
            "Pour ECS: Définir taskRoleArn dans task definition",
            "Pour EKS: Implémenter IRSA avec OIDC provider"
        ],
        verification_steps=[
            "EC2: aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,IamInstanceProfile.Arn]'",
            "Lambda: aws lambda list-functions --query 'Functions[].[FunctionName,Role]'",
            "ECS: aws ecs list-task-definitions | xargs -I {} aws ecs describe-task-definition --task-definition {}",
            "Chercher des hardcoded credentials dans le code:",
            "  git grep -i 'AKIA' (format des access keys)",
            "  git grep -i 'aws_access_key_id'",
            "CloudTrail: Rechercher GetSessionToken, GetFederationToken events"
        ],
        references=[
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html",
            "https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html"
        ]
    ),

    Question(
        id="IAM-006",
        question="Session duration et policies pour AssumeRole : durée minimale, External ID, conditions MFA ?",
        description="Vérifier la configuration sécurisée des trust policies pour les rôles avec assume role, notamment durée de session, External ID pour cross-account, et conditions",
        severity="HIGH",
        category="IAM",
        compliance=["CIS Benchmark", "SOC2", "AWS Well-Architected"],
        technical_details="""
        Configurations critiques AssumeRole:

        1. Session Duration:
           - Maximum: 12 heures
           - Recommandé: 1 heure pour rôles admin
           - Minimum: 15 minutes (pour certains use cases)

        2. Trust Policy Conditions:
           - aws:MultiFactorAuthPresent: true (pour rôles sensibles)
           - aws:SourceAccount: <account-id> (cross-account)
           - sts:ExternalId: <random-string> (contre confused deputy)
           - aws:SourceIp: <CIDR> (restriction IP)
           - aws:SecureTransport: true (force HTTPS)

        3. External ID (cross-account critical):
           - Unique par customer/partner
           - Minimum 32 caractères aléatoires
           - Jamais réutilisé
           - Stocké de manière sécurisée

        4. Permissions Boundaries:
           - Limite maximale des permissions
           - Empêche l'escalade de privilèges
        """,
        remediation=[
            "Audit des rôles avec AssumeRole trust policy:",
            "  aws iam list-roles | jq -r '.Roles[].RoleName' | while read role; do",
            "    aws iam get-role --role-name $role --query 'Role.AssumeRolePolicyDocument'",
            "  done",
            "Pour chaque rôle, vérifier:",
            "  1. MaxSessionDuration <= 3600 (1h) pour rôles admin",
            "  2. Présence de conditions dans trust policy",
            "  3. External ID pour tous les cross-account assumes",
            "  4. MFA requis pour rôles sensibles",
            "Exemple trust policy sécurisée:",
            "{",
            "  \"Version\": \"2012-10-17\",",
            "  \"Statement\": [{",
            "    \"Effect\": \"Allow\",",
            "    \"Principal\": {\"AWS\": \"arn:aws:iam::ACCOUNT:root\"},",
            "    \"Action\": \"sts:AssumeRole\",",
            "    \"Condition\": {",
            "      \"StringEquals\": {\"sts:ExternalId\": \"RANDOM-32-CHARS\"},",
            "      \"Bool\": {\"aws:MultiFactorAuthPresent\": \"true\"},",
            "      \"IpAddress\": {\"aws:SourceIp\": \"203.0.113.0/24\"}",
            "    }",
            "  }]",
            "}",
            "Générer External ID: openssl rand -hex 32"
        ],
        verification_steps=[
            "aws iam get-role --role-name <role> --query 'Role.MaxSessionDuration'",
            "aws iam get-role --role-name <role> --query 'Role.AssumeRolePolicyDocument' | jq '.Statement[].Condition'",
            "Vérifier présence External ID pour cross-account:",
            "  jq '.Statement[].Condition.StringEquals.\"sts:ExternalId\"'",
            "Vérifier MFA condition:",
            "  jq '.Statement[].Condition.Bool.\"aws:MultiFactorAuthPresent\"'",
            "CloudTrail: aws logs filter-pattern AssumeRole --log-group-name CloudTrail/DefaultLogGroup"
        ],
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html"
        ]
    ),

    Question(
        id="IAM-007",
        question="Service Control Policies (SCPs) : protection contre désactivation de services de sécurité ?",
        description="Vérifier que des SCPs sont en place au niveau AWS Organizations pour empêcher la désactivation de CloudTrail, GuardDuty, Config, etc.",
        severity="CRITICAL",
        category="IAM",
        compliance=["CIS Benchmark", "SOC2", "AWS Well-Architected"],
        technical_details="""
        SCPs critiques à implémenter:

        1. Protection des services de sécurité:
           - Deny cloudtrail:StopLogging
           - Deny cloudtrail:DeleteTrail
           - Deny guardduty:DeleteDetector
           - Deny guardduty:DisassociateFromMasterAccount
           - Deny config:DeleteConfigurationRecorder
           - Deny config:StopConfigurationRecorder

        2. Protection contre exfiltration:
           - Deny actions hors régions autorisées
           - Deny s3:PutBucketPolicy avec Principal: "*"
           - Deny création de VPC peering non autorisé

        3. Compliance obligatoire:
           - Deny suppression de tags obligatoires
           - Require encryption pour S3/EBS
           - Deny création d'instances sans IMDSv2
        """,
        remediation=[
            "Créer SCP de protection sécurité:",
            "{",
            "  \"Version\": \"2012-10-17\",",
            "  \"Statement\": [",
            "    {",
            "      \"Effect\": \"Deny\",",
            "      \"Action\": [",
            "        \"cloudtrail:StopLogging\",",
            "        \"cloudtrail:DeleteTrail\",",
            "        \"cloudtrail:UpdateTrail\",",
            "        \"guardduty:DeleteDetector\",",
            "        \"guardduty:DisassociateFromMasterAccount\",",
            "        \"config:DeleteConfigurationRecorder\",",
            "        \"config:DeleteDeliveryChannel\",",
            "        \"config:StopConfigurationRecorder\"",
            "      ],",
            "      \"Resource\": \"*\"",
            "    }",
            "  ]",
            "}",
            "Appliquer au niveau Organization ou OU:",
            "  aws organizations attach-policy --policy-id <id> --target-id <ou-id>",
            "Tester l'effet avec Policy Simulator avant application",
            "Documenter les exceptions nécessaires (break-glass procedures)"
        ],
        verification_steps=[
            "aws organizations list-policies --filter SERVICE_CONTROL_POLICY",
            "aws organizations describe-policy --policy-id <id>",
            "aws organizations list-targets-for-policy --policy-id <id>",
            "Tester avec un compte test:",
            "  aws cloudtrail stop-logging --name <trail> (devrait être Deny)",
            "Vérifier les deny statements couvrent tous les services critiques"
        ],
        references=[
            "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html",
            "https://github.com/aws-samples/aws-security-reference-architecture-examples"
        ]
    )
]

# ==================== VPC (Virtual Private Cloud) ====================
VPC_QUESTIONS = [
    Question(
        id="VPC-001",
        question="Architecture VPC : isolation réseau entre environnements (prod/dev/test) et tiers applicatifs ?",
        description="Vérifier que l'architecture VPC implémente une séparation réseau stricte avec des VPC dédiés ou des subnets isolés par environnement",
        severity="CRITICAL",
        category="VPC",
        compliance=["CIS Benchmark", "PCI-DSS", "ISO 27001"],
        technical_details="""
        Modèles d'architecture recommandés:

        1. Multi-VPC (recommandé pour isolation forte):
           - VPC Production (compte AWS dédié)
           - VPC Staging (compte AWS dédié)
           - VPC Development (compte AWS dédié)
           - VPC Shared Services (Transit Gateway hub)

        2. Single VPC avec subnets isolés:
           - Subnets Public (DMZ): ALB, NAT Gateway, Bastion
           - Subnets Private Application: EC2, ECS, Lambda
           - Subnets Private Database: RDS, ElastiCache, Redshift
           - Subnets Management: Monitoring, Logging tools

        3. Tiers applicatifs (defense in depth):
           - Tier 1 - Web/Load Balancers (public subnets)
           - Tier 2 - Application servers (private subnets)
           - Tier 3 - Databases (isolated private subnets)
           - Tier 4 - Management (bastion/VPN)

        Principes de sécurité:
        - Aucune communication directe Internet pour tiers applicatif/base
        - NACLs restrictives entre tiers
        - Route tables séparées par tier
        - Flow Logs activés sur tous les subnets
        """,
        remediation=[
            "Audit architecture existante:",
            "  aws ec2 describe-vpcs --query 'Vpcs[].[VpcId,Tags[?Key==`Environment`].Value]'",
            "  aws ec2 describe-subnets --query 'Subnets[].[SubnetId,VpcId,Tags[?Key==`Tier`].Value,MapPublicIpOnLaunch]'",
            "Pour multi-VPC avec Transit Gateway:",
            "  1. Créer Transit Gateway dans compte réseau central",
            "  2. Attacher VPCs avec TGW attachments",
            "  3. Créer route tables TGW avec routage inter-VPC contrôlé",
            "  4. Implémenter inspection centralisée (Network Firewall)",
            "Pour single VPC:",
            "  1. Créer subnets par tier et AZ",
            "  2. Route tables dédiées par tier",
            "  3. NACLs avec deny explicite inter-tier (sauf flux autorisés)",
            "  4. Security Groups avec principe du moindre privilège",
            "Exemple NACL restrictive tier DB:",
            "  Inbound: Allow port 3306 from App subnet CIDR only",
            "  Outbound: Deny all sauf responses",
            "Documenter architecture dans diagrammes (draw.io, CloudCraft)"
        ],
        verification_steps=[
            "aws ec2 describe-vpcs --output table",
            "aws ec2 describe-subnets --filters Name=vpc-id,Values=<vpc-id> --query 'Subnets[].[SubnetId,CidrBlock,MapPublicIpOnLaunch,AvailabilityZone]'",
            "aws ec2 describe-route-tables --filters Name=vpc-id,Values=<vpc-id>",
            "aws ec2 describe-network-acls --filters Name=vpc-id,Values=<vpc-id>",
            "Vérifier aucun subnet DB n'a de route vers Internet Gateway",
            "Vérifier MapPublicIpOnLaunch = false pour subnets privés",
            "Tracer un flux réseau du LB au DB et vérifier les contrôles à chaque hop"
        ],
        references=[
            "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Scenario2.html",
            "https://aws.amazon.com/architecture/well-architected/"
        ]
    ),

    Question(
        id="VPC-002",
        question="Security Groups : règles minimales, pas de 0.0.0.0/0 sur ports sensibles, documentation ?",
        description="Audit complet des Security Groups pour identifier les règles permissives (0.0.0.0/0) sur des ports autres que HTTP/HTTPS, et vérifier la documentation des flux",
        severity="CRITICAL",
        category="VPC",
        compliance=["CIS Benchmark", "PCI-DSS", "SOC2"],
        technical_details="""
        Règles critiques à auditer:

        Ports JAMAIS exposés à 0.0.0.0/0:
        - 22 (SSH)
        - 3389 (RDP)
        - 3306 (MySQL)
        - 5432 (PostgreSQL)
        - 27017 (MongoDB)
        - 6379 (Redis)
        - 9200-9300 (Elasticsearch)
        - 1433 (SQL Server)
        - 5984 (CouchDB)
        - 11211 (Memcached)

        Ports acceptables publics (avec précautions):
        - 80 (HTTP) → Rediriger vers 443
        - 443 (HTTPS) → Avec WAF/CloudFront

        Best practices SG:
        - Nommer de manière descriptive (sg-web-tier-prod)
        - Ajouter Description à chaque règle
        - Référencer d'autres SG plutôt que des CIDR (micro-segmentation)
        - Règles sortantes restrictives (pas de 0.0.0.0/0 all)
        - Tagging avec Owner, Application, Environment
        - Révision trimestrielle des règles
        """,
        remediation=[
            "Script d'audit des SG dangereux:",
            "aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`] && (FromPort!=`80` && FromPort!=`443`)]].[GroupId,GroupName,IpPermissions]'",
            "Pour chaque SG problématique:",
            "  1. Identifier les instances/ressources utilisant ce SG",
            "  2. Comprendre le flux métier nécessaire",
            "  3. Remplacer 0.0.0.0/0 par:",
            "     - IP ranges spécifiques du bureau/VPN",
            "     - Security Group IDs sources",
            "     - Prefix Lists (pour services AWS)",
            "  4. Tester connectivité après modification",
            "  5. Monitorer VPC Flow Logs pour rejects",
            "Pour SSH/RDP:",
            "  - Utiliser AWS Systems Manager Session Manager (pas de SG rules)",
            "  - Ou Bastion host dans subnet public avec IP restreinte",
            "  - Ou AWS Client VPN / Site-to-Site VPN",
            "Automatiser monitoring:",
            "  AWS Config Rule: restricted-ssh (détecte 0.0.0.0/0 sur port 22)",
            "  AWS Config Rule: restricted-common-ports",
            "  Security Hub: contrôles automatiques CIS"
        ],
        verification_steps=[
            "aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values='0.0.0.0/0'",
            "Pour chaque SG, vérifier:",
            "  aws ec2 describe-security-groups --group-ids <sg-id> --query 'SecurityGroups[].IpPermissions[].[FromPort,ToPort,IpRanges[].CidrIp]'",
            "Lister ressources par SG:",
            "  aws ec2 describe-instances --filters Name=instance.group-id,Values=<sg-id> --query 'Reservations[].Instances[].[InstanceId,Tags[?Key==`Name`].Value]'",
            "  aws rds describe-db-instances --query 'DBInstances[?VpcSecurityGroups[?VpcSecurityGroupId==`<sg-id>`]].[DBInstanceIdentifier]'",
            "  aws elbv2 describe-load-balancers --query 'LoadBalancers[?SecurityGroups[?contains(@,`<sg-id>`)]].[LoadBalancerName]'",
            "Générer rapport Excel avec tous les SG et leurs règles pour review"
        ],
        references=[
            "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html",
            "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html"
        ]
    ),

    Question(
        id="VPC-003",
        question="VPC Flow Logs : activés sur tous les VPCs/subnets, rétention adéquate, analysés régulièrement ?",
        description="Vérifier que VPC Flow Logs capture tout le trafic réseau avec rétention suffisante et que les logs sont analysés pour détecter anomalies",
        severity="HIGH",
        category="VPC",
        compliance=["PCI-DSS", "HIPAA", "SOC2", "ISO 27001"],
        technical_details="""
        Configuration Flow Logs recommandée:

        1. Scope:
           - ALL VPCs (niveau VPC pour global)
           - Subnets critiques (niveau subnet pour détail)
           - ENIs spécifiques (troubleshooting)

        2. Traffic Type:
           - ACCEPT: trafic autorisé (baseline normal)
           - REJECT: trafic bloqué (tentatives suspectes)
           - ALL: recommandé (vue complète)

        3. Destination:
           - CloudWatch Logs (analyse temps-réel, alertes)
           - S3 (long-terme, analyse batch, compliance)
           - Partition Hive pour requêtes Athena performantes

        4. Format:
           - Default format (minimum)
           - Custom format (inclure vpc-id, subnet-id, instance-id, tcp-flags)

        5. Rétention:
           - CloudWatch: 90 jours minimum
           - S3: 1-7 ans selon compliance (avec lifecycle vers Glacier)

        Use cases critiques:
        - Détection d'exfiltration (connexions inhabituelles sortantes)
        - Scans de ports (nombreux REJECTs sur ports variés)
        - Lateral movement (connexions inter-instances inhabituelles)
        - DDoS / flood (volume anormal de connexions)
        - Compliance (preuve de logging réseau)
        """,
        remediation=[
            "Vérifier Flow Logs existants:",
            "  aws ec2 describe-flow-logs",
            "Activer Flow Logs niveau VPC:",
            "  aws ec2 create-flow-logs \\",
            "    --resource-type VPC \\",
            "    --resource-ids <vpc-id> \\",
            "    --traffic-type ALL \\",
            "    --log-destination-type s3 \\",
            "    --log-destination arn:aws:s3:::<bucket>/vpc-flow-logs/ \\",
            "    --log-format '${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${subnet-id} ${instance-id} ${tcp-flags} ${type} ${pkt-srcaddr} ${pkt-dstaddr}'",
            "Créer bucket S3 avec:",
            "  - Versioning activé",
            "  - Lifecycle: transition vers Glacier après 90j",
            "  - Bucket policy limitant accès (uniquement VPC Flow Logs service)",
            "  - Encryption SSE-S3 ou SSE-KMS",
            "Configurer Athena pour requêtes:",
            "  CREATE EXTERNAL TABLE vpc_flow_logs (...) PARTITIONED BY (dt string) LOCATION 's3://bucket/vpc-flow-logs/'",
            "Créer CloudWatch Metric Filters:",
            "  - SSH rejects: [version, account, eni, source, dest, srcport=\"22\", destport, protocol, packets, bytes, windowstart, windowend, action=\"REJECT\", flowlogstatus]",
            "  - RDP rejects: même avec destport=\"3389\"",
            "Alarmes SNS sur métriques anormales"
        ],
        verification_steps=[
            "aws ec2 describe-vpcs --query 'Vpcs[].VpcId' | xargs -I {} aws ec2 describe-flow-logs --filter Name=resource-id,Values={}",
            "Vérifier TrafficType = ALL",
            "Vérifier LogDestinationType (s3 ou cloud-watch-logs)",
            "Pour S3: vérifier présence de fichiers récents:",
            "  aws s3 ls s3://<bucket>/vpc-flow-logs/ --recursive | tail",
            "Pour CloudWatch: vérifier log streams récents:",
            "  aws logs describe-log-streams --log-group-name <group> --order-by LastEventTime --descending --max-items 5",
            "Test Athena query:",
            "  SELECT * FROM vpc_flow_logs WHERE action='REJECT' AND srcport=22 LIMIT 100;",
            "Vérifier absence de VPCs/subnets sans Flow Logs"
        ],
        references=[
            "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html",
            "https://docs.aws.amazon.com/athena/latest/ug/vpc-flow-logs.html"
        ]
    ),

    Question(
        id="VPC-004",
        question="Network ACLs (NACLs) : utilisées en complément des SG, règles stateless documentées ?",
        description="Vérifier que des NACLs restrictives sont configurées comme couche de défense supplémentaire aux Security Groups",
        severity="MEDIUM",
        category="VPC",
        compliance=["Defense in Depth", "CIS Benchmark"],
        technical_details="""
        Différences SG vs NACL:

        Security Groups (stateful):
        - Instance/ENI level
        - Stateful (return traffic auto-allowed)
        - Allow rules only
        - Evaluated as a whole (all rules)

        NACLs (stateless):
        - Subnet level
        - Stateless (return traffic must be explicitly allowed)
        - Allow AND Deny rules
        - Evaluated in order (lowest rule number first)
        - Default NACL: allow all

        Use cases NACLs:
        1. Blocker des IP ranges malveillants (deny rules)
        2. Isoler des subnets entre eux
        3. Restreindre ports au niveau subnet (défense profonde)
        4. Compliance requirement (dual-layer security)

        Best practices:
        - Numéroter par incréments de 10 (ex: 100, 110, 120) pour insertion future
        - Documenter chaque règle (Description non disponible, utiliser tag/doc externe)
        - Règle finale: deny all explicite (même si implicite)
        - Tester impact avant apply (peut casser connectivity si mal configuré)
        - Allow ephemeral ports outbound (1024-65535) pour return traffic
        """,
        remediation=[
            "Audit NACLs actuelles:",
            "  aws ec2 describe-network-acls --query 'NetworkAcls[].[NetworkAclId,VpcId,Associations[].SubnetId,IsDefault]'",
            "Identifier subnets utilisant default NACL (trop permissive):",
            "  aws ec2 describe-network-acls --filters Name=default,Values=true",
            "Créer NACL restrictive pour subnet Database:",
            "  aws ec2 create-network-acl --vpc-id <vpc-id>",
            "Exemple règles NACL pour DB tier (MySQL on port 3306):",
            "  # Inbound",
            "  100: ALLOW TCP port 3306 from App subnet CIDR",
            "  110: ALLOW TCP ports 1024-65535 from App subnet CIDR (return traffic)",
            "  *: DENY all",
            "  # Outbound",
            "  100: ALLOW TCP ports 1024-65535 to App subnet CIDR (responses)",
            "  110: ALLOW TCP port 443 to 0.0.0.0/0 (OS updates via HTTPS)",
            "  120: ALLOW UDP port 123 to 0.0.0.0/0 (NTP)",
            "  *: DENY all",
            "Commandes:",
            "  aws ec2 create-network-acl-entry --network-acl-id <acl-id> --rule-number 100 --protocol 6 --port-range From=3306,To=3306 --cidr-block 10.0.1.0/24 --egress false --rule-action allow",
            "Associer NACL au subnet:",
            "  aws ec2 replace-network-acl-association --association-id <assoc-id> --network-acl-id <new-acl-id>",
            "Tester connectivité application après changement",
            "Monitorer VPC Flow Logs pour REJECTs inattendus"
        ],
        verification_steps=[
            "aws ec2 describe-network-acls --network-acl-ids <acl-id>",
            "Vérifier rules Inbound et Outbound:",
            "  jq '.NetworkAcls[].Entries | sort_by(.RuleNumber)'",
            "Pour chaque subnet, identifier NACL associée:",
            "  aws ec2 describe-subnets --subnet-ids <subnet-id> --query 'Subnets[].[SubnetId,NetworkAclAssociationId]'",
            "Comparer avec SGs pour cohérence (NACL + SG = defense in depth)",
            "Vérifier pas de default NACL sur subnets production critiques",
            "Test: essayer connexion non autorisée et vérifier REJECT dans Flow Logs avec raison (SG ou NACL)"
        ],
        references=[
            "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html",
            "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Security.html"
        ]
    ),

    Question(
        id="VPC-005",
        question="Endpoints VPC (Gateway & Interface) : utilisés pour éviter trafic Internet vers services AWS ?",
        description="Vérifier que les VPC Endpoints sont configurés pour S3, DynamoDB et autres services AWS afin de garder le trafic dans le réseau AWS privé",
        severity="MEDIUM",
        category="VPC",
        compliance=["AWS Well-Architected", "Data Privacy"],
        technical_details="""
        Types de VPC Endpoints:

        1. Gateway Endpoints (gratuit):
           - S3
           - DynamoDB
           - Route table entry (pas d'ENI)
           - Pas de coût

        2. Interface Endpoints (PrivateLink - payant):
           - Autres services AWS (EC2, SNS, SQS, etc.)
           - ENI dans subnet
           - Coût: $0.01/hour + $0.01/GB data processed

        Avantages:
        - Pas de traversée Internet
        - Pas besoin de NAT Gateway pour accès AWS services
        - Bande passante illimitée (vs NAT GW)
        - Meilleure latence
        - Logs VPC Flow Logs (vs invisible si via IGW)
        - Sécurité: isolation réseau

        Services critiques nécessitant endpoints:
        - S3 (Gateway) - pour backups, logs, artifacts
        - DynamoDB (Gateway) - pour applications
        - ECR (Interface) - pour pull Docker images
        - CloudWatch Logs (Interface) - pour logging
        - Systems Manager (Interface) - pour management
        - Secrets Manager (Interface) - pour secrets
        - KMS (Interface) - pour encryption keys
        """,
        remediation=[
            "Lister endpoints existants:",
            "  aws ec2 describe-vpc-endpoints --query 'VpcEndpoints[].[VpcEndpointType,ServiceName,VpcId,State]'",
            "Créer Gateway Endpoint S3:",
            "  aws ec2 create-vpc-endpoint \\",
            "    --vpc-id <vpc-id> \\",
            "    --service-name com.amazonaws.<region>.s3 \\",
            "    --route-table-ids <rt-id> \\",
            "    --policy-document file://s3-endpoint-policy.json",
            "Endpoint policy S3 (restrictive):",
            "{",
            "  \"Statement\": [{",
            "    \"Effect\": \"Allow\",",
            "    \"Principal\": \"*\",",
            "    \"Action\": [\"s3:GetObject\", \"s3:PutObject\"],",
            "    \"Resource\": \"arn:aws:s3:::my-company-bucket/*\",",
            "    \"Condition\": {",
            "      \"StringEquals\": {\"aws:PrincipalOrgID\": \"o-xxxxxxxxxx\"}",
            "    }",
            "  }]",
            "}",
            "Créer Interface Endpoint (ex: ECR):",
            "  aws ec2 create-vpc-endpoint \\",
            "    --vpc-id <vpc-id> \\",
            "    --vpc-endpoint-type Interface \\",
            "    --service-name com.amazonaws.<region>.ecr.dkr \\",
            "    --subnet-ids <subnet-1> <subnet-2> \\",
            "    --security-group-ids <sg-id>",
            "Créer aussi com.amazonaws.<region>.ecr.api (ECR nécessite 2 endpoints)",
            "Enable Private DNS pour résolution automatique",
            "Vérifier route tables: pas de route 0.0.0.0/0 → IGW pour subnets avec endpoints"
        ],
        verification_steps=[
            "aws ec2 describe-vpc-endpoints --filters Name=vpc-id,Values=<vpc-id>",
            "Pour S3 Gateway Endpoint:",
            "  Vérifier présence dans route tables des subnets privés",
            "  aws ec2 describe-route-tables --route-table-ids <rt-id> --query 'RouteTables[].Routes[?GatewayId!=`local`]'",
            "Pour Interface Endpoints:",
            "  Vérifier état Available",
            "  Vérifier PrivateDnsEnabled = true",
            "  Vérifier Security Group autorise trafic sur port service (443 généralement)",
            "Test fonctionnel depuis instance dans subnet privé (sans NAT GW):",
            "  aws s3 ls (devrait fonctionner via S3 endpoint)",
            "  nslookup s3.<region>.amazonaws.com (devrait résoudre en IP privée VPC si endpoint interface)",
            "VPC Flow Logs: vérifier trafic vers AWS service passe par ENI endpoint (IP privée)"
        ],
        references=[
            "https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints.html",
            "https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-s3.html"
        ]
    ),

    Question(
        id="VPC-006",
        question="PrivateLink : utilisé pour exposer services à des tiers sans VPC Peering ni Internet ?",
        description="Évaluer l'utilisation de AWS PrivateLink pour exposer des services internes de manière sécurisée à des partenaires/clients",
        severity="LOW",
        category="VPC",
        compliance=["AWS Well-Architected", "Zero Trust"],
        technical_details="""
        AWS PrivateLink use cases:

        1. Exposer API interne à des clients:
           - Créer NLB interne pour votre API
           - Créer VPC Endpoint Service
           - Clients créent VPC Endpoint dans leur VPC
           - Connexion privée via réseau AWS (pas Internet)

        2. Consommer SaaS de manière privée:
           - SaaS vendor expose service via PrivateLink
           - Vous créez interface endpoint
           - Pas besoin de whitelister IPs

        3. Multi-account / Multi-région:
           - Alternatif à VPC Peering
           - Plus scalable (pas de limites de peering)
           - Pas de overlap CIDR problems

        Avantages vs alternatives:
        - vs VPC Peering: pas de limit 125 peerings, pas de overlap CIDR
        - vs Internet: pas d'exposition publique, meilleure sécurité
        - vs VPN/Direct Connect: plus simple, moins cher pour use case spécifique
        - vs Transit Gateway: moins cher pour connexion point-to-point

        Architecture:
        Service Provider → NLB (internal) → VPC Endpoint Service → [ AWS Network ] → VPC Interface Endpoint → Service Consumer
        """,
        remediation=[
            "Côté Service Provider (exposer votre service):",
            "1. Créer Network Load Balancer internal:",
            "   aws elbv2 create-load-balancer --name my-api-nlb --scheme internal --type network --subnets <subnet-ids>",
            "2. Créer VPC Endpoint Service:",
            "   aws ec2 create-vpc-endpoint-service-configuration \\",
            "     --network-load-balancer-arns <nlb-arn> \\",
            "     --acceptance-required (pour approuver chaque consumer)",
            "3. Noter le Service Name: com.amazonaws.vpce.<region>.vpce-svc-xxxxxxx",
            "4. Partager Service Name avec consumers",
            "5. Approuver connection requests:",
            "   aws ec2 describe-vpc-endpoint-connections --filters Name=service-id,Values=<svc-id>",
            "   aws ec2 accept-vpc-endpoint-connections --service-id <svc-id> --vpc-endpoint-ids <endpoint-id>",
            "",
            "Côté Service Consumer:",
            "1. Créer Interface Endpoint vers service:",
            "   aws ec2 create-vpc-endpoint \\",
            "     --vpc-id <vpc-id> \\",
            "     --vpc-endpoint-type Interface \\",
            "     --service-name <service-name-from-provider> \\",
            "     --subnet-ids <subnet-ids> \\",
            "     --security-group-ids <sg-id>",
            "2. Attendre approval du provider",
            "3. Utiliser DNS name de l'endpoint pour appeler le service",
            "",
            "Sécurité:",
            "- Provider: Endpoint policy pour restreindre consumers (par compte AWS)",
            "- Consumer: Security Group sur endpoint pour restreindre sources"
        ],
        verification_steps=[
            "Provider side:",
            "  aws ec2 describe-vpc-endpoint-service-configurations",
            "  aws ec2 describe-vpc-endpoint-connections",
            "  Vérifier State = available",
            "Consumer side:",
            "  aws ec2 describe-vpc-endpoints --filters Name=service-name,Values=<service-name>",
            "  Vérifier State = available",
            "Test connectivité:",
            "  Depuis consumer, curl https://<endpoint-dns-name>/api",
            "Vérifier logs NLB pour requêtes provenant d'IPs privées (endpoint ENIs)"
        ],
        references=[
            "https://docs.aws.amazon.com/vpc/latest/privatelink/privatelink-share-your-services.html",
            "https://docs.aws.amazon.com/vpc/latest/privatelink/create-endpoint-service.html"
        ]
    ),

    Question(
        id="VPC-007",
        question="AWS Network Firewall ou tiers (Palo Alto, Fortinet) : inspection trafic centralisée ?",
        description="Évaluer si une solution de firewall réseau est déployée pour inspection centralisée du trafic (IDS/IPS, filtrage applicatif L7)",
        severity="MEDIUM",
        category="VPC",
        compliance=["PCI-DSS", "HIPAA", "Zero Trust"],
        technical_details="""
        Options de Network Firewall:

        1. AWS Network Firewall (AWS-managed):
           - Stateful firewall rules
           - Stateless firewall rules
           - Intrusion Detection/Prevention (Suricata compatible)
           - Domain name filtering
           - Logging vers S3/CloudWatch/Kinesis
           - Scaling automatique

        2. Third-party (Palo Alto, Fortinet, Check Point):
           - Features avancées (L7 inspection, threat intelligence)
           - Unified management multi-cloud
           - Advanced threat prevention
           - Coût licensing élevé

        3. Inline IDS/IPS:
           - Suricata, Snort sur EC2
           - Traffic mirroring avec VPC Traffic Mirroring
           - Analyse passive ou active (inline)

        Architecture avec Network Firewall:
        - Deployment: Firewall subnet par AZ (dédiés)
        - Routing: IGW → Firewall subnet → NAT GW → App subnets
        - Ou: App subnets → Firewall → TGW → Other VPCs
        - Centralized inspection dans VPC Hub (hub-and-spoke)

        Use cases:
        - Bloquer exfiltration vers IPs malveillantes
        - IDS/IPS pour détecter exploits
        - Filtrage HTTP/HTTPS par domaine (blocklist/allowlist)
        - Log toutes connexions sortantes
        - Compliance: preuve de network monitoring
        """,
        remediation=[
            "Option 1: Déployer AWS Network Firewall",
            "1. Créer Firewall Policy:",
            "   aws network-firewall create-firewall-policy \\",
            "     --firewall-policy-name my-policy \\",
            "     --firewall-policy file://policy.json",
            "   Exemple policy.json:",
            "   {",
            "     \"StatelessDefaultActions\": [\"aws:forward_to_sfe\"],",
            "     \"StatelessFragmentDefaultActions\": [\"aws:forward_to_sfe\"],",
            "     \"StatefulRuleGroupReferences\": [",
            "       {\"ResourceArn\": \"<rule-group-arn>\"}",
            "     ]",
            "   }",
            "2. Créer Rule Groups (stateful for domain filtering):",
            "   aws network-firewall create-rule-group \\",
            "     --rule-group-name block-malicious \\",
            "     --type STATEFUL \\",
            "     --rule-group file://rules.json \\",
            "     --capacity 100",
            "3. Créer Firewall:",
            "   aws network-firewall create-firewall \\",
            "     --firewall-name my-firewall \\",
            "     --firewall-policy-arn <policy-arn> \\",
            "     --vpc-id <vpc-id> \\",
            "     --subnet-mappings SubnetId=<subnet-1> SubnetId=<subnet-2>",
            "4. Update Route Tables:",
            "   - IGW route table: 0.0.0.0/0 → Firewall Endpoint",
            "   - App subnet route tables: 0.0.0.0/0 → Firewall Endpoint",
            "   - Firewall subnet route table: 0.0.0.0/0 → NAT Gateway",
            "5. Enable logging:",
            "   aws network-firewall update-logging-configuration \\",
            "     --firewall-name my-firewall \\",
            "     --logging-configuration file://logging.json",
            "",
            "Option 2: Third-party Firewall",
            "- Deploy from AWS Marketplace (auto-scaling group)",
            "- Configure routing similar to Network Firewall",
            "- Integrate logging with SIEM (Splunk, QRadar)"
        ],
        verification_steps=[
            "aws network-firewall list-firewalls",
            "aws network-firewall describe-firewall --firewall-name <name>",
            "Vérifier status = READY",
            "Vérifier FirewallPolicyArn est attached",
            "Vérifier logging configuré:",
            "  aws network-firewall describe-logging-configuration --firewall-name <name>",
            "Test: déclencher alerte (curl vers domaine bloqué)",
            "Vérifier logs dans CloudWatch/S3:",
            "  aws logs filter-log-events --log-group-name /aws/networkfirewall/<name>",
            "Vérifier routing: traceroute doit passer par firewall endpoint"
        ],
        references=[
            "https://docs.aws.amazon.com/network-firewall/latest/developerguide/what-is-aws-network-firewall.html",
            "https://aws.amazon.com/blogs/networking-and-content-delivery/deployment-models-for-aws-network-firewall/"
        ]
    )
]

# Continuer avec d'autres services...
# EC2, S3, RDS, Lambda, API Gateway, CloudFront, etc.

ALL_QUESTIONS = IAM_QUESTIONS + VPC_QUESTIONS
