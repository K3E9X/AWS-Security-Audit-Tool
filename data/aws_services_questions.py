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
    ),

    Question(
        id="IAM-008",
        question="Compte root AWS: sécurisé avec MFA, aucune access key, usage monitoring et email dédié sécurisé?",
        description="Vérifier que le compte root est durci: MFA hardware activé, aucune access key, usage monitored via CloudTrail, et email sécurisé avec accès restreint",
        severity="CRITICAL",
        category="IAM",
        compliance=["CIS Benchmark", "PCI-DSS", "SOC2", "NIST"],
        technical_details="""
        Compte root = accès complet sans restriction possible

        Capacités uniques du root (non délégables):
        - Changer account settings (nom, email, password)
        - Fermer le compte AWS
        - Changer AWS Support plan
        - Activer IAM user access to Billing
        - Restaurer IAM user permissions (si tous admin lockout)
        - S3 bucket policy avec deny explicite (root override)
        - Enregistrer domaine Route 53 (certains TLDs)
        - Créer CloudFront key pairs (legacy)
        - Soumettre reverse DNS pour EC2 email

        Risques majeurs root account:
        - Pas de restrictions via IAM policies
        - Pas de SCPs applicables
        - Pas de permission boundaries
        - Full access à tous les services/ressources
        - Cible prioritaire des attaquants

        Protection root account (CIS Benchmark):
        1. Hardware MFA (YubiKey, pas virtual MFA)
        2. Aucune access key (si existantes: supprimer)
        3. Utilisation uniquement en break-glass scenarios
        4. Email root avec MFA (G Suite, Office 365)
        5. Email accessible par 2+ personnes (no single point of failure)
        6. Pas de usage quotidien (jamais)
        7. CloudWatch alarm sur root usage
        8. Password complexe (>30 caractères) dans vault sécurisé

        Email root best practices:
        - Email dédié (pas personal email)
        - Distribution list avec accès contrôlé
        - MFA sur email account
        - Alertes SMS/phone sur login email
        - Separate email provider (différent de corp email)
        - Documentation accès email en lieu sécurisé
        """,
        remediation=[
            "1. Vérifier et supprimer access keys root:",
            "   # Se connecter en root via console",
            "   # My Security Credentials → Access keys",
            "   # Delete toutes les access keys",
            "   # Vérification CLI (depuis IAM user admin):",
            "   aws iam get-account-summary | grep 'AccountAccessKeysPresent'",
            "   # Doit être = 0",
            "",
            "2. Activer MFA hardware pour root:",
            "   # Console: My Security Credentials → MFA → Activate MFA",
            "   # Choisir: Hardware MFA device (YubiKey recommandé)",
            "   # Enregistrer 2 MFA devices (backup)",
            "   # Stocker backup MFA en lieu physique sécurisé (coffre)",
            "",
            "3. Configurer CloudWatch alarm root usage:",
            "   aws cloudwatch put-metric-alarm \\",
            "     --alarm-name root-account-usage \\",
            "     --alarm-description 'Alert on root account usage' \\",
            "     --metric-name RootAccountUsage \\",
            "     --namespace AWS/CloudTrail \\",
            "     --statistic Sum \\",
            "     --period 60 \\",
            "     --evaluation-periods 1 \\",
            "     --threshold 1 \\",
            "     --comparison-operator GreaterThanOrEqualToThreshold \\",
            "     --alarm-actions arn:aws:sns:region:account:security-alerts",
            "",
            "   Metric filter pour CloudTrail:",
            "   { $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }",
            "",
            "4. Sécuriser email root:",
            "   # Changer vers email dédié (si personnel):",
            "   # Console root → My Account → Contact Information",
            "   # Utiliser: aws-root@company.com (distribution list)",
            "   # Activer MFA sur email provider",
            "   # Limiter accès email à 2-3 personnes (CISO, VP Eng, etc.)",
            "   # Documenter procédure accès email dans runbook",
            "",
            "5. Créer AWS Config rule root compliance:",
            "   aws configservice put-config-rule \\",
            "     --config-rule file://root-account-rule.json",
            "",
            "   root-account-rule.json:",
            "   {",
            '     "ConfigRuleName": "root-account-mfa-enabled",',
            '     "Source": {',
            '       "Owner": "AWS",',
            '       "SourceIdentifier": "ROOT_ACCOUNT_MFA_ENABLED"',
            "     }",
            "   }",
            "",
            "6. Documenter break-glass procedure:",
            "   Créer runbook avec:",
            "   - Quand utiliser root (liste exhaustive scenarios)",
            "   - Comment accéder email root",
            "   - Où trouver password root (password manager)",
            "   - Où trouver MFA device backup",
            "   - Process approbation (2-person rule)",
            "   - Post-usage audit review",
            "",
            "7. Alternate contacts configuration:",
            "   Console → My Account → Alternate Contacts",
            "   Configurer: Billing, Operations, Security contacts",
            "   Utiliser distribution lists (pas individual emails)",
            "",
            "8. Implémenter rotation password root annuelle:",
            "   Calendrier: changer password root tous les 365 jours",
            "   Stocker dans password manager enterprise (1Password, LastPass)"
        ],
        verification_steps=[
            "Vérifier absence access keys root:",
            "  aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'",
            "  # Expected: 0",
            "",
            "Vérifier MFA root via Credential Report:",
            "  aws iam generate-credential-report",
            "  aws iam get-credential-report --output text | base64 -d | grep '<root_account>'",
            "  # Colonne mfa_active doit être 'true'",
            "",
            "Audit usage root dans CloudTrail (90 derniers jours):",
            "  aws cloudtrail lookup-events \\",
            "    --lookup-attributes AttributeKey=Username,AttributeValue=root \\",
            "    --start-time $(date -d '90 days ago' +%s) \\",
            "    --max-results 50",
            "  # Devrait être vide ou quasi-vide",
            "",
            "Vérifier CloudWatch alarm configurée:",
            "  aws cloudwatch describe-alarms --alarm-names root-account-usage",
            "",
            "Config rule compliance:",
            "  aws configservice describe-compliance-by-config-rule \\",
            "    --config-rule-names root-account-mfa-enabled",
            "",
            "SecurityHub finding check:",
            "  aws securityhub get-findings \\",
            "    --filters '{\"GeneratorId\":[{\"Value\":\"arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0/rule/1.4\",\"Comparison\":\"EQUALS\"}]}'",
            "  # CIS 1.4: Ensure no root user access key exists",
            "",
            "Vérifier alternate contacts configurés:",
            "  aws account get-alternate-contact --alternate-contact-type SECURITY",
            "  aws account get-alternate-contact --alternate-contact-type BILLING",
            "  aws account get-alternate-contact --alternate-contact-type OPERATIONS"
        ],
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials",
            "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html"
        ]
    ),

    Question(
        id="IAM-009",
        question="IAM Groups utilisés pour gestion permissions: aucune policy attachée directement aux users?",
        description="Vérifier que toutes les permissions sont gérées via IAM Groups et qu'aucun user n'a de policy attachée directement (inline ou managed)",
        severity="HIGH",
        category="IAM",
        compliance=["CIS Benchmark", "AWS Well-Architected", "Least Privilege"],
        technical_details="""
        Problèmes permissions directes sur users:
        - Gestion décentralisée difficile à auditer
        - Pas de cohérence entre users similaires
        - Difficile de voir "qui a quoi" globalement
        - Risque de drift: permissions divergent over time
        - Onboarding/offboarding complexe
        - Pas de principe de rôles (role-based access)

        Avantages IAM Groups:
        - Gestion centralisée des permissions
        - Cohérence: tous membres groupe = mêmes permissions
        - Audit simplifié: review group memberships
        - Onboarding rapide: ajouter user à groups appropriés
        - Offboarding sécurisé: remove user from groups
        - Évolutif: modifications propagées automatiquement
        - Aligné avec org structure (Dev, Ops, Security, etc.)

        Structure recommandée:
        Groups par fonction:
        - Developers: read/write sur dev resources
        - Operators: admin EC2, RDS, mais pas IAM
        - SecurityAuditors: read-only sur tous services
        - Billing: accès Billing console
        - NetworkAdmins: VPC, Route53, CloudFront admin

        Groups par environnement:
        - Production-ReadOnly
        - Production-Admin (très restreint)
        - Staging-Admin
        - Development-Admin

        Best practices:
        - Un user peut appartenir à plusieurs groups (intersection permissions)
        - Préférer managed policies sur groups (vs inline)
        - Naming convention: <Environment>-<Function>-Group
        - Documentation obligatoire par group (README)
        - Review régulier des memberships (quarterly)
        - Automated alerts: user ajouté à sensitive group

        Anti-patterns à éviter:
        - User avec inline policy (jamais)
        - User avec managed policy directement (jamais)
        - Group vide (cleanup nécessaire)
        - Group avec un seul member (créer policy user direct?)
        - Group overlap 100% (merger groups)
        """,
        remediation=[
            "1. Audit users avec policies directes:",
            "   # Lister tous les users:",
            "   aws iam list-users --query 'Users[].UserName' --output text",
            "",
            "   # Pour chaque user, check inline policies:",
            "   for user in $(aws iam list-users --query 'Users[].UserName' --output text); do",
            "     echo \"=== User: $user ===\"",
            "     aws iam list-user-policies --user-name $user",
            "     aws iam list-attached-user-policies --user-name $user",
            "   done",
            "",
            "2. Identifier users avec permissions directes:",
            "   # Script pour report complet:",
            "   aws iam list-users | jq -r '.Users[].UserName' | while read user; do",
            "     inline=$(aws iam list-user-policies --user-name $user --query 'PolicyNames' --output text)",
            "     attached=$(aws iam list-attached-user-policies --user-name $user --query 'AttachedPolicies[].PolicyName' --output text)",
            "     if [ -n \"$inline\" ] || [ -n \"$attached\" ]; then",
            "       echo \"$user: inline=[$inline] attached=[$attached]\"",
            "     fi",
            "   done",
            "",
            "3. Créer IAM Groups par fonction:",
            "   aws iam create-group --group-name Developers",
            "   aws iam create-group --group-name Operators",
            "   aws iam create-group --group-name SecurityAuditors",
            "   aws iam create-group --group-name BillingViewers",
            "",
            "4. Attacher policies appropriées aux groups:",
            "   # Developers:",
            "   aws iam attach-group-policy --group-name Developers \\",
            "     --policy-arn arn:aws:iam::aws:policy/PowerUserAccess",
            "",
            "   # Operators:",
            "   aws iam attach-group-policy --group-name Operators \\",
            "     --policy-arn arn:aws:iam::account:policy/OperatorAccess  # Custom policy",
            "",
            "   # SecurityAuditors:",
            "   aws iam attach-group-policy --group-name SecurityAuditors \\",
            "     --policy-arn arn:aws:iam::aws:policy/SecurityAudit",
            "",
            "5. Migrer users vers groups:",
            "   # Pour chaque user identifié step 2:",
            "   # A. Identifier permissions actuelles",
            "   # B. Déterminer group(s) approprié(s)",
            "   # C. Ajouter user au(x) group(s):",
            "   aws iam add-user-to-group --user-name john.doe --group-name Developers",
            "",
            "   # D. Tester access avec user (validation)",
            "",
            "   # E. Supprimer inline policies:",
            "   aws iam delete-user-policy --user-name john.doe --policy-name PolicyName",
            "",
            "   # F. Detach managed policies:",
            "   aws iam detach-user-policy --user-name john.doe --policy-arn <arn>",
            "",
            "6. Créer AWS Config rule:",
            "   aws configservice put-config-rule \\",
            "     --config-rule file://no-direct-user-policies.json",
            "",
            "   no-direct-user-policies.json:",
            "   {",
            '     "ConfigRuleName": "iam-user-no-policies-check",',
            '     "Source": {',
            '       "Owner": "AWS",',
            '       "SourceIdentifier": "IAM_USER_NO_POLICIES_CHECK"',
            "     }",
            "   }",
            "",
            "7. Automatiser alerts nouveaux users avec policies:",
            "   EventBridge rule:",
            "   Event: AttachUserPolicy, PutUserPolicy",
            "   Target: SNS topic → alerte security team",
            "",
            "8. Documenter groups:",
            "   Créer wiki/confluence page par group:",
            "   - Purpose du group",
            "   - Permissions incluses",
            "   - Approval process pour membership",
            "   - Owner du group (qui review memberships)",
            "   - Quarterly review checklist"
        ],
        verification_steps=[
            "Lister tous users avec inline policies:",
            "  aws iam list-users | jq -r '.Users[].UserName' | while read u; do",
            "    policies=$(aws iam list-user-policies --user-name $u --query 'PolicyNames' --output text)",
            "    [ -n \"$policies\" ] && echo \"$u: $policies\"",
            "  done",
            "  # Expected: aucun résultat",
            "",
            "Lister users avec managed policies attachées:",
            "  aws iam list-users | jq -r '.Users[].UserName' | while read u; do",
            "    policies=$(aws iam list-attached-user-policies --user-name $u --query 'AttachedPolicies[].PolicyName' --output text)",
            "    [ -n \"$policies\" ] && echo \"$u: $policies\"",
            "  done",
            "  # Expected: aucun résultat",
            "",
            "Lister tous IAM groups et memberships:",
            "  aws iam list-groups --query 'Groups[].[GroupName]' --output text | while read g; do",
            "    echo \"=== Group: $g ===\"",
            "    aws iam get-group --group-name $g --query 'Users[].[UserName]' --output text",
            "    aws iam list-attached-group-policies --group-name $g --query 'AttachedPolicies[].[PolicyName]' --output text",
            "  done",
            "",
            "Config rule compliance:",
            "  aws configservice describe-compliance-by-config-rule \\",
            "    --config-rule-names iam-user-no-policies-check",
            "  # Expected: COMPLIANT",
            "",
            "SecurityHub CIS check:",
            "  aws securityhub get-findings \\",
            "    --filters '{\"GeneratorId\":[{\"Value\":\"arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0/rule/1.16\",\"Comparison\":\"EQUALS\"}]}'",
            "  # CIS 1.16: Ensure IAM policies attached only to groups or roles",
            "",
            "Vérifier aucun user orphelin (pas dans group):",
            "  aws iam list-users | jq -r '.Users[].UserName' | while read u; do",
            "    groups=$(aws iam list-groups-for-user --user-name $u --query 'Groups' --output text)",
            "    [ -z \"$groups\" ] && echo \"Orphan user: $u\"",
            "  done"
        ],
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups.html",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#use-groups-for-permissions",
            "https://aws.amazon.com/blogs/security/guidelines-for-when-to-use-accounts-users-and-groups/"
        ]
    ),

    Question(
        id="IAM-010",
        question="Permission Boundaries implémentées pour délégation sécurisée admin et prévention escalade privilèges?",
        description="Vérifier que Permission Boundaries sont utilisées pour limiter les permissions maximales des IAM entities, empêchant escalade de privilèges",
        severity="MEDIUM",
        category="IAM",
        compliance=["AWS Well-Architected", "Least Privilege", "Zero Trust"],
        technical_details="""
        Permission Boundaries = limite maximale de permissions

        Concept:
        - Managed policy définissant permissions maximales
        - Appliquée à user ou role
        - Effective permissions = Intersection(Identity policy AND Boundary)
        - Empêche user/role d'obtenir permissions au-delà boundary

        Use cases critiques:
        1. Délégation admin sécurisée:
           - Donner CreateUser/CreateRole à dev lead
           - Boundary empêche création de users/roles admin
           - Dev lead peut créer users avec max "Developer" permissions

        2. Prévention escalade privilèges:
           - User avec iam:CreateUser mais boundary restrictive
           - Ne peut pas créer user plus privilégié que boundary
           - Protection contre auto-escalation

        3. Multi-tenant environments:
           - Chaque tenant a boundary limitant à ses resources
           - Tenant A ne peut pas créer roles accédant à Tenant B
           - Isolation entre tenants via boundaries

        4. Sandboxing:
           - Boundaries limitant à specific VPC/Region/Account
           - Development environments isolés
           - Experimentation sécurisée

        Comment ça fonctionne:
        User policy: Allow s3:*, ec2:*, iam:*
        Boundary: Allow s3:*, ec2:* (pas iam:*)
        Effective: s3:*, ec2:* (iam:* bloqué par boundary)

        Différence vs SCP:
        - SCP: appliqué au niveau Organizations (account entier)
        - Boundary: appliqué au niveau IAM entity (user/role)
        - Combinaison: effective = Identity AND Boundary AND SCP

        Best practices:
        - Boundary obligatoire pour tous delegated admins
        - Condition IAM policy: CreateUser/CreateRole require boundary
        - Boundary ne peut pas être modifiée par l'entity
        - Audit régulier: qui a boundary, qui n'en a pas
        - Documentation claire: quelles boundaries existent, purpose

        Limitations boundaries:
        - Pas applicable à resource-based policies
        - Pas applicable à SCPs
        - User peut toujours assumer role sans boundary (risk)
        """,
        remediation=[
            "1. Créer Permission Boundary pour delegated admins:",
            "   # Boundary empêchant admin complet:",
            "   boundary-developer-admin.json:",
            "   {",
            '     "Version": "2012-10-17",',
            '     "Statement": [',
            "       {",
            '         "Effect": "Allow",',
            '         "Action": [',
            '           "ec2:*",',
            '           "s3:*",',
            '           "rds:*",',
            '           "lambda:*",',
            '           "logs:*",',
            '           "cloudwatch:*"',
            "         ],",
            '         "Resource": "*"',
            "       },",
            "       {",
            '         "Effect": "Allow",',
            '         "Action": [',
            '           "iam:GetUser",',
            '           "iam:GetRole",',
            '           "iam:ListUsers",',
            '           "iam:ListRoles",',
            '           "iam:GetPolicy",',
            '           "iam:GetPolicyVersion"',
            "         ],",
            '         "Resource": "*"',
            "       },",
            "       {",
            '         "Effect": "Deny",',
            '         "Action": [',
            '           "iam:CreateUser",',
            '           "iam:CreateRole",',
            '           "iam:DeleteUser",',
            '           "iam:DeleteRole",',
            '           "iam:PutUserPolicy",',
            '           "iam:PutRolePolicy",',
            '           "iam:AttachUserPolicy",',
            '           "iam:AttachRolePolicy",',
            '           "iam:DeleteUserPolicy",',
            '           "iam:DeleteRolePolicy",',
            '           "organizations:*",',
            '           "account:*"',
            "         ],",
            '         "Resource": "*"',
            "       }",
            "     ]",
            "   }",
            "",
            "   # Créer policy:",
            "   aws iam create-policy \\",
            "     --policy-name DeveloperAdminBoundary \\",
            "     --policy-document file://boundary-developer-admin.json",
            "",
            "2. Appliquer boundary à un user/role:",
            "   # Pour user existant:",
            "   aws iam put-user-permissions-boundary \\",
            "     --user-name delegated-admin \\",
            "     --permissions-boundary arn:aws:iam::account:policy/DeveloperAdminBoundary",
            "",
            "   # Pour role existant:",
            "   aws iam put-role-permissions-boundary \\",
            "     --role-name developer-admin-role \\",
            "     --permissions-boundary arn:aws:iam::account:policy/DeveloperAdminBoundary",
            "",
            "3. Forcer boundary lors création users/roles:",
            "   # Policy pour delegated admin (enforcing boundary):",
            "   delegated-admin-policy.json:",
            "   {",
            '     "Version": "2012-10-17",',
            '     "Statement": [',
            "       {",
            '         "Effect": "Allow",',
            '         "Action": [',
            '           "iam:CreateUser",',
            '           "iam:CreateRole"',
            "         ],",
            '         "Resource": "*",',
            '         "Condition": {',
            '           "StringEquals": {',
            '             "iam:PermissionsBoundary": "arn:aws:iam::account:policy/DeveloperAdminBoundary"',
            "           }",
            "         }",
            "       },",
            "       {",
            '         "Effect": "Allow",',
            '         "Action": [',
            '           "iam:AttachUserPolicy",',
            '           "iam:AttachRolePolicy",',
            '           "iam:PutUserPolicy",',
            '           "iam:PutRolePolicy"',
            "         ],",
            '         "Resource": "*",',
            '         "Condition": {',
            '           "StringEquals": {',
            '             "iam:PermissionsBoundary": "arn:aws:iam::account:policy/DeveloperAdminBoundary"',
            "           }",
            "         }",
            "       }",
            "     ]",
            "   }",
            "",
            "   # Attacher au delegated admin:",
            "   aws iam put-user-policy \\",
            "     --user-name delegated-admin \\",
            "     --policy-name EnforceBoundary \\",
            "     --policy-document file://delegated-admin-policy.json",
            "",
            "4. Créer boundary pour isolation tenant:",
            "   # Boundary limitant à resources avec tag Tenant=A:",
            "   {",
            '     "Statement": [{',
            '       "Effect": "Allow",',
            '       "Action": "*",',
            '       "Resource": "*",',
            '       "Condition": {',
            '         "StringEquals": {"aws:ResourceTag/Tenant": "A"}',
            "       }",
            "     }]",
            "   }",
            "",
            "5. Audit boundaries existantes:",
            "   # Lister users avec boundary:",
            "   aws iam list-users | jq -r '.Users[] | select(.PermissionsBoundary) | {UserName, Boundary: .PermissionsBoundary.PermissionsBoundaryArn}'",
            "",
            "   # Lister roles avec boundary:",
            "   aws iam list-roles | jq -r '.Roles[] | select(.PermissionsBoundary) | {RoleName, Boundary: .PermissionsBoundary.PermissionsBoundaryArn}'",
            "",
            "6. Identifier users/roles sans boundary (should have):",
            "   # Users avec CreateUser permission mais sans boundary:",
            "   # Manual review nécessaire",
            "",
            "7. Test escalation attempt:",
            "   # Avec user ayant boundary, tester:",
            "   aws iam create-user --user-name test-escalation",
            "   # Sans --permissions-boundary: devrait échouer (condition)",
            "",
            "   aws iam attach-user-policy --user-name test-escalation \\",
            "     --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            "   # Devrait réussir MAIS effective permissions limitées par boundary"
        ],
        verification_steps=[
            "Lister toutes les permission boundaries définies:",
            "  aws iam list-policies --scope Local --query 'Policies[?DefaultVersionId].{Name:PolicyName,Arn:Arn}' --output table",
            "  # Identifier lesquelles sont boundaries (naming convention)",
            "",
            "Lister entities avec boundaries:",
            "  # Users:",
            "  aws iam list-users --query 'Users[?PermissionsBoundary].[UserName,PermissionsBoundary.PermissionsBoundaryArn]' --output table",
            "",
            "  # Roles:",
            "  aws iam list-roles --query 'Roles[?PermissionsBoundary].[RoleName,PermissionsBoundary.PermissionsBoundaryArn]' --output table",
            "",
            "Vérifier enforcement boundary lors création:",
            "  # Tenter créer user sans boundary (devrait échouer si bien configuré):",
            "  aws iam create-user --user-name test-no-boundary",
            "  # Expected: AccessDenied avec message sur condition iam:PermissionsBoundary",
            "",
            "Simuler permissions effectives avec boundary:",
            "  aws iam simulate-principal-policy \\",
            "    --policy-source-arn arn:aws:iam::account:user/delegated-admin \\",
            "    --action-names iam:CreateUser iam:DeleteUser s3:PutObject \\",
            "    --permissions-boundary-policy-input-list file://boundary.json",
            "",
            "Audit CloudTrail pour violations boundary attempts:",
            "  aws cloudtrail lookup-events \\",
            "    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \\",
            "    --query 'Events[?errorCode==`AccessDenied`]' \\",
            "    --max-results 50",
            "",
            "Vérifier qui peut modifier boundaries:",
            "  # Trouver users/roles avec iam:PutUserPermissionsBoundary:",
            "  # Manual review policies nécessaire",
            "",
            "Test effective permissions:",
            "  # User avec AdministratorAccess policy + boundary restrictive:",
            "  # Test action bloquée par boundary (ex: organizations:CreateAccount)",
            "  aws organizations create-account --email test@example.com --account-name Test",
            "  # Expected: AccessDenied (blocked by boundary)"
        ],
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html",
            "https://aws.amazon.com/blogs/security/delegate-permission-management-to-developers-using-iam-permissions-boundaries/",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries_delegation.html"
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
    ),

    Question(
        id="VPC-008",
        question="Transit Gateway: architecture hub-and-spoke avec isolation routing et segmentation entre environnements?",
        description="Vérifier que Transit Gateway est utilisé avec route tables séparées pour isoler le trafic entre VPCs/environnements selon principe zero-trust",
        severity="MEDIUM",
        category="VPC",
        compliance=["Zero Trust", "AWS Well-Architected", "Network Segmentation"],
        technical_details="""
        AWS Transit Gateway (TGW) = routeur régional cloud

        Fonctionnement:
        - Hub central connectant VPCs, VPNs, Direct Connect
        - Remplace VPC peering mesh complexe
        - Scaling: jusqu'à 5000 VPCs attachés
        - 50 Gbps per VPC attachment (burst 100 Gbps)
        - Route tables multiples pour isolation

        Architecture Hub-and-Spoke:
        - Hub = Transit Gateway
        - Spokes = VPCs (production, staging, dev, shared services)
        - Avantages:
          * Gestion centralisée routing
          * Pas de peering N-to-N (complexité O(n²))
          * Inspection centralisée (via firewall VPC)
          * Facilite audit et compliance

        Segmentation via TGW Route Tables:
        - Production Route Table: isole VPCs production
        - Non-Production Route Table: dev/staging
        - Shared Services Route Table: DNS, AD, monitoring
        - Egress Route Table: vers Internet/on-prem via firewall

        Isolation patterns:
        1. Full isolation: aucune route entre prod et dev
        2. Shared services only: prod/dev → shared services, pas entre eux
        3. Inspection-based: tout trafic passe par firewall VPC

        TGW Connect pour SD-WAN:
        - GRE tunnels over TGW
        - Intégration Cisco Viptela, VMware VeloCloud, etc.
        - Multicast support

        TGW Peering (inter-region):
        - Connecter TGW entre régions
        - DR, global architecture
        - Encrypted par défaut

        Cost considerations:
        - $0.05/hour per attachment
        - $0.02/GB data processed
        - Optimization: partager TGW entre comptes (RAM)

        Monitoring:
        - CloudWatch metrics: BytesIn, BytesOut, PacketsDropCountBlackhole
        - VPC Flow Logs: capture trafic cross-VPC
        - TGW Network Manager: visualisation topology
        """,
        remediation=[
            "1. Créer Transit Gateway:",
            "   aws ec2 create-transit-gateway \\",
            "     --description 'Corporate TGW' \\",
            "     --options 'AmazonSideAsn=64512,AutoAcceptSharedAttachments=disable,DefaultRouteTableAssociation=disable,DefaultRouteTablePropagation=disable,VpnEcmpSupport=enable,DnsSupport=enable'",
            "",
            "   Notes:",
            "   - DefaultRouteTableAssociation=disable: évite auto-association (sécurité)",
            "   - DefaultRouteTablePropagation=disable: contrôle explicite routing",
            "",
            "2. Créer TGW Route Tables par environnement:",
            "   # Production RT:",
            "   aws ec2 create-transit-gateway-route-table \\",
            "     --transit-gateway-id tgw-xxxxx \\",
            "     --tag-specifications 'ResourceType=transit-gateway-route-table,Tags=[{Key=Name,Value=Production-RT},{Key=Environment,Value=production}]'",
            "",
            "   # Non-Production RT:",
            "   aws ec2 create-transit-gateway-route-table \\",
            "     --transit-gateway-id tgw-xxxxx \\",
            "     --tag-specifications 'ResourceType=transit-gateway-route-table,Tags=[{Key=Name,Value=NonProd-RT},{Key=Environment,Value=non-production}]'",
            "",
            "   # Shared Services RT:",
            "   aws ec2 create-transit-gateway-route-table \\",
            "     --transit-gateway-id tgw-xxxxx \\",
            "     --tag-specifications 'ResourceType=transit-gateway-route-table,Tags=[{Key=Name,Value=SharedServices-RT}]'",
            "",
            "3. Créer VPC attachments:",
            "   aws ec2 create-transit-gateway-vpc-attachment \\",
            "     --transit-gateway-id tgw-xxxxx \\",
            "     --vpc-id vpc-prod-xxxxx \\",
            "     --subnet-ids subnet-1 subnet-2 subnet-3 \\",
            "     --tag-specifications 'ResourceType=transit-gateway-attachment,Tags=[{Key=Name,Value=Production-VPC}]'",
            "",
            "   # Répéter pour chaque VPC (staging, dev, shared services)",
            "",
            "4. Associer attachments aux route tables appropriées:",
            "   # Production VPC → Production RT:",
            "   aws ec2 associate-transit-gateway-route-table \\",
            "     --transit-gateway-route-table-id tgw-rtb-prod \\",
            "     --transit-gateway-attachment-id tgw-attach-prod",
            "",
            "5. Configurer routes dans TGW Route Tables:",
            "   # Dans Production RT: route vers Shared Services:",
            "   aws ec2 create-transit-gateway-route \\",
            "     --destination-cidr-block 10.0.0.0/16 \\",  # Shared Services VPC CIDR",
            "     --transit-gateway-route-table-id tgw-rtb-prod \\",
            "     --transit-gateway-attachment-id tgw-attach-shared",
            "",
            "   # Dans Shared Services RT: routes vers Production ET NonProd:",
            "   aws ec2 create-transit-gateway-route \\",
            "     --destination-cidr-block 10.1.0.0/16 \\",  # Production VPC",
            "     --transit-gateway-route-table-id tgw-rtb-shared \\",
            "     --transit-gateway-attachment-id tgw-attach-prod",
            "",
            "   aws ec2 create-transit-gateway-route \\",
            "     --destination-cidr-block 10.2.0.0/16 \\",  # Dev VPC",
            "     --transit-gateway-route-table-id tgw-rtb-shared \\",
            "     --transit-gateway-attachment-id tgw-attach-dev",
            "",
            "   # PAS de route entre Production RT et NonProd RT (isolation)",
            "",
            "6. Mettre à jour VPC route tables:",
            "   # Dans VPC Production subnets:",
            "   aws ec2 create-route \\",
            "     --route-table-id rtb-prod-private \\",
            "     --destination-cidr-block 10.0.0.0/8 \\",  # Tous internal",
            "     --transit-gateway-id tgw-xxxxx",
            "",
            "7. Partager TGW avec autres comptes (RAM):",
            "   aws ram create-resource-share \\",
            "     --name TGW-Share \\",
            "     --resource-arns arn:aws:ec2:region:account:transit-gateway/tgw-xxxxx \\",
            "     --principals arn:aws:organizations::account:organization/o-xxxxx",
            "",
            "8. Activer TGW Flow Logs:",
            "   aws ec2 create-flow-logs \\",
            "     --resource-type TransitGateway \\",
            "     --resource-ids tgw-xxxxx \\",
            "     --traffic-type ALL \\",
            "     --log-destination-type s3 \\",
            "     --log-destination arn:aws:s3:::tgw-flow-logs",
            "",
            "9. Monitoring CloudWatch:",
            "   aws cloudwatch put-metric-alarm \\",
            "     --alarm-name TGW-PacketDrops \\",
            "     --metric-name PacketDropCountBlackhole \\",
            "     --namespace AWS/TransitGateway \\",
            "     --statistic Sum \\",
            "     --period 300 \\",
            "     --evaluation-periods 2 \\",
            "     --threshold 100 \\",
            "     --comparison-operator GreaterThanThreshold"
        ],
        verification_steps=[
            "Lister Transit Gateways:",
            "  aws ec2 describe-transit-gateways --query 'TransitGateways[].[TransitGatewayId,State,Options]'",
            "",
            "Lister TGW Route Tables:",
            "  aws ec2 describe-transit-gateway-route-tables --query 'TransitGatewayRouteTables[].[TransitGatewayRouteTableId,Tags[?Key==`Name`].Value|[0]]'",
            "",
            "Vérifier associations (VPC attachments → Route Tables):",
            "  aws ec2 get-transit-gateway-route-table-associations --transit-gateway-route-table-id tgw-rtb-xxxxx",
            "",
            "Vérifier routes dans chaque RT:",
            "  aws ec2 search-transit-gateway-routes \\",
            "    --transit-gateway-route-table-id tgw-rtb-prod \\",
            "    --filters Name=state,Values=active",
            "",
            "Test isolation: depuis instance Production, ping instance Dev:",
            "  ping 10.2.1.10  # Dev instance IP",
            "  # Expected: timeout (pas de route Production → Dev)",
            "",
            "Test Shared Services access: depuis Production, ping Shared:",
            "  ping 10.0.1.10  # Shared Services instance",
            "  # Expected: success",
            "",
            "Vérifier VPC Flow Logs capture TGW traffic:",
            "  aws logs filter-log-events --log-group-name /aws/tgw/tgw-xxxxx --filter-pattern '[version, account, interface, srcaddr, dstaddr]' --max-items 10",
            "",
            "CloudWatch metrics - vérifier pas de packet drops anormaux:",
            "  aws cloudwatch get-metric-statistics \\",
            "    --namespace AWS/TransitGateway \\",
            "    --metric-name PacketDropCountBlackhole \\",
            "    --dimensions Name=TransitGateway,Value=tgw-xxxxx \\",
            "    --start-time 2024-01-01T00:00:00Z \\",
            "    --end-time 2024-01-02T00:00:00Z \\",
            "    --period 3600 \\",
            "    --statistics Sum",
            "",
            "Visualiser topology (TGW Network Manager):",
            "  Console: VPC → Transit Gateway Network Manager → Network topology"
        ],
        references=[
            "https://docs.aws.amazon.com/vpc/latest/tgw/what-is-transit-gateway.html",
            "https://docs.aws.amazon.com/vpc/latest/tgw/tgw-route-tables.html",
            "https://aws.amazon.com/blogs/networking-and-content-delivery/creating-a-single-internet-exit-point-from-multiple-vpcs-using-aws-transit-gateway/"
        ]
    ),

    Question(
        id="VPC-009",
        question="AWS PrivateLink utilisé pour exposition sécurisée de services sans Internet/peering/transit gateway?",
        description="Vérifier que PrivateLink (VPC Endpoint Services) est utilisé pour partager services entre VPCs/comptes de manière privée sans exposer sur Internet",
        severity="MEDIUM",
        category="VPC",
        compliance=["Zero Trust", "AWS Well-Architected", "Data Privacy"],
        technical_details="""
        AWS PrivateLink = private connectivity entre VPCs/services

        Architecture:
        - Service Provider: expose service via Endpoint Service (NLB)
        - Service Consumer: accède via Interface Endpoint (ENI privée)
        - Trafic reste sur réseau AWS privé
        - Pas de VPC peering/TGW/Internet requis

        Avantages vs alternatives:
        1. vs VPC Peering:
           - Pas d'overlap CIDR issues
           - Pas de transitive routing risk
           - Granular access (service-level, pas VPC entier)
           - Scaling: 1000s consumers possible

        2. vs Internet:
           - Pas d'exposition publique
           - Pas de IGW/NAT Gateway requis
           - Latence réduite
           - Pas de data transfer OUT charges

        3. vs Transit Gateway:
           - Isolation forte (consumer voit seulement endpoint)
           - Pas de routing visibility entre VPCs
           - Coût: pas de TGW attachment fees

        Use cases:
        - SaaS provider → clients (multi-tenant)
        - Shared services: auth, logging, monitoring
        - API exposure entre business units
        - Marketplace services
        - Partner integration

        PrivateLink pricing:
        - Endpoint Service (provider): gratuit
        - Interface Endpoint (consumer): $0.01/hour + $0.01/GB
        - NLB requis (provider): $0.0225/hour + LCU charges

        Security:
        - Endpoint policy: IAM-like control sur actions
        - Security Group sur ENI endpoint
        - NLB security: listener rules, target health
        - Private DNS: auto-resolve to endpoint IP

        Multi-account/cross-region:
        - Cross-account: via principal whitelist
        - Cross-region: pas supporté directly (use proxy ou TGW)
        - AWS Organizations integration

        Monitoring:
        - CloudWatch metrics: ActiveConnections, ProcessedBytes
        - VPC Flow Logs: voir trafic endpoint
        - NLB access logs
        """,
        remediation=[
            "Côté Service Provider:",
            "",
            "1. Créer Network Load Balancer:",
            "   aws elbv2 create-load-balancer \\",
            "     --name my-service-nlb \\",
            "     --type network \\",
            "     --scheme internal \\",  # IMPORTANT: internal",
            "     --subnets subnet-1 subnet-2 subnet-3 \\",
            "     --tags Key=Name,Value=PrivateLink-NLB",
            "",
            "2. Créer Target Group et enregistrer targets:",
            "   aws elbv2 create-target-group \\",
            "     --name my-service-targets \\",
            "     --protocol TCP \\",
            "     --port 443 \\",
            "     --vpc-id vpc-xxxxx \\",
            "     --target-type instance  # ou ip, lambda",
            "",
            "   aws elbv2 register-targets \\",
            "     --target-group-arn <arn> \\",
            "     --targets Id=i-instance1 Id=i-instance2",
            "",
            "3. Créer VPC Endpoint Service:",
            "   aws ec2 create-vpc-endpoint-service-configuration \\",
            "     --network-load-balancer-arns arn:aws:elasticloadbalancing:region:account:loadbalancer/net/my-service-nlb/xxxxx \\",
            "     --acceptance-required  # Require manual approval",
            "",
            "   # Si acceptation automatique:",
            "   aws ec2 create-vpc-endpoint-service-configuration \\",
            "     --network-load-balancer-arns <nlb-arn> \\",
            "     --no-acceptance-required",
            "",
            "4. Whitelister principals consumers (comptes/roles autorisés):",
            "   aws ec2 modify-vpc-endpoint-service-permissions \\",
            "     --service-id vpce-svc-xxxxx \\",
            "     --add-allowed-principals arn:aws:iam::CONSUMER-ACCOUNT:root",
            "",
            "   # Ou utiliser Organizations:",
            "   aws ec2 modify-vpc-endpoint-service-permissions \\",
            "     --service-id vpce-svc-xxxxx \\",
            "     --add-allowed-principals arn:aws:iam::CONSUMER-ACCOUNT:root",
            "",
            "5. Activer Private DNS (optionnel):",
            "   aws ec2 modify-vpc-endpoint-service-configuration \\",
            "     --service-id vpce-svc-xxxxx \\",
            "     --private-dns-name api.myservice.com",
            "   # Nécessite validation DNS (TXT record)",
            "",
            "Côté Service Consumer:",
            "",
            "6. Créer Interface Endpoint vers service:",
            "   aws ec2 create-vpc-endpoint \\",
            "     --vpc-id vpc-consumer-xxxxx \\",
            "     --vpc-endpoint-type Interface \\",
            "     --service-name com.amazonaws.vpce.region.vpce-svc-xxxxx \\",  # Provider service name",
            "     --subnet-ids subnet-1 subnet-2 \\",
            "     --security-group-ids sg-xxxxx",
            "",
            "7. Configurer Security Group pour endpoint:",
            "   aws ec2 authorize-security-group-ingress \\",
            "     --group-id sg-endpoint \\",
            "     --protocol tcp \\",
            "     --port 443 \\",
            "     --source-group sg-app-instances  # SG des consumers",
            "",
            "8. Créer Endpoint Policy (optionnel - contrôle IAM-like):",
            "   endpoint-policy.json:",
            "   {",
            '     "Statement": [{',
            '       "Effect": "Allow",',
            '       "Principal": "*",',
            '       "Action": "elasticloadbalancing:*",',
            '       "Resource": "*"',
            "     }]",
            "   }",
            "",
            "   aws ec2 modify-vpc-endpoint \\",
            "     --vpc-endpoint-id vpce-xxxxx \\",
            "     --policy-document file://endpoint-policy.json",
            "",
            "9. Activer Private DNS pour endpoint:",
            "   aws ec2 modify-vpc-endpoint \\",
            "     --vpc-endpoint-id vpce-xxxxx \\",
            "     --private-dns-enabled",
            "",
            "10. Test connexion depuis consumer VPC:",
            "    # Récupérer endpoint DNS:",
            "    aws ec2 describe-vpc-endpoints --vpc-endpoint-ids vpce-xxxxx --query 'VpcEndpoints[].DnsEntries'",
            "",
            "    # Test:",
            "    curl https://vpce-xxxxx-yyyyy.vpce-svc-zzzzz.region.vpce.amazonaws.com",
            "    # Ou si Private DNS activé:",
            "    curl https://api.myservice.com"
        ],
        verification_steps=[
            "Provider: lister Endpoint Services:",
            "  aws ec2 describe-vpc-endpoint-service-configurations",
            "",
            "Provider: voir consumers connectés:",
            "  aws ec2 describe-vpc-endpoint-connections --filters Name=service-id,Values=vpce-svc-xxxxx",
            "",
            "Provider: accepter pending connections:",
            "  aws ec2 accept-vpc-endpoint-connections --service-id vpce-svc-xxxxx --vpc-endpoint-ids vpce-consumer-xxxxx",
            "",
            "Consumer: lister endpoints:",
            "  aws ec2 describe-vpc-endpoints --filters Name=service-name,Values=com.amazonaws.vpce.*",
            "",
            "Consumer: vérifier état endpoint:",
            "  aws ec2 describe-vpc-endpoints --vpc-endpoint-ids vpce-xxxxx --query 'VpcEndpoints[].[VpcEndpointId,State,ServiceName]'",
            "  # Expected State: available",
            "",
            "Tester résolution DNS (si Private DNS activé):",
            "  nslookup api.myservice.com",
            "  # Devrait résoudre en IP privée VPC (dans 10.0.0.0/8 range)",
            "",
            "Tester connectivité depuis consumer:",
            "  # Depuis instance dans consumer VPC:",
            "  curl -v https://vpce-xxxxx.vpce-svc-yyyyy.region.vpce.amazonaws.com/health",
            "  # Expected: HTTP 200 OK",
            "",
            "Vérifier Security Group endpoint autorise trafic:",
            "  aws ec2 describe-security-groups --group-ids sg-endpoint --query 'SecurityGroups[].IpPermissions'",
            "",
            "VPC Flow Logs: voir trafic vers endpoint:",
            "  aws logs filter-log-events --log-group-name /aws/vpc/flowlogs --filter-pattern 'vpce-xxxxx' --max-items 20",
            "",
            "CloudWatch metrics - connexions actives:",
            "  aws cloudwatch get-metric-statistics \\",
            "    --namespace AWS/PrivateLinkEndpoints \\",
            "    --metric-name ActiveConnections \\",
            "    --dimensions Name=Endpoint,Value=vpce-xxxxx \\",
            "    --start-time 2024-01-01T00:00:00Z \\",
            "    --end-time 2024-01-02T00:00:00Z \\",
            "    --period 3600 \\",
            "    --statistics Average"
        ],
        references=[
            "https://docs.aws.amazon.com/vpc/latest/privatelink/what-is-privatelink.html",
            "https://docs.aws.amazon.com/vpc/latest/privatelink/create-endpoint-service.html",
            "https://aws.amazon.com/blogs/networking-and-content-delivery/how-to-securely-publish-internet-applications-at-scale-using-application-load-balancer-and-aws-privatelink/"
        ]
    ),

    Question(
        id="VPC-010",
        question="DNS security: Route 53 Resolver avec DNS Firewall pour bloquer domaines malveillants et DNSSEC validation?",
        description="Vérifier que Route 53 Resolver DNS Firewall est configuré pour bloquer queries vers domaines malveillants et que DNSSEC validation est activée",
        severity="MEDIUM",
        category="VPC",
        compliance=["Zero Trust", "Threat Protection", "CIS Benchmark"],
        technical_details="""
        DNS = vecteur d'attaque commun

        Menaces DNS:
        - Exfiltration via DNS tunneling
        - C2 communication (malware beacon)
        - Phishing domains
        - Cryptomining domains
        - DGA (Domain Generation Algorithm) domains
        - DNS cache poisoning

        Route 53 Resolver DNS Firewall:
        - Filtrage queries DNS sortantes depuis VPC
        - Blocklists/allowlists de domaines
        - Intégration threat intelligence (AWS-managed lists)
        - Response: NODATA, NXDOMAIN, override IP
        - Logging vers S3/CloudWatch/Kinesis Firehose

        AWS-managed domain lists:
        - AWSManagedDomainsMalwareDomainList
        - AWSManagedDomainsBotnetCommandandControl
        - Régulièrement updated par AWS threat intel

        DNSSEC (DNS Security Extensions):
        - Validation signatures cryptographiques
        - Protection contre cache poisoning
        - Garantie authenticité réponses DNS
        - Activation via Route 53 Resolver

        Route 53 Resolver:
        - Default VPC DNS (Amazon-provided)
        - Resolver endpoints: hybrid DNS (on-prem ↔ AWS)
        - Inbound endpoint: on-prem query AWS Route 53
        - Outbound endpoint: AWS query on-prem DNS
        - Query logging: audit toutes DNS queries

        Architecture DNS sécurisée:
        1. Route 53 private hosted zones (internes)
        2. Resolver DNS Firewall (filtrage sortant)
        3. Resolver query logging (audit)
        4. DNSSEC validation (authenticité)
        5. Resolver endpoints si hybrid (on-prem)

        Use cases:
        - Bloquer accès à domaines malware connus
        - Empêcher DNS tunneling exfiltration
        - Compliance: logs de toutes DNS queries
        - Threat detection: alertes sur queries suspectes
        """,
        remediation=[
            "1. Activer Route 53 Resolver query logging:",
            "   # Créer CloudWatch Log Group:",
            "   aws logs create-log-group --log-group-name /aws/route53/resolver-queries",
            "",
            "   # Créer Resolver query log config:",
            "   aws route53resolver create-resolver-query-log-config \\",
            "     --name vpc-dns-logs \\",
            "     --destination-arn arn:aws:logs:region:account:log-group:/aws/route53/resolver-queries",
            "",
            "   # Associer au VPC:",
            "   aws route53resolver associate-resolver-query-log-config \\",
            "     --resolver-query-log-config-id rqlc-xxxxx \\",
            "     --resource-id vpc-xxxxx",
            "",
            "2. Créer DNS Firewall rule group (AWS-managed lists):",
            "   aws route53resolver create-firewall-rule-group \\",
            "     --name corporate-dns-firewall \\",
            "     --tags Key=Environment,Value=production",
            "",
            "3. Ajouter rule avec AWS-managed malware list:",
            "   aws route53resolver create-firewall-rule \\",
            "     --firewall-rule-group-id frg-xxxxx \\",
            "     --firewall-domain-list-id arn:aws:route53resolver:region:aws:firewall-domain-list/rslvr-fdl-AWSManagedDomainsMalwareDomainList \\",
            "     --priority 100 \\",
            "     --action BLOCK \\",
            "     --block-response NXDOMAIN \\",
            "     --name block-malware",
            "",
            "4. Ajouter rule avec botnet C2 list:",
            "   aws route53resolver create-firewall-rule \\",
            "     --firewall-rule-group-id frg-xxxxx \\",
            "     --firewall-domain-list-id arn:aws:route53resolver:region:aws:firewall-domain-list/rslvr-fdl-AWSManagedDomainsBotnetCommandandControl \\",
            "     --priority 101 \\",
            "     --action BLOCK \\",
            "     --block-response NXDOMAIN \\",
            "     --name block-botnet-c2",
            "",
            "5. Créer custom domain list (allowlist corporate domains):",
            "   # Créer fichier domains.txt:",
            "   # *.mycompany.com",
            "   # *.aws.amazon.com",
            "   # *.microsoft.com",
            "",
            "   aws route53resolver create-firewall-domain-list \\",
            "     --name corporate-allowlist \\",
            "     --domains file://domains.txt",
            "",
            "   # Ajouter rule ALLOW avec haute priorité:",
            "   aws route53resolver create-firewall-rule \\",
            "     --firewall-rule-group-id frg-xxxxx \\",
            "     --firewall-domain-list-id fdl-custom-xxxxx \\",
            "     --priority 50 \\",  # Avant blocklists",
            "     --action ALLOW \\",
            "     --name allow-corporate",
            "",
            "6. Associer firewall rule group au VPC:",
            "   aws route53resolver associate-firewall-rule-group \\",
            "     --firewall-rule-group-id frg-xxxxx \\",
            "     --vpc-id vpc-xxxxx \\",
            "     --priority 100 \\",  # Multiple rule groups possible",
            "     --name production-vpc-firewall",
            "",
            "7. Activer DNSSEC validation:",
            "   # Via VPC DHCP Options Set:",
            "   aws ec2 create-dhcp-options \\",
            "     --dhcp-configurations 'Key=domain-name-servers,Values=AmazonProvidedDNS' \\",
            "     --tag-specifications 'ResourceType=dhcp-options,Tags=[{Key=Name,Value=DNSSEC-enabled}]'",
            "",
            "   # Associer au VPC:",
            "   aws ec2 associate-dhcp-options --dhcp-options-id dopt-xxxxx --vpc-id vpc-xxxxx",
            "",
            "   # Note: DNSSEC validation automatique si utilisant Amazon-provided DNS",
            "",
            "8. Créer CloudWatch alarms sur queries bloquées:",
            "   aws cloudwatch put-metric-alarm \\",
            "     --alarm-name DNS-Firewall-Blocks \\",
            "     --metric-name BlockedQueries \\",
            "     --namespace AWS/Route53Resolver \\",
            "     --statistic Sum \\",
            "     --period 300 \\",
            "     --evaluation-periods 1 \\",
            "     --threshold 10 \\",
            "     --comparison-operator GreaterThanThreshold \\",
            "     --dimensions Name=FirewallRuleGroupId,Value=frg-xxxxx \\",
            "     --alarm-actions arn:aws:sns:region:account:security-alerts",
            "",
            "9. Analyser logs pour détection threats:",
            "   # CloudWatch Logs Insights query:",
            "   # fields @timestamp, query_name, query_type, rcode, firewall_rule_action",
            "   # | filter firewall_rule_action = 'BLOCK'",
            "   # | stats count() by query_name",
            "   # | sort count desc",
            "",
            "10. (Optionnel) Créer Resolver endpoints pour hybrid:",
            "    # Inbound endpoint (on-prem → AWS):",
            "    aws route53resolver create-resolver-endpoint \\",
            "      --creator-request-id $(uuidgen) \\",
            "      --security-group-ids sg-xxxxx \\",
            "      --direction INBOUND \\",
            "      --ip-addresses SubnetId=subnet-1,Ip=10.0.1.10 SubnetId=subnet-2,Ip=10.0.2.10",
            "",
            "    # Outbound endpoint (AWS → on-prem):",
            "    aws route53resolver create-resolver-endpoint \\",
            "      --creator-request-id $(uuidgen) \\",
            "      --security-group-ids sg-xxxxx \\",
            "      --direction OUTBOUND \\",
            "      --ip-addresses SubnetId=subnet-1 SubnetId=subnet-2"
        ],
        verification_steps=[
            "Vérifier query logging configuré:",
            "  aws route53resolver list-resolver-query-log-configs",
            "  aws route53resolver list-resolver-query-log-config-associations --filters Name=ResourceId,Values=vpc-xxxxx",
            "",
            "Vérifier DNS Firewall associations:",
            "  aws route53resolver list-firewall-rule-group-associations --vpc-id vpc-xxxxx",
            "",
            "Lister firewall rules:",
            "  aws route53resolver list-firewall-rules --firewall-rule-group-id frg-xxxxx",
            "",
            "Vérifier AWS-managed lists actives:",
            "  aws route53resolver list-firewall-domain-lists --query 'FirewallDomainLists[?ManagedOwnerName==`Route 53 Resolver DNS Firewall`]'",
            "",
            "Test blocage domaine malveillant (depuis instance VPC):",
            "  # Tester query vers domaine dans blocklist:",
            "  nslookup malicious-test-domain.example.com",
            "  # Expected: NXDOMAIN ou NODATA",
            "",
            "  dig malicious-test-domain.example.com",
            "  # Expected: status NXDOMAIN",
            "",
            "Test allowlist corporate domain:",
            "  nslookup myapp.mycompany.com",
            "  # Expected: normal resolution",
            "",
            "Analyser query logs:",
            "  aws logs tail /aws/route53/resolver-queries --follow",
            "  # Chercher: firewall_rule_action = BLOCK",
            "",
            "CloudWatch Insights - top blocked domains:",
            "  Query:",
            "  fields @timestamp, query_name",
            "  | filter firewall_rule_action = 'BLOCK'",
            "  | stats count() by query_name as blocks",
            "  | sort blocks desc",
            "  | limit 20",
            "",
            "Vérifier DNSSEC validation:",
            "  dig +dnssec example.com",
            "  # Doit montrer flags: ad (authenticated data)",
            "",
            "Metrics CloudWatch - queries bloquées:",
            "  aws cloudwatch get-metric-statistics \\",
            "    --namespace AWS/Route53Resolver \\",
            "    --metric-name BlockedQueries \\",
            "    --dimensions Name=FirewallRuleGroupId,Value=frg-xxxxx \\",
            "    --start-time 2024-01-01T00:00:00Z \\",
            "    --end-time 2024-01-02T00:00:00Z \\",
            "    --period 3600 \\",
            "    --statistics Sum",
            "",
            "Vérifier resolver endpoints (si hybrid):",
            "  aws route53resolver list-resolver-endpoints"
        ],
        references=[
            "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall.html",
            "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html",
            "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dnssec-validation.html",
            "https://aws.amazon.com/blogs/security/how-to-protect-your-company-from-dns-based-threats-using-route-53-resolver-dns-firewall/"
        ]
    )
]

# ==================== EC2 & COMPUTE ====================
EC2_QUESTIONS = [
    Question(
        id="EC2-001",
        question="IMDSv2 obligatoire sur toutes les instances EC2 pour prévenir SSRF et vol de credentials?",
        description="Instance Metadata Service v2 avec session tokens obligatoire pour prévenir les attaques SSRF permettant de voler les credentials IAM",
        severity="CRITICAL",
        category="EC2",
        compliance=["CIS Benchmark", "AWS Well-Architected", "NIST"],
        technical_details="""
        Vulnérabilité IMDSv1:
        - Accessible via simple HTTP GET sans authentification
        - Exploitable via SSRF (Server-Side Request Forgery)
        - Permet vol de credentials IAM role de l'instance
        - Exemple exploit: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

        IMDSv2 (Token-based):
        - Nécessite PUT request pour obtenir token session
        - Token avec TTL configurable (1-6 heures)
        - Hop limit = 1 (bloque forwarding via NAT/Proxy)
        - Protection contre SSRF car attaquant ne peut pas faire PUT via SSRF

        Metadata exposées (sensibles):
        - IAM role credentials (temporary)
        - User data (peut contenir secrets)
        - Security credentials
        - Network configuration

        Configuration IMDSv2:
        - HttpTokens: required (force v2)
        - HttpPutResponseHopLimit: 1 (empêche proxying)
        - HttpEndpoint: enabled
        - InstanceMetadataTags: enabled (optionnel)
        """,
        remediation=[
            "Pour nouvelles instances, exiger IMDSv2 dans launch template:",
            "  MetadataOptions:",
            "    HttpTokens: required",
            "    HttpPutResponseHopLimit: 1",
            "    HttpEndpoint: enabled",
            "",
            "Pour instances existantes:",
            "  aws ec2 modify-instance-metadata-options \\",
            "    --instance-id i-xxxxx \\",
            "    --http-tokens required \\",
            "    --http-put-response-hop-limit 1",
            "",
            "Identifier instances avec IMDSv1:",
            "  aws ec2 describe-instances \\",
            "    --query 'Reservations[].Instances[?MetadataOptions.HttpTokens==`optional`].[InstanceId,Tags[?Key==`Name`].Value|[0]]'",
            "",
            "Créer SCP pour bloquer lancement instances sans IMDSv2:",
            '  {"Effect": "Deny",',
            '   "Action": "ec2:RunInstances",',
            '   "Resource": "arn:aws:ec2:*:*:instance/*",',
            '   "Condition": {',
            '     "StringNotEquals": {"ec2:MetadataHttpTokens": "required"}',
            '   }}',
            "",
            "Automatiser: AWS Config rule imds-v2-enabled"
        ],
        verification_steps=[
            "aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,MetadataOptions.HttpTokens,MetadataOptions.HttpPutResponseHopLimit]' --output table",
            "Vérifier HttpTokens = required pour toutes instances",
            "Vérifier HttpPutResponseHopLimit = 1",
            "Test depuis instance:",
            "  # V1 (should fail):",
            "  curl http://169.254.169.254/latest/meta-data/",
            "  # V2 (should work):",
            "  TOKEN=$(curl -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')",
            "  curl -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/",
            "Config rule: aws configservice describe-compliance-by-config-rule --config-rule-names imds-v2-enabled"
        ],
        references=[
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
            "https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/"
        ]
    ),

    Question(
        id="EC2-002",
        question="Chiffrement des volumes EBS activé par défaut et chiffrement en transit pour EBS optimized?",
        description="Vérifier que tous les volumes EBS sont chiffrés avec KMS et que le chiffrement EBS-optimized est activé pour données en transit",
        severity="CRITICAL",
        category="EC2",
        compliance=["PCI-DSS", "HIPAA", "GDPR", "ISO 27001"],
        technical_details="""
        EBS Encryption at rest:
        - Utilise AES-256
        - Transparent (pas d'impact performance)
        - Chiffrement data blocks, snapshots, volumes créés depuis snapshots
        - Clé KMS par défaut ou customer-managed key

        EBS Encryption in transit:
        - EBS-optimized instances: dedicated bandwidth
        - Chiffrement data entre instance et volumes EBS
        - Pas de configuration supplémentaire si EBS-optimized

        Types de volumes:
        - gp3/gp2: General Purpose SSD
        - io2/io1: Provisioned IOPS SSD
        - st1: Throughput Optimized HDD
        - sc1: Cold HDD

        Activation chiffrement par défaut:
        - Au niveau région
        - Tous nouveaux volumes automatiquement chiffrés
        - Ne chiffre pas volumes existants

        Snapshots:
        - Snapshots de volumes chiffrés sont chiffrés
        - Snapshots non chiffrés peuvent être copiés avec chiffrement
        - Partage snapshots: attention aux clés KMS
        """,
        remediation=[
            "Activer encryption by default par région:",
            "  aws ec2 enable-ebs-encryption-by-default --region <region>",
            "",
            "Vérifier status:",
            "  aws ec2 get-ebs-encryption-by-default --region <region>",
            "",
            "Définir KMS key par défaut:",
            "  aws ec2 modify-ebs-default-kms-key-id --kms-key-id <key-arn>",
            "",
            "Chiffrer volumes existants non chiffrés:",
            "  1. Créer snapshot du volume",
            "  2. Copier snapshot avec encryption:",
            "     aws ec2 copy-snapshot --source-snapshot-id snap-xxxxx --encrypted --kms-key-id <key-id>",
            "  3. Créer volume depuis snapshot chiffré",
            "  4. Attacher nouveau volume, détacher ancien",
            "",
            "Identifier volumes non chiffrés:",
            "  aws ec2 describe-volumes --query 'Volumes[?Encrypted==`false`].[VolumeId,Size,State,Attachments[0].InstanceId]' --output table",
            "",
            "Créer AWS Config rule: encrypted-volumes",
            "",
            "SCP pour bloquer création volumes non chiffrés:",
            '  {"Effect": "Deny",',
            '   "Action": ["ec2:CreateVolume", "ec2:RunInstances"],',
            '   "Condition": {"Bool": {"ec2:Encrypted": "false"}}}'
        ],
        verification_steps=[
            "aws ec2 get-ebs-encryption-by-default --region <region>",
            "aws ec2 get-ebs-default-kms-key-id --region <region>",
            "aws ec2 describe-volumes --filters Name=encrypted,Values=false",
            "aws ec2 describe-snapshots --owner-ids self --filters Name=encrypted,Values=false",
            "Vérifier aucun volume/snapshot non chiffré",
            "Pour instances: vérifier EbsOptimized = true:",
            "  aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,InstanceType,EbsOptimized]' --output table"
        ],
        references=[
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-optimized.html"
        ]
    ),

    Question(
        id="EC2-003",
        question="Systems Manager Session Manager utilisé au lieu de SSH/RDP avec bastion host?",
        description="Vérifier que l'accès aux instances utilise SSM Session Manager éliminant besoin de SSH keys, bastions, et Security Groups ouverts",
        severity="HIGH",
        category="EC2",
        compliance=["CIS Benchmark", "Zero Trust", "AWS Well-Architected"],
        technical_details="""
        Avantages Session Manager vs SSH:
        - Pas de clés SSH à gérer/distribuer
        - Pas de bastion host à maintenir
        - Pas de ports SSH/RDP ouverts (Security Groups)
        - Logging centralisé dans CloudTrail
        - Enregistrement sessions (audit trail)
        - IAM-based access control
        - MFA support via IAM
        - Port forwarding sécurisé
        - Connexion via console ou CLI

        Architecture:
        - Instance ← SSM Agent → SSM Service ← IAM Policy ← User
        - Communication via HTTPS (443)
        - Pas de inbound ports ouverts

        Prérequis:
        - SSM Agent installé (pré-installé AMIs récentes)
        - IAM role sur instance avec AmazonSSMManagedInstanceCore
        - Connectivité: Internet ou VPC Endpoints (ssm, ssmmessages, ec2messages)
        - IAM permissions user: ssm:StartSession

        Features additionnelles:
        - Run Command: exécution commandes à distance
        - Patch Manager: gestion patches OS
        - State Manager: configuration management
        - Port forwarding: tunnel SSH/RDP si vraiment nécessaire
        - Session recording: enregistrement complet sessions
        """,
        remediation=[
            "1. Installer SSM Agent si absent:",
            "   # Amazon Linux 2 / Ubuntu (pré-installé sur AMIs récentes)",
            "   sudo yum install -y amazon-ssm-agent  # AL2",
            "   sudo systemctl enable amazon-ssm-agent",
            "   sudo systemctl start amazon-ssm-agent",
            "",
            "2. Créer IAM role pour instances:",
            "   aws iam create-role --role-name EC2-SSM-Role \\",
            "     --assume-role-policy-document '{",
            '       "Version": "2012-10-17",',
            '       "Statement": [{"Effect": "Allow",',
            '         "Principal": {"Service": "ec2.amazonaws.com"},',
            '         "Action": "sts:AssumeRole"}]}\'',
            "",
            "3. Attacher managed policy:",
            "   aws iam attach-role-policy --role-name EC2-SSM-Role \\",
            "     --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
            "",
            "4. Créer instance profile et associer:",
            "   aws iam create-instance-profile --instance-profile-name EC2-SSM-Profile",
            "   aws iam add-role-to-instance-profile --instance-profile-name EC2-SSM-Profile --role-name EC2-SSM-Role",
            "   aws ec2 associate-iam-instance-profile --instance-id i-xxxxx --iam-instance-profile Name=EC2-SSM-Profile",
            "",
            "5. Créer VPC Endpoints (si pas d'Internet Gateway):",
            "   aws ec2 create-vpc-endpoint --vpc-id vpc-xxxxx --service-name com.amazonaws.<region>.ssm",
            "   aws ec2 create-vpc-endpoint --vpc-id vpc-xxxxx --service-name com.amazonaws.<region>.ssmmessages",
            "   aws ec2 create-vpc-endpoint --vpc-id vpc-xxxxx --service-name com.amazonaws.<region>.ec2messages",
            "",
            "6. Donner permissions IAM users:",
            "   Policy: ssm:StartSession sur arn:aws:ec2:region:account:instance/*",
            "",
            "7. Activer session logging:",
            "   aws ssm create-document --name SessionManagerSettings --document-type Session \\",
            "     --content file://session-preferences.json",
            "",
            "8. Fermer ports SSH/RDP dans Security Groups"
        ],
        verification_steps=[
            "Lister instances managed:",
            "  aws ssm describe-instance-information --query 'InstanceInformationList[].[InstanceId,PingStatus,PlatformName,AgentVersion]' --output table",
            "",
            "Vérifier instance accessible:",
            "  aws ssm start-session --target i-xxxxx",
            "",
            "Vérifier IAM role attaché:",
            "  aws ec2 describe-instances --instance-ids i-xxxxx --query 'Reservations[].Instances[].IamInstanceProfile'",
            "",
            "Vérifier SSM Agent status:",
            "  sudo systemctl status amazon-ssm-agent",
            "",
            "Vérifier Security Groups ne contiennent pas SSH/RDP ouvert:",
            "  aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?(FromPort==`22` || FromPort==`3389`) && IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName]'",
            "",
            "Audit logs:",
            "  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=StartSession"
        ],
        references=[
            "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html",
            "https://aws.amazon.com/blogs/mt/vpc-endpoints-for-ssm-and-session-manager/"
        ]
    ),

    Question(
        id="EC2-004",
        question="Patch management avec Systems Manager Patch Manager: baseline et compliance tracking?",
        description="Vérifier qu'un processus automatisé de patching existe via SSM Patch Manager avec baselines et reporting de compliance",
        severity="HIGH",
        category="EC2",
        compliance=["PCI-DSS", "HIPAA", "ISO 27001", "SOC2"],
        technical_details="""
        Patch Manager capabilities:
        - Patch baselines: définit quels patches installer
        - Patch groups: catégorisation instances
        - Maintenance windows: fenêtres d'installation
        - Compliance reporting: tracking patch status
        - Pre-defined baselines: AWS-DefaultPatchBaseline
        - Custom baselines: pour règles spécifiques

        Patch baselines:
        - Operating system type (Amazon Linux, Ubuntu, Windows, etc.)
        - Patch classification (Security, Critical, Important, etc.)
        - Patch severity levels
        - Auto-approval delays (ex: 7 jours après release)
        - Approved/rejected patches lists
        - Patch sources (repositories)

        Maintenance windows:
        - Schedule: cron ou rate expression
        - Duration: combien de temps
        - Cutoff: arrêt nouvelles exécutions avant fin
        - Targets: instances par tags
        - Tasks: Run Command documents (AWS-RunPatchBaseline)

        Compliance levels:
        - COMPLIANT: tous patches installés
        - NON_COMPLIANT: patches manquants
        - UNSPECIFIED: pas de data
        - NOT_APPLICABLE: n'a pas tourné

        Integration:
        - CloudWatch Events: alertes non-compliance
        - SNS: notifications
        - S3: export compliance reports
        """,
        remediation=[
            "1. Créer custom patch baseline:",
            "   aws ssm create-patch-baseline \\",
            "     --name 'Production-Baseline' \\",
            "     --operating-system AMAZON_LINUX_2 \\",
            "     --approval-rules file://approval-rules.json \\",
            "     --approved-patches 'CVE-2023-12345,CVE-2023-67890' \\",
            "     --rejected-patches 'KB1234567'",
            "",
            "   approval-rules.json:",
            "   {",
            '     "PatchRules": [{',
            '       "PatchFilterGroup": {',
            '         "PatchFilters": [{',
            '           "Key": "CLASSIFICATION",',
            '           "Values": ["Security", "Critical"]',
            "         }]",
            "       },",
            '       "ComplianceLevel": "CRITICAL",',
            '       "ApproveAfterDays": 7',
            "     }]",
            "   }",
            "",
            "2. Créer patch group et associer baseline:",
            "   # Tag instances:",
            "   aws ec2 create-tags --resources i-xxxxx --tags Key=Patch Group,Value=Production",
            "   # Register patch group:",
            "   aws ssm register-patch-baseline-for-patch-group \\",
            "     --baseline-id pb-xxxxx \\",
            "     --patch-group Production",
            "",
            "3. Créer maintenance window:",
            "   aws ssm create-maintenance-window \\",
            "     --name 'Production-Patching-Window' \\",
            "     --schedule 'cron(0 2 ? * SUN *)' \\",
            "     --duration 4 \\",
            "     --cutoff 1 \\",
            "     --allow-unassociated-targets",
            "",
            "4. Register targets (instances):",
            "   aws ssm register-target-with-maintenance-window \\",
            "     --window-id mw-xxxxx \\",
            "     --target-type INSTANCE \\",
            "     --resource-type INSTANCE \\",
            "     --targets Key=tag:Patch Group,Values=Production",
            "",
            "5. Register task (patch installation):",
            "   aws ssm register-task-with-maintenance-window \\",
            "     --window-id mw-xxxxx \\",
            "     --task-type RUN_COMMAND \\",
            "     --task-arn AWS-RunPatchBaseline \\",
            "     --targets Key=WindowTargetIds,Values=<target-id> \\",
            "     --task-invocation-parameters 'RunCommand={Parameters={Operation=[Install]}}'",
            "",
            "6. Configurer SNS notifications:",
            "   aws ssm update-maintenance-window --window-id mw-xxxxx \\",
            "     --notification-config NotificationArn=arn:aws:sns:region:account:topic,NotificationEvents=[SUCCESS,FAILED]",
            "",
            "7. Scan compliance (sans installer):",
            "   aws ssm send-command \\",
            "     --document-name AWS-RunPatchBaseline \\",
            "     --parameters 'Operation=Scan' \\",
            "     --targets Key=tag:Patch Group,Values=Production"
        ],
        verification_steps=[
            "Lister patch baselines:",
            "  aws ssm describe-patch-baselines",
            "",
            "Voir compliance summary:",
            "  aws ssm describe-patch-group-state --patch-group Production",
            "",
            "Compliance par instance:",
            "  aws ssm list-compliance-items --resource-ids i-xxxxx --resource-types ManagedInstance",
            "",
            "Patches manquants par instance:",
            "  aws ssm describe-instance-patches --instance-id i-xxxxx",
            "",
            "Voir maintenance windows:",
            "  aws ssm describe-maintenance-windows",
            "",
            "Historique exécutions:",
            "  aws ssm describe-maintenance-window-executions --window-id mw-xxxxx",
            "",
            "Dashboard compliance:",
            "  aws ssm list-compliance-summaries",
            "",
            "Export compliance report:",
            "  aws ssm list-resource-compliance-summaries --output json > compliance-report.json"
        ],
        references=[
            "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-patch.html",
            "https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-compliance-about.html"
        ]
    ),

    Question(
        id="EC2-005",
        question="AMI hardening: Golden AMIs avec CIS benchmarks et images builder pipeline automatisé?",
        description="Vérifier existence de processus de création AMI hardened selon CIS benchmarks avec pipeline automatisé EC2 Image Builder",
        severity="HIGH",
        category="EC2",
        compliance=["CIS Benchmark", "NIST", "ISO 27001"],
        technical_details="""
        Golden AMI concept:
        - AMI de base hardened selon security standards
        - Pré-configurée avec:
          * OS patches récents
          * Security agents (AV, HIDS, logging)
          * Hardening configurations
          * Compliance scanning tools
          * Monitoring agents
        - Utilisée comme base pour toutes instances
        - Régulièrement mise à jour (monthly/quarterly)

        CIS Benchmarks applicables:
        - CIS Amazon Linux 2 Benchmark
        - CIS Ubuntu Benchmark
        - CIS Windows Server Benchmark
        - CIS Red Hat Enterprise Linux Benchmark

        Hardenings typiques:
        - Désactiver services inutiles
        - Configurer firewall (iptables/firewalld)
        - SSH hardening (disable root login, key-based only)
        - Audit logging (auditd)
        - Password policies
        - File permissions strictes
        - Remove unnecessary packages
        - Disable USB/CD-ROM mounting
        - AIDE (Advanced Intrusion Detection Environment)

        EC2 Image Builder:
        - Service AWS pour automatiser création/test/distribution AMIs
        - Pipeline définit:
          * Base image (source AMI)
          * Components (scripts hardening)
          * Tests (validation)
          * Distribution (regions, comptes)
        - Scheduling: cron pour rebuild automatique
        - Versioning: tracking des AMI versions

        Components disponibles:
        - AWS-managed: Amazon Linux hardening, CIS benchmarks
        - Custom: scripts bash/PowerShell
        - Test components: validation hardening appliqué

        Workflow:
        1. Source AMI (public AWS ou custom)
        2. Build: application components (hardening)
        3. Test: validation tests components
        4. Distribute: copy vers regions/comptes
        5. Launch permissions: partage contrôlé
        """,
        remediation=[
            "1. Créer Image Builder Pipeline:",
            "",
            "   A. Créer component de hardening CIS:",
            "   aws imagebuilder create-component \\",
            "     --name CIS-Hardening-AL2 \\",
            "     --semantic-version 1.0.0 \\",
            "     --platform Linux \\",
            "     --data file://cis-hardening.yml",
            "",
            "   cis-hardening.yml (example):",
            "   name: CIS Amazon Linux 2 Hardening",
            "   schemaVersion: 1.0",
            "   phases:",
            "     - name: build",
            "       steps:",
            "         - name: DisableRootLogin",
            "           action: ExecuteBash",
            "           inputs:",
            "             commands:",
            "               - sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config",
            "         - name: ConfigureFirewall",
            "           action: ExecuteBash",
            "           inputs:",
            "             commands:",
            "               - yum install -y firewalld",
            "               - systemctl enable firewalld",
            "         - name: InstallSecurityTools",
            "           action: ExecuteBash",
            "           inputs:",
            "             commands:",
            "               - yum install -y aide",
            "               - aide --init",
            "",
            "   B. Créer test component:",
            "   aws imagebuilder create-component \\",
            "     --name CIS-Validation-Tests \\",
            "     --semantic-version 1.0.0 \\",
            "     --platform Linux \\",
            "     --data file://validation-tests.yml",
            "",
            "   C. Créer infrastructure configuration:",
            "   aws imagebuilder create-infrastructure-configuration \\",
            "     --name ImageBuilder-Infra \\",
            "     --instance-types t3.medium \\",
            "     --instance-profile-name ImageBuilderRole \\",
            "     --security-group-ids sg-xxxxx \\",
            "     --subnet-id subnet-xxxxx \\",
            "     --terminate-instance-on-failure",
            "",
            "   D. Créer distribution configuration:",
            "   aws imagebuilder create-distribution-configuration \\",
            "     --name Multi-Region-Distribution \\",
            "     --distributions file://distribution.json",
            "",
            "   distribution.json:",
            "   [{",
            '     "region": "us-east-1",',
            '     "amiDistributionConfiguration": {',
            '       "name": "Golden-AMI-{{imagebuilder:buildDate}}",',
            '       "description": "Hardened AMI CIS Level 1",',
            '       "amiTags": {"CIS": "Level1", "Environment": "Production"},',
            '       "launchPermission": {"userIds": ["123456789012"]}',
            "     }",
            "   }]",
            "",
            "   E. Créer image recipe:",
            "   aws imagebuilder create-image-recipe \\",
            "     --name Golden-AMI-Recipe \\",
            "     --semantic-version 1.0.0 \\",
            "     --parent-image arn:aws:imagebuilder:region:aws:image/amazon-linux-2-x86/x.x.x \\",
            "     --components componentArn=<cis-hardening-arn> \\",
            "     --block-device-mappings file://block-devices.json",
            "",
            "   F. Créer image pipeline:",
            "   aws imagebuilder create-image-pipeline \\",
            "     --name Golden-AMI-Pipeline \\",
            "     --image-recipe-arn <recipe-arn> \\",
            "     --infrastructure-configuration-arn <infra-arn> \\",
            "     --distribution-configuration-arn <distrib-arn> \\",
            "     --image-tests-configuration imageTestsEnabled=true,timeoutMinutes=90 \\",
            "     --schedule 'scheduleExpression=cron(0 0 1 * ? *)'  # Monthly",
            "",
            "2. Déclencher build manuellement:",
            "   aws imagebuilder start-image-pipeline-execution --image-pipeline-arn <arn>",
            "",
            "3. Appliquer tag governance:",
            "   - AMIs doivent être taggées avec version, CIS level, date",
            "   - Deprecate old AMIs après 3 mois",
            "   - Automatiser rotation AMIs utilisées",
            "",
            "4. Documenter baseline configuration:",
            "   - Créer runbook avec toutes hardenings appliquées",
            "   - Maintenir changelog des modifications",
            "   - Scanner régulièrement avec AWS Inspector"
        ],
        verification_steps=[
            "Lister pipelines Image Builder:",
            "  aws imagebuilder list-image-pipelines",
            "",
            "Voir détails pipeline:",
            "  aws imagebuilder get-image-pipeline --image-pipeline-arn <arn>",
            "",
            "Historique builds:",
            "  aws imagebuilder list-image-pipeline-images --image-pipeline-arn <arn>",
            "",
            "Lister AMIs créées:",
            "  aws ec2 describe-images --owners self --filters 'Name=name,Values=Golden-AMI-*'",
            "",
            "Vérifier tags AMI:",
            "  aws ec2 describe-images --image-ids ami-xxxxx --query 'Images[].Tags'",
            "",
            "Test compliance CIS sur AMI:",
            "  # Lancer instance depuis AMI",
            "  # Installer CIS-CAT tool ou OpenSCAP",
            "  # Run assessment:",
            "  oscap xccdf eval --profile cis --results results.xml cis-benchmark.xml",
            "",
            "Vérifier dernière execution pipeline:",
            "  aws imagebuilder list-image-pipeline-images --image-pipeline-arn <arn> --max-results 1",
            "",
            "Inspector scan findings:",
            "  aws inspector2 list-findings --filter-criteria 'resourceType={comparison=EQUALS,value=AWS_EC2_INSTANCE}'"
        ],
        references=[
            "https://docs.aws.amazon.com/imagebuilder/latest/userguide/what-is-image-builder.html",
            "https://www.cisecurity.org/cis-benchmarks/",
            "https://aws.amazon.com/blogs/mt/create-immutable-servers-using-ec2-image-builder-aws-codepipeline/"
        ]
    ),

    Question(
        id="EC2-006",
        question="Security Groups audit: règles trop permissives (0.0.0.0/0), ports inutiles, documentation règles?",
        description="Vérifier que les Security Groups n'ont pas de règles trop ouvertes (0.0.0.0/0), que seuls les ports nécessaires sont ouverts, et que les règles sont documentées",
        severity="HIGH",
        category="EC2",
        compliance=["CIS Benchmark", "PCI-DSS", "NIST", "Zero Trust"],
        technical_details="""
        Security Groups = stateful firewall au niveau instance/ENI

        Risques règles trop permissives:
        - 0.0.0.0/0 sur ports sensibles (SSH 22, RDP 3389, DB ports)
        - Exposition inutile de services internes
        - Attack surface élargie
        - Risque brute force, exploitation vulnérabilités
        - Non-compliance avec standards sécurité

        Ports sensibles à restreindre:
        - 22 (SSH): limiter à IP admin ou bastion uniquement
        - 3389 (RDP): limiter à IP admin ou bastion
        - 3306 (MySQL), 5432 (PostgreSQL): limiter à app tier
        - 1433 (MSSQL), 27017 (MongoDB): limiter à app tier
        - 6379 (Redis), 11211 (Memcached): limiter à app tier
        - 9200 (Elasticsearch), 5601 (Kibana): limiter à trusted IPs
        - 8080, 8443 (App servers): derrière ALB uniquement

        Best practices Security Groups:
        - Principe least privilege: minimal ports ouverts
        - Source restriction: security group IDs plutôt que CIDRs
        - Pas de 0.0.0.0/0 sauf ALB/CloudFront (ports 80/443)
        - Naming convention: <env>-<tier>-<service>-sg
        - Description obligatoire pour chaque règle
        - Tagging: Owner, Purpose, Environment
        - Regular audit: trimestrial minimum
        - Unused SGs cleanup

        Référencement par SG ID vs CIDR:
        - Avantage SG ID: dynamique (instances ajoutées/retirées auto)
        - Exemple: App tier SG référence DB tier SG au lieu de CIDR
        - Permet micro-segmentation architecture
        - Évite hardcoding IP ranges

        Logging et monitoring:
        - VPC Flow Logs: voir trafic rejected par SGs
        - CloudWatch alarms: sur rules changes
        - AWS Config: detect overly permissive SGs
        - SecurityHub: automated compliance checks
        """,
        remediation=[
            "1. Audit règles trop ouvertes (0.0.0.0/0):",
            "   aws ec2 describe-security-groups \\",
            "     --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName,IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]]'",
            "",
            "2. Identifier SSH/RDP ouverts à Internet:",
            "   aws ec2 describe-security-groups \\",
            "     --filters Name=ip-permission.from-port,Values=22 \\",
            "               Name=ip-permission.cidr,Values='0.0.0.0/0' \\",
            "     --query 'SecurityGroups[].[GroupId,GroupName,VpcId]'",
            "",
            "   # Même pour RDP (port 3389)",
            "   aws ec2 describe-security-groups \\",
            "     --filters Name=ip-permission.from-port,Values=3389 \\",
            "               Name=ip-permission.cidr,Values='0.0.0.0/0'",
            "",
            "3. Créer AWS Config rule - restricted-ssh:",
            "   aws configservice put-config-rule \\",
            "     --config-rule file://restricted-ssh-rule.json",
            "",
            "   restricted-ssh-rule.json:",
            "   {",
            '     "ConfigRuleName": "restricted-ssh",',
            '     "Source": {',
            '       "Owner": "AWS",',
            '       "SourceIdentifier": "INCOMING_SSH_DISABLED"',
            "     }",
            "   }",
            "",
            "4. Créer AWS Config rule - restricted-common-ports:",
            "   Rule: restricted-common-ports",
            "   Parameters: blockedPort1=3389,blockedPort2=3306,blockedPort3=5432",
            "",
            "5. Remédiation - Remplacer 0.0.0.0/0 par CIDR restreint:",
            "   # Supprimer règle ouverte",
            "   aws ec2 revoke-security-group-ingress \\",
            "     --group-id sg-xxxxx \\",
            "     --protocol tcp \\",
            "     --port 22 \\",
            "     --cidr 0.0.0.0/0",
            "",
            "   # Ajouter règle restreinte (ex: VPN IP range)",
            "   aws ec2 authorize-security-group-ingress \\",
            "     --group-id sg-xxxxx \\",
            "     --protocol tcp \\",
            "     --port 22 \\",
            "     --cidr 203.0.113.0/24 \\",
            "     --group-rule-description 'SSH from corporate VPN'",
            "",
            "6. Remplacer CIDR par Security Group reference:",
            "   # Pour app → DB access",
            "   aws ec2 authorize-security-group-ingress \\",
            "     --group-id sg-db-xxxxx \\",
            "     --protocol tcp \\",
            "     --port 3306 \\",
            "     --source-group sg-app-xxxxx \\",
            "     --group-rule-description 'MySQL from app tier'",
            "",
            "7. Nettoyer unused Security Groups:",
            "   # Lister SGs non attachés",
            "   aws ec2 describe-security-groups --query 'SecurityGroups[?length(IpPermissions)==`0`].[GroupId,GroupName]'",
            "",
            "   # Supprimer si non utilisé:",
            "   aws ec2 delete-security-group --group-id sg-xxxxx",
            "",
            "8. Activer SecurityHub pour checks automatiques:",
            "   aws securityhub enable-security-hub",
            "   aws securityhub batch-enable-standards \\",
            "     --standards-subscription-requests '[{\"StandardsArn\":\"arn:aws:securityhub:region::standards/cis-aws-foundations-benchmark/v/1.4.0\"}]'",
            "",
            "9. CloudWatch Events pour alertes modifications SG:",
            "   EventBridge rule: AuthorizeSecurityGroupIngress, RevokeSecurityGroupIngress",
            "   Target: SNS topic pour notifications équipe sécurité"
        ],
        verification_steps=[
            "Rapport règles 0.0.0.0/0:",
            "  aws ec2 describe-security-groups \\",
            "    --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].{ID:GroupId,Name:GroupName,VPC:VpcId}' \\",
            "    --output table",
            "",
            "Vérifier aucun SSH/RDP ouvert publiquement (résultat vide attendu):",
            "  aws ec2 describe-security-groups \\",
            "    --filters Name=ip-permission.from-port,Values=22,3389 \\",
            "              Name=ip-permission.cidr,Values='0.0.0.0/0'",
            "",
            "Config rules compliance:",
            "  aws configservice describe-compliance-by-config-rule \\",
            "    --config-rule-names restricted-ssh restricted-common-ports",
            "",
            "SecurityHub findings:",
            "  aws securityhub get-findings \\",
            "    --filters '{\"ProductFields\":[{\"Key\":\"aws/securityhub/ProductName\",\"Value\":\"Security Hub\",\"Comparison\":\"EQUALS\"}],\"ResourceType\":[{\"Value\":\"AwsEc2SecurityGroup\",\"Comparison\":\"EQUALS\"}]}'",
            "",
            "Lister SGs avec descriptions manquantes:",
            "  aws ec2 describe-security-groups \\",
            "    --query 'SecurityGroups[?IpPermissions[?(!Description)]].{GroupId:GroupId,Rule:IpPermissions}'",
            "",
            "VPC Flow Logs - vérifier REJECTs:",
            "  Athena query: SELECT * FROM vpc_flow_logs WHERE action='REJECT' ORDER BY start DESC LIMIT 100",
            "",
            "Unused Security Groups:",
            "  aws ec2 describe-network-interfaces \\",
            "    --query 'NetworkInterfaces[].Groups[].GroupId' | sort | uniq",
            "  # Comparer avec liste totale SGs pour trouver unused"
        ],
        references=[
            "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html",
            "https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html",
            "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html"
        ]
    ),

    Question(
        id="EC2-007",
        question="EC2 Instance Connect activé pour accès SSH temporaire sans gestion de clés permanentes?",
        description="Vérifier que EC2 Instance Connect est utilisé pour accès SSH temporaire avec credentials éphémères via IAM au lieu de clés SSH permanentes",
        severity="MEDIUM",
        category="EC2",
        compliance=["AWS Well-Architected", "Zero Trust", "Least Privilege"],
        technical_details="""
        EC2 Instance Connect:
        - Accès SSH temporaire via IAM (pas de clés permanentes)
        - Push one-time SSH public key vers instance metadata
        - Clé valide 60 secondes
        - Authentication via IAM permissions
        - Audit via CloudTrail (SendSSHPublicKey)
        - Compatible Amazon Linux 2, Ubuntu 16.04+

        Avantages vs clés SSH traditionnelles:
        - Pas de gestion/distribution clés privées
        - Pas de clés stockées sur postes utilisateurs
        - Révocation instantanée (via IAM)
        - Rotation automatique (clés éphémères)
        - Audit centralisé CloudTrail
        - MFA enforcement possible via IAM
        - Pas de risque clé compromise/volée

        Comparaison solutions accès EC2:
        1. Clés SSH traditionnelles:
           - Clés permanentes difficiles à rotate
           - Pas d'audit qui utilise quelle clé
           - Risque vol/partage clés
           - Gestion complexe (qui a accès?)

        2. EC2 Instance Connect:
           - Clés éphémères (60s)
           - IAM-based (granular permissions)
           - Audit CloudTrail
           - Pas de gestion clés

        3. Systems Manager Session Manager:
           - Pas SSH du tout (HTTPS)
           - Pas de ports ouverts
           - Logging complet sessions
           - Plus sécurisé mais nécessite SSM Agent

        Architecture Instance Connect:
        - User → IAM auth → EC2 Instance Connect API
        - API push temporary public key → instance metadata
        - User SSH avec private key correspondante
        - Après 60s: clé expirée, supprimée metadata

        Prérequis:
        - EC2 Instance Connect package installé
        - Security Group autorise SSH depuis EC2_INSTANCE_CONNECT service (IP ranges AWS)
        - IAM permission: ec2-instance-connect:SendSSHPublicKey
        - Instance dans région supportée

        Use case idéal:
        - Accès admin ponctuel/troubleshooting
        - Environnements où audit strict requis
        - Éviter partage clés SSH entre utilisateurs
        - Break-glass access
        """,
        remediation=[
            "1. Installer EC2 Instance Connect sur instances:",
            "   # Amazon Linux 2 (déjà inclus sur AMIs récentes)",
            "   sudo yum install -y ec2-instance-connect",
            "",
            "   # Ubuntu 20.04+",
            "   sudo apt install -y ec2-instance-connect",
            "",
            "   # Vérifier service actif:",
            "   sudo systemctl status ec2-instance-connect",
            "",
            "2. Configurer Security Group pour Instance Connect:",
            "   # Récupérer IP ranges EC2_INSTANCE_CONNECT pour région",
            "   aws ec2 describe-managed-prefix-lists \\",
            "     --filters Name=prefix-list-name,Values='com.amazonaws.*.ec2-instance-connect' \\",
            "     --query 'PrefixLists[0].PrefixListId'",
            "",
            "   # Autoriser SSH depuis prefix list:",
            "   aws ec2 authorize-security-group-ingress \\",
            "     --group-id sg-xxxxx \\",
            "     --ip-permissions IpProtocol=tcp,FromPort=22,ToPort=22,PrefixListIds=[{PrefixListId=pl-xxxxx,Description='EC2 Instance Connect'}]",
            "",
            "3. Créer IAM policy pour utilisateurs:",
            "   {",
            '     "Version": "2012-10-17",',
            '     "Statement": [{',
            '       "Effect": "Allow",',
            '       "Action": "ec2-instance-connect:SendSSHPublicKey",',
            '       "Resource": "arn:aws:ec2:region:account:instance/*",',
            '       "Condition": {',
            '         "StringEquals": {',
            '           "ec2:osuser": "ec2-user"',
            "         }",
            "       }",
            "     },",
            "     {",
            '       "Effect": "Allow",',
            '       "Action": "ec2:DescribeInstances",',
            '       "Resource": "*"',
            "     }]",
            "   }",
            "",
            "4. Attacher policy au groupe IAM utilisateurs:",
            "   aws iam put-group-policy \\",
            "     --group-name Developers \\",
            "     --policy-name EC2InstanceConnectAccess \\",
            "     --policy-document file://instance-connect-policy.json",
            "",
            "5. Connexion via AWS CLI:",
            "   # Méthode 1: AWS CLI helper (génère clé automatiquement)",
            "   aws ec2-instance-connect ssh --instance-id i-xxxxx",
            "",
            "   # Méthode 2: Manuelle",
            "   # Générer keypair temporaire:",
            "   ssh-keygen -t rsa -f /tmp/temp_key -N ''",
            "",
            "   # Push public key vers instance:",
            "   aws ec2-instance-connect send-ssh-public-key \\",
            "     --instance-id i-xxxxx \\",
            "     --availability-zone us-east-1a \\",
            "     --instance-os-user ec2-user \\",
            "     --ssh-public-key file:///tmp/temp_key.pub",
            "",
            "   # Connexion SSH dans 60 secondes:",
            "   ssh -i /tmp/temp_key ec2-user@<instance-ip>",
            "",
            "6. Connexion via Console (browser-based):",
            "   EC2 Console → Instance → Connect → EC2 Instance Connect → Connect",
            "",
            "7. Désactiver accès SSH traditionnel:",
            "   # Supprimer authorized_keys existantes",
            "   # Bloquer port 22 depuis Internet dans SG (garder uniquement prefix list)",
            "",
            "8. Enforcer MFA pour accès Instance Connect:",
            "   IAM policy condition:",
            "   \"Condition\": {",
            "     \"BoolIfExists\": {\"aws:MultiFactorAuthPresent\": \"true\"}",
            "   }"
        ],
        verification_steps=[
            "Vérifier package installé sur instances:",
            "  rpm -qa | grep ec2-instance-connect  # Amazon Linux",
            "  dpkg -l | grep ec2-instance-connect  # Ubuntu",
            "",
            "Vérifier SG autorise EC2_INSTANCE_CONNECT:",
            "  aws ec2 describe-security-groups --group-ids sg-xxxxx \\",
            "    --query 'SecurityGroups[].IpPermissions[?FromPort==`22`].PrefixListIds'",
            "",
            "Test connexion Instance Connect:",
            "  aws ec2-instance-connect ssh --instance-id i-xxxxx",
            "",
            "Audit CloudTrail - voir utilisation:",
            "  aws cloudtrail lookup-events \\",
            "    --lookup-attributes AttributeKey=EventName,AttributeValue=SendSSHPublicKey \\",
            "    --max-results 50",
            "",
            "Vérifier IAM permissions utilisateurs:",
            "  aws iam get-group-policy --group-name Developers --policy-name EC2InstanceConnectAccess",
            "",
            "Test depuis Console EC2:",
            "  EC2 → Select instance → Connect → EC2 Instance Connect tab → Connect button",
            "",
            "Vérifier logs SSH sur instance:",
            "  sudo tail -f /var/log/secure  # Amazon Linux",
            "  sudo tail -f /var/log/auth.log  # Ubuntu",
            "  # Chercher: \"Accepted publickey for ec2-user from...\"",
            "",
            "Lister IP ranges EC2 Instance Connect pour région:",
            "  aws ec2 describe-managed-prefix-lists \\",
            "    --filters Name=prefix-list-name,Values='com.amazonaws.*.ec2-instance-connect' \\",
            "    --query 'PrefixLists[].[PrefixListId,PrefixListName]'"
        ],
        references=[
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Connect-using-EC2-Instance-Connect.html",
            "https://aws.amazon.com/blogs/compute/new-using-amazon-ec2-instance-connect-for-ssh-access-to-your-ec2-instances/",
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-methods.html"
        ]
    ),

    Question(
        id="EC2-008",
        question="Protection terminaison instances critiques et stratégie backup EBS avec lifecycle automatisé?",
        description="Vérifier que termination protection est activée sur instances critiques et que stratégie de backup automatisée existe pour volumes EBS avec rétention appropriée",
        severity="MEDIUM",
        category="EC2",
        compliance=["Business Continuity", "Disaster Recovery", "Data Protection"],
        technical_details="""
        Termination Protection:
        - Empêche suppression accidentelle instance via console/API/CLI
        - Attribut DisableApiTermination = true
        - Protection contre: ec2:TerminateInstances API calls
        - Ne protège pas contre: shutdown depuis OS, Auto Scaling termination
        - À activer sur: production databases, stateful apps, long-running workloads

        DeleteOnTermination attribute (EBS):
        - Par défaut: root volume deleted, data volumes retained
        - Risque: data loss si mal configuré
        - Best practice: false pour data volumes (DB, logs, user data)
        - Root volume: peut être true si immutable infrastructure

        AWS Backup service:
        - Backup centralisé multi-services (EC2, EBS, RDS, EFS, etc.)
        - Backup plans: scheduling, retention, lifecycle
        - Backup vaults: storage avec encryption KMS
        - Cross-region copy: disaster recovery
        - Point-in-time recovery
        - Compliance reporting

        Stratégie backup EBS:
        1. Snapshots automatiques (AWS Backup ou Data Lifecycle Manager)
        2. Rétention selon RPO/RTO:
           - Critical (RPO<1h): snapshots toutes les 4h, rétention 30j
           - Important (RPO<24h): snapshots daily, rétention 14j
           - Standard (RPO<7j): snapshots weekly, rétention 7j
        3. Cross-region replication pour DR
        4. Tagging snapshots pour organisation/coûts
        5. Testing régulier restore

        EBS Snapshots particularités:
        - Incrementaux (seuls blocks modifiés)
        - Stockage S3 (durability 99.999999999%)
        - Copy cross-region pour DR
        - Encryption preserved (si volume source encrypted)
        - Fast Snapshot Restore (FSR) pour restauration rapide

        Amazon Data Lifecycle Manager (DLM):
        - Alternative légère à AWS Backup
        - Policies basées sur tags
        - Automatisation création/rétention/suppression snapshots
        - Gratuit (seulement coût storage snapshots)
        - Cross-account sharing snapshots

        Testing DR:
        - Drill réguliers: restore snapshot vers nouvelle instance
        - Vérifier integrity data
        - Documenter RTO réel
        - GameDays: simulation panne
        """,
        remediation=[
            "1. Activer Termination Protection instances critiques:",
            "   # Identifier instances production sans protection:",
            "   aws ec2 describe-instances \\",
            "     --filters Name=tag:Environment,Values=production \\",
            "     --query 'Reservations[].Instances[?DisableApiTermination==`false`].[InstanceId,Tags[?Key==`Name`].Value|[0]]'",
            "",
            "   # Activer protection:",
            "   aws ec2 modify-instance-attribute \\",
            "     --instance-id i-xxxxx \\",
            "     --disable-api-termination",
            "",
            "   # Vérifier:",
            "   aws ec2 describe-instance-attribute \\",
            "     --instance-id i-xxxxx \\",
            "     --attribute disableApiTermination",
            "",
            "2. Configurer DeleteOnTermination pour data volumes:",
            "   # Vérifier current setting:",
            "   aws ec2 describe-instances --instance-id i-xxxxx \\",
            "     --query 'Reservations[].Instances[].BlockDeviceMappings[].[DeviceName,Ebs.VolumeId,Ebs.DeleteOnTermination]'",
            "",
            "   # Désactiver DeleteOnTermination pour data volume:",
            "   aws ec2 modify-instance-attribute \\",
            "     --instance-id i-xxxxx \\",
            "     --block-device-mappings '[{\"DeviceName\":\"/dev/sdf\",\"Ebs\":{\"DeleteOnTermination\":false}}]'",
            "",
            "3. Créer AWS Backup plan:",
            "   aws backup create-backup-plan \\",
            "     --backup-plan file://backup-plan.json",
            "",
            "   backup-plan.json:",
            "   {",
            '     "BackupPlanName": "DailyEBSBackup",',
            '     "Rules": [{',
            '       "RuleName": "DailyBackup",',
            '       "TargetBackupVaultName": "Default",',
            '       "ScheduleExpression": "cron(0 5 ? * * *)",',
            '       "StartWindowMinutes": 60,',
            '       "CompletionWindowMinutes": 120,',
            '       "Lifecycle": {',
            '         "DeleteAfterDays": 30,',
            '         "MoveToColdStorageAfterDays": 7',
            "       },",
            '       "RecoveryPointTags": {',
            '         "BackupType": "Automated"',
            "       }",
            "     }]",
            "   }",
            "",
            "4. Assigner resources au backup plan (via tags):",
            "   aws backup create-backup-selection \\",
            "     --backup-plan-id <plan-id> \\",
            "     --backup-selection file://selection.json",
            "",
            "   selection.json:",
            "   {",
            '     "SelectionName": "ProductionEBS",',
            '     "IamRoleArn": "arn:aws:iam::account:role/AWSBackupDefaultServiceRole",',
            '     "Resources": ["*"],',
            '     "ListOfTags": [{',
            '       "ConditionType": "STRINGEQUALS",',
            '       "ConditionKey": "Environment",',
            '       "ConditionValue": "production"',
            "     }]",
            "   }",
            "",
            "5. Alternative: Data Lifecycle Manager (DLM):",
            "   aws dlm create-lifecycle-policy \\",
            "     --execution-role-arn arn:aws:iam::account:role/AWSDataLifecycleManagerDefaultRole \\",
            "     --description 'Daily EBS snapshots' \\",
            "     --state ENABLED \\",
            "     --policy-details file://dlm-policy.json",
            "",
            "   dlm-policy.json:",
            "   {",
            '     "ResourceTypes": ["VOLUME"],',
            '     "TargetTags": [{"Key": "Backup", "Value": "true"}],',
            '     "Schedules": [{',
            '       "Name": "DailySnapshots",',
            '       "CreateRule": {"Interval": 24, "IntervalUnit": "HOURS", "Times": ["03:00"]},',
            '       "RetainRule": {"Count": 14},',
            '       "TagsToAdd": [{"Key": "SnapshotType", "Value": "DLM"}],',
            '       "CopyTags": true',
            "     }]",
            "   }",
            "",
            "6. Configurer cross-region copy pour DR:",
            "   # Dans backup plan, ajouter CopyActions:",
            '     "CopyActions": [{',
            '       "DestinationBackupVaultArn": "arn:aws:backup:eu-west-1:account:backup-vault:DR-Vault",',
            '       "Lifecycle": {"DeleteAfterDays": 90}',
            "     }]",
            "",
            "7. Tagging discipline pour backups:",
            "   aws ec2 create-tags --resources vol-xxxxx \\",
            "     --tags Key=Backup,Value=true Key=BackupFrequency,Value=Daily Key=Retention,Value=30days",
            "",
            "8. Créer backup vault avec encryption:",
            "   aws backup create-backup-vault \\",
            "     --backup-vault-name SecureVault \\",
            "     --encryption-key-arn arn:aws:kms:region:account:key/xxxxx",
            "",
            "9. Tester restore process:",
            "   # Restore snapshot vers nouveau volume:",
            "   aws ec2 create-volume \\",
            "     --snapshot-id snap-xxxxx \\",
            "     --availability-zone us-east-1a \\",
            "     --volume-type gp3",
            "",
            "   # Attacher et tester integrity:",
            "   aws ec2 attach-volume --volume-id vol-xxxxx --instance-id i-xxxxx --device /dev/sdf"
        ],
        verification_steps=[
            "Instances sans termination protection:",
            "  aws ec2 describe-instance-attribute \\",
            "    --instance-id i-xxxxx \\",
            "    --attribute disableApiTermination",
            "  # DisableApiTermination: {Value: true} attendu pour production",
            "",
            "Volumes avec DeleteOnTermination=true (risqué):",
            "  aws ec2 describe-instances \\",
            "    --query 'Reservations[].Instances[].BlockDeviceMappings[?Ebs.DeleteOnTermination==`true`].[Ebs.VolumeId,DeviceName]'",
            "",
            "Backup plans actifs:",
            "  aws backup list-backup-plans",
            "  aws backup get-backup-plan --backup-plan-id <plan-id>",
            "",
            "Backup selections (resources couverts):",
            "  aws backup list-backup-selections --backup-plan-id <plan-id>",
            "",
            "Recovery points récents:",
            "  aws backup list-recovery-points-by-backup-vault \\",
            "    --backup-vault-name Default \\",
            "    --max-results 20",
            "",
            "DLM policies:",
            "  aws dlm get-lifecycle-policies",
            "  aws dlm get-lifecycle-policy --policy-id policy-xxxxx",
            "",
            "Snapshots récents par volume:",
            "  aws ec2 describe-snapshots --owner-ids self \\",
            "    --filters Name=volume-id,Values=vol-xxxxx \\",
            "    --query 'Snapshots[].[SnapshotId,StartTime,State]' \\",
            "    --output table",
            "",
            "Compliance reporting AWS Backup:",
            "  aws backup list-backup-jobs --by-backup-vault-name Default",
            "  aws backup list-backup-jobs --by-state COMPLETED --max-results 10",
            "",
            "Test restore (dry-run):",
            "  aws backup start-restore-job \\",
            "    --recovery-point-arn <arn> \\",
            "    --iam-role-arn <role> \\",
            "    --metadata file://restore-metadata.json",
            "",
            "Coût snapshots:",
            "  aws ce get-cost-and-usage \\",
            "    --time-period Start=2024-01-01,End=2024-01-31 \\",
            "    --granularity MONTHLY \\",
            "    --metrics UnblendedCost \\",
            "    --filter file://snapshot-filter.json"
        ],
        references=[
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/terminating-instances.html#Using_ChangingDisableAPITermination",
            "https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html",
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/snapshot-lifecycle.html",
            "https://aws.amazon.com/blogs/storage/automating-amazon-ebs-snapshot-and-ami-management-using-amazon-dlm/"
        ]
    )
]

# ==================== S3 & STORAGE ====================
S3_QUESTIONS = [
    Question(
        id="S3-001",
        question="Block Public Access activé au niveau compte et bucket pour prévenir expositions accidentelles?",
        description="Vérifier que Block Public Access est activé globalement et par bucket pour empêcher toute exposition publique non intentionnelle",
        severity="CRITICAL",
        category="S3",
        compliance=["CIS Benchmark", "GDPR", "PCI-DSS", "HIPAA"],
        technical_details="""
        S3 Block Public Access settings (4 contrôles):

        1. BlockPublicAcls:
           - Bloque ajout de nouvelles ACLs publiques
           - Bloque modification ACLs existantes vers publique
           - N'affecte pas ACLs publiques existantes

        2. IgnorePublicAcls:
           - Ignore toutes ACLs publiques
           - Traite objets comme privés même si ACL dit public
           - Plus restrictif que BlockPublicAcls

        3. BlockPublicPolicy:
           - Bloque ajout/modification bucket policies avec public access
           - Validation lors du PUT bucket policy

        4. RestrictPublicBuckets:
           - Restreint accès aux buckets avec policies publiques
           - Seulement AWS service principals et autorisés dans bucket policy

        Niveaux d'application:
        - Account level: appliqué à tous buckets du compte
        - Bucket level: settings spécifiques par bucket
        - Precedence: settings compte override settings bucket

        Cas d'usage public légitime:
        - Hosting static website
        - Public downloads (ex: open data)
        - CloudFront origin (recommandé: OAI au lieu de public)

        Méthodes d'accès public à bloquer:
        - Bucket ACLs (public-read, public-read-write)
        - Object ACLs (public-read, public-read-write)
        - Bucket policies avec Principal: "*" sans conditions
        - Bucket policies avec Principal: "*" et Condition trop large

        Risques exposition:
        - Data breach (leak données sensibles)
        - Ransomware (modification/suppression)
        - Crypto mining (servir malware)
        - Compliance violations
        - Réputation damage
        """,
        remediation=[
            "1. Activer Block Public Access au niveau compte (toutes régions):",
            "   aws s3control put-public-access-block \\",
            "     --account-id <account-id> \\",
            "     --public-access-block-configuration \\",
            "       BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            "",
            "2. Vérifier configuration compte:",
            "   aws s3control get-public-access-block --account-id <account-id>",
            "",
            "3. Activer sur bucket spécifique:",
            "   aws s3api put-public-access-block \\",
            "     --bucket <bucket-name> \\",
            "     --public-access-block-configuration \\",
            "       BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            "",
            "4. Identifier buckets avec accès public:",
            "   aws s3api list-buckets --query 'Buckets[].Name' --output text | \\",
            "   while read bucket; do",
            "     echo \"Checking $bucket\"",
            "     aws s3api get-bucket-acl --bucket $bucket 2>/dev/null",
            "     aws s3api get-bucket-policy-status --bucket $bucket 2>/dev/null",
            "   done",
            "",
            "5. Utiliser AWS Config rules:",
            "   - s3-bucket-public-read-prohibited",
            "   - s3-bucket-public-write-prohibited",
            "   - s3-account-level-public-access-blocks",
            "",
            "6. Alternative pour static website hosting:",
            "   - Utiliser CloudFront avec Origin Access Identity (OAI)",
            "   - Bucket reste privé",
            "   - CloudFront sert le contenu publiquement",
            "",
            "7. Créer SCP pour bloquer désactivation:",
            "   {",
            '     "Effect": "Deny",',
            '     "Action": [',
            '       "s3:PutAccountPublicAccessBlock",',
            '       "s3:PutBucketPublicAccessBlock"',
            "     ],",
            '     "Resource": "*",',
            '     "Condition": {',
            '       "StringNotEquals": {',
            '         "s3:PublicAccessBlockConfiguration": "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"',
            "       }",
            "     }",
            "   }",
            "",
            "8. Monitorer avec EventBridge:",
            "   - Alerter sur PutBucketAcl vers public",
            "   - Alerter sur PutBucketPolicy avec Principal:*"
        ],
        verification_steps=[
            "Vérifier account-level settings:",
            "  aws s3control get-public-access-block --account-id $(aws sts get-caller-identity --query Account --output text)",
            "",
            "Lister tous buckets avec public access:",
            "  aws s3api list-buckets --query 'Buckets[].Name' --output text | while read bucket; do",
            "    status=$(aws s3api get-bucket-policy-status --bucket $bucket --query 'PolicyStatus.IsPublic' 2>/dev/null)",
            "    if [ \"$status\" = \"true\" ]; then",
            "      echo \"PUBLIC: $bucket\"",
            "    fi",
            "  done",
            "",
            "Vérifier Block Public Access par bucket:",
            "  aws s3api get-public-access-block --bucket <bucket-name>",
            "",
            "Utiliser S3 console (plus visuel):",
            "  - Colonne 'Access' montre 'Public' ou 'Not public'",
            "  - Filter par 'Public' pour voir expositions",
            "",
            "AWS Config compliance:",
            "  aws configservice describe-compliance-by-config-rule \\",
            "    --config-rule-names s3-bucket-public-read-prohibited s3-bucket-public-write-prohibited",
            "",
            "Macie findings (si activé):",
            "  aws macie2 list-findings --finding-criteria 'criterion={category={eq=[POLICY_FINDINGS]}}'",
            "",
            "Access Analyzer findings:",
            "  aws accessanalyzer list-findings --analyzer-arn <arn> --filter 'resourceType={eq=[AWS::S3::Bucket]}'"
        ],
        references=[
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            "https://aws.amazon.com/blogs/aws/amazon-s3-block-public-access-another-layer-of-protection-for-your-accounts-and-buckets/"
        ]
    ),

    Question(
        id="S3-002",
        question="Chiffrement par défaut activé (SSE-S3 ou SSE-KMS) sur tous les buckets avec policies forçant chiffrement?",
        description="Vérifier que default encryption est activée et que bucket policies refusent uploads non chiffrés",
        severity="CRITICAL",
        category="S3",
        compliance=["PCI-DSS", "HIPAA", "GDPR", "ISO 27001"],
        technical_details="""
        Types de chiffrement S3:

        1. SSE-S3 (Server-Side Encryption with S3-Managed Keys):
           - AES-256
           - Clés gérées par AWS
           - Gratuit
           - Rotation automatique clés
           - Header: x-amz-server-side-encryption: AES256

        2. SSE-KMS (Server-Side Encryption with AWS KMS):
           - AES-256
           - Clés gérées dans KMS (customer-managed ou AWS-managed)
           - Audit trail dans CloudTrail (qui utilise quelle clé)
           - Coût: $0.01 per 10,000 requests
           - Contrôle d'accès granulaire via key policies
           - Header: x-amz-server-side-encryption: aws:kms
           - Rotation automatique optionnelle

        3. SSE-C (Server-Side Encryption with Customer-Provided Keys):
           - Client fournit clé dans chaque requête
           - AWS ne stocke pas la clé
           - Client gère rotation
           - Complexe à opérer

        4. Client-Side Encryption:
           - Chiffrement avant upload
           - AWS ne voit que données chiffrées
           - Client gère clés et déchiffrement
           - SDK S3 Encryption Client

        Default Encryption:
        - Appliqué automatiquement aux nouveaux objets
        - N'affecte pas objets existants
        - Peut être override par x-amz-server-side-encryption header
        - Paramètre au niveau bucket

        Bucket Policy pour forcer chiffrement:
        - Deny PUT sans header encryption
        - Peut spécifier type de chiffrement (SSE-S3 vs SSE-KMS)
        - Peut exiger KMS key spécifique

        Compliance requirements:
        - PCI-DSS: chiffrement données sensibles
        - HIPAA: chiffrement PHI (Protected Health Information)
        - GDPR: protection données personnelles
        - SOC2: contrôles accès et chiffrement

        Performance impact:
        - SSE-S3: négligeable
        - SSE-KMS: latency due to KMS API calls
        - Throughput limits KMS: 5500 req/s (peut demander augmentation)
        """,
        remediation=[
            "1. Activer default encryption SSE-S3:",
            "   aws s3api put-bucket-encryption --bucket <bucket-name> \\",
            "     --server-side-encryption-configuration '{",
            '       "Rules": [{',
            '         "ApplyServerSideEncryptionByDefault": {',
            '           "SSEAlgorithm": "AES256"',
            "         },",
            '         "BucketKeyEnabled": true',
            "       }]",
            "     }'",
            "",
            "2. Activer default encryption SSE-KMS:",
            "   aws s3api put-bucket-encryption --bucket <bucket-name> \\",
            "     --server-side-encryption-configuration '{",
            '       "Rules": [{',
            '         "ApplyServerSideEncryptionByDefault": {',
            '           "SSEAlgorithm": "aws:kms",',
            '           "KMSMasterKeyID": "arn:aws:kms:region:account:key/xxxx"',
            "         },",
            '         "BucketKeyEnabled": true',
            "       }]",
            "     }'",
            "",
            "   Note: BucketKeyEnabled réduit coûts KMS (moins de requests)",
            "",
            "3. Créer bucket policy forçant chiffrement:",
            "   {",
            '     "Version": "2012-10-17",',
            '     "Statement": [{',
            '       "Sid": "DenyUnencryptedObjectUploads",',
            '       "Effect": "Deny",',
            '       "Principal": "*",',
            '       "Action": "s3:PutObject",',
            '       "Resource": "arn:aws:s3:::<bucket-name>/*",',
            '       "Condition": {',
            '         "StringNotEquals": {',
            '           "s3:x-amz-server-side-encryption": ["AES256", "aws:kms"]',
            "         }",
            "       }",
            "     }]",
            "   }",
            "",
            "4. Policy pour exiger KMS key spécifique:",
            "   {",
            '     "Sid": "RequireSpecificKMSKey",',
            '     "Effect": "Deny",',
            '     "Principal": "*",',
            '     "Action": "s3:PutObject",',
            '     "Resource": "arn:aws:s3:::<bucket-name>/*",',
            '     "Condition": {',
            '       "StringNotEqualsIfExists": {',
            '         "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:region:account:key/xxxxx"',
            "       }",
            "     }",
            "   }",
            "",
            "5. Chiffrer objets existants non chiffrés:",
            "   aws s3 cp s3://<bucket>/ s3://<bucket>/ --recursive --sse AES256 --metadata-directive REPLACE",
            "",
            "   Ou avec KMS:",
            "   aws s3 cp s3://<bucket>/ s3://<bucket>/ --recursive --sse aws:kms --sse-kms-key-id <key-id> --metadata-directive REPLACE",
            "",
            "6. Utiliser AWS Config rules:",
            "   - s3-default-encryption-kms",
            "   - s3-bucket-server-side-encryption-enabled",
            "",
            "7. Créer SCP pour bloquer création buckets non chiffrés:",
            "   {",
            '     "Effect": "Deny",',
            '     "Action": "s3:CreateBucket",',
            '     "Resource": "*",',
            '     "Condition": {',
            '       "StringNotEquals": {',
            '         "s3:x-amz-server-side-encryption": ["AES256", "aws:kms"]',
            "       }",
            "     }",
            "   }"
        ],
        verification_steps=[
            "Vérifier default encryption bucket:",
            "  aws s3api get-bucket-encryption --bucket <bucket-name>",
            "",
            "Lister buckets sans encryption:",
            "  aws s3api list-buckets --query 'Buckets[].Name' --output text | while read bucket; do",
            "    encryption=$(aws s3api get-bucket-encryption --bucket $bucket 2>&1)",
            "    if echo $encryption | grep -q 'ServerSideEncryptionConfigurationNotFoundError'; then",
            "      echo \"NO ENCRYPTION: $bucket\"",
            "    fi",
            "  done",
            "",
            "Vérifier objets non chiffrés dans bucket:",
            "  aws s3api list-objects-v2 --bucket <bucket-name> --query 'Contents[?!ServerSideEncryption].[Key,Size]' --output table",
            "",
            "Vérifier bucket policy contient Deny unencrypted:",
            "  aws s3api get-bucket-policy --bucket <bucket-name> --query Policy --output text | jq '.Statement[] | select(.Condition.StringNotEquals.\"s3:x-amz-server-side-encryption\")'",
            "",
            "Test upload sans encryption (devrait fail):",
            "  aws s3 cp test.txt s3://<bucket>/  # Sans --sse flag",
            "",
            "AWS Config compliance:",
            "  aws configservice describe-compliance-by-config-rule --config-rule-names s3-default-encryption-kms",
            "",
            "Macie inventory (si activé):",
            "  aws macie2 describe-buckets --criteria '{\"encryptionType\":{\"eq\":[\"NONE\"]}}'",
            "",
            "CloudWatch metric pour objets non chiffrés:",
            "  Créer custom metric via Lambda scannant buckets"
        ],
        references=[
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html",
            "https://aws.amazon.com/blogs/security/how-to-prevent-uploads-of-unencrypted-objects-to-amazon-s3/"
        ]
    ),

    Question(
        id="S3-003",
        question="S3 versioning activé avec MFA Delete et lifecycle policies configurées (Glacier, expiration)?",
        description="Vérifier versioning pour protection données et lifecycle pour optimisation coûts",
        severity="MEDIUM",
        category="S3",
        compliance=["Data Protection", "FinOps"],
        technical_details="Versioning garde historique objets. MFA Delete protège contre suppression malveillante. Lifecycle: transition Glacier après X jours, expiration objets anciens",
        remediation=["put-bucket-versioning MFADelete=Enabled", "put-bucket-lifecycle-configuration transitions", "Intelligent-Tiering pour auto-optimization"],
        verification_steps=["get-bucket-versioning", "get-bucket-lifecycle-configuration", "S3 Storage Lens metrics par classe"],
        references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html"]
    ),

    Question(
        id="S3-004",
        question="S3 access logging activé et CloudTrail data events configurés pour audit complet accès objets?",
        description="Vérifier logging accès S3 (server access logs) et CloudTrail data events pour traçabilité complète",
        severity="HIGH",
        category="S3",
        compliance=["Audit Trail", "PCI-DSS", "HIPAA", "SOC2"],
        technical_details="S3 Server Access Logs: capture requêtes bucket-level (GET, PUT, DELETE). CloudTrail data events: capture API calls objet-level avec identité caller. Complémentaires pour audit forensics",
        remediation=[
            "aws s3api put-bucket-logging --bucket source-bucket --bucket-logging-status file://logging.json",
            "CloudTrail data events: aws cloudtrail put-event-selectors --trail-name trail --event-selectors '[{\"ReadWriteType\":\"All\",\"DataResources\":[{\"Type\":\"AWS::S3::Object\",\"Values\":[\"arn:aws:s3:::bucket/*\"]}]}]'",
            "Analyser logs avec Athena pour détection accès non autorisés"
        ],
        verification_steps=[
            "aws s3api get-bucket-logging --bucket mybucket",
            "aws cloudtrail get-event-selectors --trail-name trail | grep S3",
            "Vérifier logs S3 dans target bucket: aws s3 ls s3://logs-bucket/",
            "Athena query: SELECT * FROM s3_access_logs WHERE status='403' OR status='404'"
        ],
        references=[
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html",
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html"
        ]
    ),

    Question(
        id="S3-005",
        question="S3 Object Lock (WORM) activé pour données réglementées avec retention compliance mode?",
        description="Vérifier Object Lock avec Compliance/Governance mode pour protection immuable données critiques",
        severity="HIGH",
        category="S3",
        compliance=["SEC Rule 17a-4", "FINRA", "HIPAA", "GDPR"],
        technical_details="Object Lock WORM (Write Once Read Many): Compliance mode (immuable même root), Governance mode (bypass avec permissions). Retention period + Legal Hold. Requis pour compliance financière/santé",
        remediation=[
            "Créer bucket avec Object Lock: aws s3api create-bucket --bucket compliant-bucket --object-lock-enabled-for-bucket",
            "aws s3api put-object-lock-configuration --bucket compliant-bucket --object-lock-configuration 'ObjectLockEnabled=Enabled,Rule={DefaultRetention={Mode=COMPLIANCE,Years=7}}'",
            "Legal hold sur objet spécifique: aws s3api put-object-legal-hold --bucket bucket --key file.pdf --legal-hold Status=ON"
        ],
        verification_steps=[
            "aws s3api get-object-lock-configuration --bucket mybucket",
            "aws s3api get-object-retention --bucket bucket --key file.pdf",
            "aws s3api get-object-legal-hold --bucket bucket --key file.pdf",
            "Test: tenter suppression objet locked (doit échouer)"
        ],
        references=[
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html",
            "https://aws.amazon.com/blogs/storage/how-to-use-s3-object-lock-to-meet-compliance-requirements/"
        ]
    ),

    Question(
        id="S3-006",
        question="S3 Replication (CRR/SRR) configurée pour disaster recovery et compliance multi-région?",
        description="Vérifier Cross-Region Replication ou Same-Region Replication pour resilience et conformité géographique",
        severity="MEDIUM",
        category="S3",
        compliance=["Disaster Recovery", "Data Residency", "GDPR"],
        technical_details="CRR: réplication cross-region pour DR et latency. SRR: réplication same-region pour aggregation/compliance. Réplication automatique asynchrone. Supporte RTC (15min SLA), Delete marker replication, Replica modification sync",
        remediation=[
            "aws s3api put-bucket-versioning --bucket source --versioning-configuration Status=Enabled",
            "aws s3api put-bucket-versioning --bucket destination --versioning-configuration Status=Enabled",
            "aws s3api put-bucket-replication --bucket source --replication-configuration file://replication.json",
            "IAM role avec s3:ReplicateObject, s3:ReplicateDelete permissions",
            "Activer Replication Time Control pour SLA 15min"
        ],
        verification_steps=[
            "aws s3api get-bucket-replication --bucket source-bucket",
            "CloudWatch metrics: aws cloudwatch get-metric-statistics --namespace AWS/S3 --metric-name ReplicationLatency",
            "Vérifier objets répliqués: aws s3 ls s3://destination-bucket/ --recursive",
            "Test: upload objet source, vérifier apparition dans destination sous 15min"
        ],
        references=[
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-time-control.html"
        ]
    ),

    Question(
        id="S3-007",
        question="S3 Inventory et Storage Class Analysis activés pour governance et optimisation coûts?",
        description="Vérifier S3 Inventory pour audit objets et Analytics pour recommandations lifecycle/tiering",
        severity="LOW",
        category="S3",
        compliance=["FinOps", "Data Governance"],
        technical_details="S3 Inventory: rapport CSV/Parquet de tous objets (metadata, encryption, storage class). Storage Class Analysis: recommande transitions lifecycle basées sur patterns accès. S3 Storage Lens: métriques organisation-wide",
        remediation=[
            "aws s3api put-bucket-inventory-configuration --bucket mybucket --id daily-inventory --inventory-configuration file://inventory.json",
            "aws s3api put-bucket-analytics-configuration --bucket mybucket --id storage-analytics --analytics-configuration file://analytics.json",
            "S3 Storage Lens: activer via console pour dashboard organisation-wide",
            "Athena queries sur inventory pour trouver objets non chiffrés, non versionnés, etc."
        ],
        verification_steps=[
            "aws s3api list-bucket-inventory-configurations --bucket mybucket",
            "aws s3api list-bucket-analytics-configurations --bucket mybucket",
            "Vérifier inventory reports dans destination bucket: aws s3 ls s3://inventory-bucket/",
            "Athena CREATE TABLE depuis inventory manifest puis SELECT encryption_status, COUNT(*) GROUP BY encryption_status",
            "Storage Class Analysis recommendations après 30 jours observation"
        ],
        references=[
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-inventory.html",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/analytics-storage-class.html",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage_lens.html"
        ]
    )
]

# ==================== RDS & DATABASES ====================
RDS_QUESTIONS = [
    Question(
        id="RDS-001",
        question="Encryption at rest activée pour toutes instances RDS et Aurora avec KMS?",
        description="Vérifier chiffrement RDS/Aurora au repos",
        severity="CRITICAL",
        category="RDS",
        compliance=["PCI-DSS", "HIPAA", "GDPR"],
        technical_details="RDS encryption at rest avec KMS, snapshots chiffrés",
        remediation=["Activer encryption à la création", "Ou créer snapshot chiffré et restore"],
        verification_steps=["aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,StorageEncrypted]'"],
        references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"]
    ),

    Question(
        id="RDS-002",
        question="Multi-AZ deployment activé pour toutes DB de production avec failover automatique?",
        description="Vérifier haute disponibilité RDS/Aurora avec Multi-AZ pour resilience et failover automatique",
        severity="HIGH",
        category="RDS",
        compliance=["AWS Well-Architected", "SOC2", "ISO 27001"],
        technical_details="""
        Multi-AZ deployment pour haute disponibilité:

        RDS Multi-AZ (non Aurora):
        - Réplication synchrone vers standby dans AZ différente
        - Failover automatique en 60-120 secondes
        - Backups depuis standby (pas d'impact performance)
        - Patching sur standby d'abord (downtime réduit)
        - Endpoint DNS reste identique après failover

        Aurora Multi-AZ:
        - 6 copies des données across 3 AZs minimum
        - Shared storage layer avec auto-healing
        - Read replicas peuvent être promoted as writer
        - Failover en 30 secondes typiquement
        - Priorité de failover configurable par tier

        Différence vs Single-AZ:
        - Single-AZ: maintenance ou AZ failure = downtime
        - Multi-AZ: maintenance sur standby = pas de downtime
        - Multi-AZ: automatic failover sans intervention

        Coût:
        - Multi-AZ coûte ~2x prix Single-AZ
        - Mais critique pour production workloads

        Monitoring failover:
        - CloudWatch metric: DatabaseConnections
        - RDS Events: failover started, completed
        - Enhanced Monitoring pour temps de failover
        """,
        remediation=[
            "1. Activer Multi-AZ pour instance existante (downtime requis):",
            "   aws rds modify-db-instance \\",
            "     --db-instance-identifier mydb \\",
            "     --multi-az \\",
            "     --apply-immediately",
            "",
            "   Note: apply-immediately force outage. Sans flag, apply durant maintenance window",
            "",
            "2. Vérifier que toutes DB prod sont Multi-AZ:",
            "   aws rds describe-db-instances \\",
            "     --query 'DBInstances[?MultiAZ==`false`].[DBInstanceIdentifier,DBInstanceClass,Engine]' \\",
            "     --output table",
            "",
            "3. Pour Aurora, créer replicas dans autres AZs:",
            "   aws rds create-db-instance \\",
            "     --db-instance-identifier mydb-replica-az2 \\",
            "     --db-cluster-identifier mydb-cluster \\",
            "     --db-instance-class db.r5.large \\",
            "     --engine aurora-mysql \\",
            "     --availability-zone us-east-1b",
            "",
            "4. Configurer failover priority pour Aurora:",
            "   aws rds modify-db-instance \\",
            "     --db-instance-identifier mydb-replica \\",
            "     --promotion-tier 1",
            "",
            "   Tier 0-15: 0 = highest priority pour failover",
            "",
            "5. Tester failover (hors production d'abord!):",
            "   aws rds reboot-db-instance \\",
            "     --db-instance-identifier mydb \\",
            "     --force-failover",
            "",
            "6. Créer alarme CloudWatch pour failover events:",
            "   aws cloudwatch put-metric-alarm \\",
            "     --alarm-name rds-failover-detection \\",
            "     --alarm-description 'Alert on RDS failover' \\",
            "     --metric-name DatabaseConnections \\",
            "     --namespace AWS/RDS",
            "",
            "7. Tag production databases:",
            "   aws rds add-tags-to-resource \\",
            "     --resource-name arn:aws:rds:region:account:db:mydb \\",
            "     --tags Key=Environment,Value=Production Key=RequiresMultiAZ,Value=true"
        ],
        verification_steps=[
            "Lister toutes instances avec statut Multi-AZ:",
            "  aws rds describe-db-instances \\",
            "    --query 'DBInstances[].[DBInstanceIdentifier,MultiAZ,Engine,AvailabilityZone,SecondaryAvailabilityZone]' \\",
            "    --output table",
            "",
            "Identifier instances prod sans Multi-AZ:",
            "  aws rds describe-db-instances \\",
            "    --query 'DBInstances[?MultiAZ==`false`].[DBInstanceIdentifier,Tags[?Key==`Environment`].Value|[0]]' \\",
            "    --output table",
            "",
            "Pour Aurora, vérifier nombre replicas par AZ:",
            "  aws rds describe-db-clusters \\",
            "    --query 'DBClusters[].[DBClusterIdentifier,MultiAZ,AvailabilityZones]' \\",
            "    --output table",
            "",
            "  aws rds describe-db-clusters --db-cluster-identifier mycluster \\",
            "    --query 'DBClusters[0].DBClusterMembers[*].[DBInstanceIdentifier,PromotionTier,IsClusterWriter]'",
            "",
            "Vérifier failover tier Aurora:",
            "  aws rds describe-db-instances \\",
            "    --query 'DBInstances[].[DBInstanceIdentifier,PromotionTier]' \\",
            "    --output table",
            "",
            "Historique des failovers (via RDS events):",
            "  aws rds describe-events \\",
            "    --source-type db-instance \\",
            "    --source-identifier mydb \\",
            "    --duration 10080 \\",
            "    --query 'Events[?contains(Message,`failover`)].[Date,Message]' \\",
            "    --output table",
            "",
            "Temps de failover moyen (via CloudWatch Insights):",
            "  aws logs start-query \\",
            "    --log-group-name /aws/rds/instance/mydb/error \\",
            "    --start-time $(date -d '7 days ago' +%s) \\",
            "    --end-time $(date +%s) \\",
            "    --query-string 'fields @timestamp, @message | filter @message like /failover/'",
            "",
            "AWS Config rule pour Multi-AZ:",
            "  aws configservice put-config-rule --config-rule '{",
            '    "ConfigRuleName": "rds-multi-az-required",',
            '    "Source": {',
            '      "Owner": "AWS",',
            '      "SourceIdentifier": "RDS_MULTI_AZ_SUPPORT"',
            "    }",
            "  }'"
        ],
        references=[
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html",
            "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Concepts.AuroraHighAvailability.html",
            "https://aws.amazon.com/rds/features/multi-az/"
        ]
    ),

    Question(
        id="RDS-003",
        question="Automated backups activés avec retention >= 7 jours, snapshots manuels cross-region?",
        description="Vérifier stratégie de backup RDS/Aurora avec automated backups, retention adequat, et disaster recovery cross-region",
        severity="CRITICAL",
        category="RDS",
        compliance=["PCI-DSS", "HIPAA", "SOC2", "ISO 27001"],
        technical_details="""
        RDS Backup strategy complète:

        Automated Backups:
        - Backup quotidien automatique du full DB + transaction logs
        - Point-in-time recovery (PITR) à n'importe quelle seconde
        - Retention: 0-35 jours (0 = désactivé, DANGER!)
        - Stored dans S3 (multi-AZ automatique)
        - Backup window configurable (maintenance)
        - I/O suspension possible durant backup (pas avec Multi-AZ)

        Manual Snapshots:
        - Snapshots manuels conservés indéfiniment (jusqu'à suppression)
        - Utile avant migrations, upgrades majeurs
        - Peuvent être copiés vers autres régions (DR)
        - Peuvent être partagés avec autres comptes AWS
        - Snapshots chiffrés si source DB chiffrée

        Aurora Backups:
        - Continuous incremental backups vers S3
        - Backup automatique sans impact performance
        - Retention 1-35 jours
        - Backtrack: retour en arrière sans restore (MySQL)

        Cross-Region disaster recovery:
        - Copie snapshots vers région secondaire
        - Aurora Global Database pour réplication cross-region
        - RTO/RPO à définir selon criticité

        Backup encryption:
        - Automated backups héritent encryption de source
        - Impossible de chiffrer backup d'une DB non chiffrée
        - Pour migrer: snapshot → copy chiffré → restore

        Coût:
        - Automated backups: gratuit jusqu'à 100% du storage provisionné
        - Au-delà: $0.095/GB-month
        - Manual snapshots: toujours payant
        - Cross-region copy: transfer + storage
        """,
        remediation=[
            "1. Activer automated backups si désactivé:",
            "   aws rds modify-db-instance \\",
            "     --db-instance-identifier mydb \\",
            "     --backup-retention-period 7 \\",
            "     --preferred-backup-window '03:00-04:00' \\",
            "     --apply-immediately",
            "",
            "2. Augmenter retention à 30 jours pour prod critical:",
            "   aws rds modify-db-instance \\",
            "     --db-instance-identifier mydb-prod \\",
            "     --backup-retention-period 30",
            "",
            "3. Créer snapshot manuel avant maintenance:",
            "   aws rds create-db-snapshot \\",
            "     --db-instance-identifier mydb \\",
            "     --db-snapshot-identifier mydb-before-upgrade-$(date +%Y%m%d)",
            "",
            "4. Copier snapshot vers région secondaire (DR):",
            "   aws rds copy-db-snapshot \\",
            "     --source-db-snapshot-identifier arn:aws:rds:us-east-1:account:snapshot:mydb-snap \\",
            "     --target-db-snapshot-identifier mydb-snap-dr \\",
            "     --region us-west-2 \\",
            "     --kms-key-id arn:aws:kms:us-west-2:account:key/xxxx",
            "",
            "   Note: KMS key doit exister dans target region",
            "",
            "5. Automatiser cross-region backup via Lambda:",
            "   # Lambda triggered daily par EventBridge",
            "   # Copy latest automated backup to DR region",
            "",
            "6. Partager snapshot avec autre compte (backup isolation):",
            "   aws rds modify-db-snapshot-attribute \\",
            "     --db-snapshot-identifier mydb-snap \\",
            "     --attribute-name restore \\",
            "     --values-to-add 123456789012",
            "",
            "7. Restore DB depuis snapshot (test DR!):",
            "   aws rds restore-db-instance-from-db-snapshot \\",
            "     --db-instance-identifier mydb-restored \\",
            "     --db-snapshot-identifier mydb-snap",
            "",
            "8. Point-in-time restore à timestamp précis:",
            "   aws rds restore-db-instance-to-point-in-time \\",
            "     --source-db-instance-identifier mydb \\",
            "     --target-db-instance-identifier mydb-pitr \\",
            "     --restore-time 2024-01-15T14:30:00Z",
            "",
            "9. Aurora Backtrack (MySQL seulement):",
            "   aws rds backtrack-db-cluster \\",
            "     --db-cluster-identifier mycluster \\",
            "     --backtrack-to 2024-01-15T14:00:00Z",
            "",
            "10. Tag snapshots pour lifecycle management:",
            "    aws rds add-tags-to-resource \\",
            "      --resource-name arn:aws:rds:region:account:snapshot:mydb-snap \\",
            "      --tags Key=Retention,Value=90days Key=CriticalityLevel,Value=High"
        ],
        verification_steps=[
            "Vérifier automated backup enabled et retention:",
            "  aws rds describe-db-instances \\",
            "    --query 'DBInstances[].[DBInstanceIdentifier,BackupRetentionPeriod,PreferredBackupWindow]' \\",
            "    --output table",
            "",
            "Identifier DB sans backups (CRITICAL!):",
            "  aws rds describe-db-instances \\",
            "    --query 'DBInstances[?BackupRetentionPeriod==`0`].[DBInstanceIdentifier,Engine]' \\",
            "    --output table",
            "",
            "Lister automated backups disponibles:",
            "  aws rds describe-db-instance-automated-backups \\",
            "    --db-instance-identifier mydb",
            "",
            "Lister manual snapshots:",
            "  aws rds describe-db-snapshots \\",
            "    --db-instance-identifier mydb \\",
            "    --snapshot-type manual \\",
            "    --query 'DBSnapshots[].[DBSnapshotIdentifier,SnapshotCreateTime,Encrypted,Status]' \\",
            "    --output table",
            "",
            "Vérifier snapshots cross-region:",
            "  aws rds describe-db-snapshots \\",
            "    --region us-west-2 \\",
            "    --query 'DBSnapshots[?contains(DBSnapshotIdentifier,`dr`)]' \\",
            "    --output table",
            "",
            "Calculer earliest restore time (PITR):",
            "  aws rds describe-db-instances \\",
            "    --db-instance-identifier mydb \\",
            "    --query 'DBInstances[0].[LatestRestorableTime,BackupRetentionPeriod]'",
            "",
            "Vérifier que snapshots sont chiffrés:",
            "  aws rds describe-db-snapshots \\",
            "    --query 'DBSnapshots[?Encrypted==`false`].[DBSnapshotIdentifier,SnapshotCreateTime]' \\",
            "    --output table",
            "",
            "Tester restore (dans environnement test):",
            "  # Créer snapshot",
            "  # Restore vers nouvelle instance",
            "  # Vérifier data integrity",
            "  # Documenter RTO (Recovery Time Objective)",
            "",
            "Audit via AWS Config:",
            "  aws configservice describe-compliance-by-config-rule \\",
            "    --config-rule-names db-backup-enabled \\",
            "    --compliance-types NON_COMPLIANT",
            "",
            "Snapshot age et freshness:",
            "  aws rds describe-db-snapshots \\",
            "    --query 'DBSnapshots[*].[DBSnapshotIdentifier,SnapshotCreateTime]' \\",
            "    --output table | head -20"
        ],
        references=[
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html",
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PIT.html",
            "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Aurora.Managing.Backups.html",
            "https://aws.amazon.com/blogs/database/implementing-a-disaster-recovery-strategy-with-amazon-rds/"
        ]
    ),

    Question(
        id="RDS-004",
        question="DB parameter groups configurés avec SSL/TLS enforced, logging activé, et paramètres sécurisés?",
        description="Vérifier DB parameter groups pour enforcer TLS, activer audit logging, et appliquer security best practices",
        severity="HIGH",
        category="RDS",
        compliance=["PCI-DSS", "HIPAA", "SOC2", "CIS Benchmark"],
        technical_details="""
        RDS Parameter Groups security configuration:

        SSL/TLS enforcement:
        - require_secure_transport=ON (MySQL/MariaDB)
        - rds.force_ssl=1 (PostgreSQL)
        - Empêche connexions non chiffrées
        - Client doit utiliser SSL pour se connecter

        Audit logging (MySQL/MariaDB):
        - server_audit_logging=1
        - server_audit_events=CONNECT,QUERY_DDL,QUERY_DML
        - Logs vers CloudWatch Logs

        PostgreSQL logging:
        - log_connections=1
        - log_disconnections=1
        - log_statement=ddl (ou all pour tout)
        - log_min_duration_statement=1000 (log slow queries)

        SQL Server auditing:
        - Via native SQL Server Audit
        - Logs vers S3

        Autres paramètres sécurité:
        - max_connections: limiter pour éviter DoS
        - local_infile=0 (MySQL): empêcher LOAD DATA LOCAL
        - log_bin_trust_function_creators=0

        Parameter groups vs DB instance:
        - Parameter group = template de config
        - Peut être partagé entre plusieurs DB
        - Changements nécessitent reboot (pour static params)
        - Dynamic params: appliqués immédiatement

        Custom vs default parameter groups:
        - Toujours utiliser custom (default non modifiable)
        - Permet versioning et rollback
        - Tag parameter groups par environment
        """,
        remediation=[
            "1. Créer custom parameter group:",
            "   aws rds create-db-parameter-group \\",
            "     --db-parameter-group-name mysql57-secure \\",
            "     --db-parameter-group-family mysql5.7 \\",
            "     --description 'Secure MySQL 5.7 configuration'",
            "",
            "2. Enforcer SSL/TLS pour MySQL:",
            "   aws rds modify-db-parameter-group \\",
            "     --db-parameter-group-name mysql57-secure \\",
            "     --parameters 'ParameterName=require_secure_transport,ParameterValue=ON,ApplyMethod=immediate'",
            "",
            "3. Enforcer SSL pour PostgreSQL:",
            "   aws rds modify-db-parameter-group \\",
            "     --db-parameter-group-name postgres13-secure \\",
            "     --parameters 'ParameterName=rds.force_ssl,ParameterValue=1,ApplyMethod=immediate'",
            "",
            "4. Activer audit logging MySQL:",
            "   aws rds modify-db-parameter-group \\",
            "     --db-parameter-group-name mysql57-secure \\",
            "     --parameters \\",
            "       'ParameterName=server_audit_logging,ParameterValue=1,ApplyMethod=immediate' \\",
            "       'ParameterName=server_audit_events,ParameterValue=CONNECT,ApplyMethod=immediate'",
            "",
            "5. Activer logging PostgreSQL:",
            "   aws rds modify-db-parameter-group \\",
            "     --db-parameter-group-name postgres13-secure \\",
            "     --parameters \\",
            "       'ParameterName=log_connections,ParameterValue=1,ApplyMethod=immediate' \\",
            "       'ParameterName=log_statement,ParameterValue=ddl,ApplyMethod=immediate'",
            "",
            "6. Appliquer parameter group à DB instance:",
            "   aws rds modify-db-instance \\",
            "     --db-instance-identifier mydb \\",
            "     --db-parameter-group-name mysql57-secure \\",
            "     --apply-immediately",
            "",
            "   Note: reboot requis pour static parameters",
            "",
            "7. Reboot pour appliquer changements:",
            "   aws rds reboot-db-instance --db-instance-identifier mydb",
            "",
            "8. Exporter logs vers CloudWatch:",
            "   aws rds modify-db-instance \\",
            "     --db-instance-identifier mydb \\",
            "     --cloudwatch-logs-export-configuration '{\"LogTypesToEnable\":[\"audit\",\"error\",\"general\",\"slowquery\"]}'",
            "",
            "9. Créer Config rule pour vérifier parameter groups:",
            "   # Custom Config rule vérifiant require_secure_transport=ON"
        ],
        verification_steps=[
            "Lister parameter groups custom:",
            "  aws rds describe-db-parameter-groups \\",
            "    --query 'DBParameterGroups[?!starts_with(DBParameterGroupName,`default`)]'",
            "",
            "Vérifier SSL enforced pour MySQL:",
            "  aws rds describe-db-parameters \\",
            "    --db-parameter-group-name mysql57-secure \\",
            "    --query 'Parameters[?ParameterName==`require_secure_transport`].[ParameterValue]' \\",
            "    --output text",
            "",
            "Vérifier SSL enforced pour PostgreSQL:",
            "  aws rds describe-db-parameters \\",
            "    --db-parameter-group-name postgres13-secure \\",
            "    --query 'Parameters[?ParameterName==`rds.force_ssl`].[ParameterValue]' \\",
            "    --output text",
            "",
            "Vérifier audit logging MySQL:",
            "  aws rds describe-db-parameters \\",
            "    --db-parameter-group-name mysql57-secure \\",
            "    --query 'Parameters[?ParameterName==`server_audit_logging`].[ParameterValue]'",
            "",
            "Lister DB avec default parameter groups (NON CONFORME):",
            "  aws rds describe-db-instances \\",
            "    --query 'DBInstances[?starts_with(DBParameterGroups[0].DBParameterGroupName,`default`)].[DBInstanceIdentifier,DBParameterGroups[0].DBParameterGroupName]' \\",
            "    --output table",
            "",
            "Vérifier CloudWatch Logs export enabled:",
            "  aws rds describe-db-instances \\",
            "    --query 'DBInstances[].[DBInstanceIdentifier,EnabledCloudwatchLogsExports]' \\",
            "    --output table",
            "",
            "Tester connexion SSL (doit réussir):",
            "  mysql -h mydb.xxxx.rds.amazonaws.com -u admin -p --ssl-mode=REQUIRED",
            "",
            "Tester connexion non-SSL (doit échouer si force_ssl):",
            "  mysql -h mydb.xxxx.rds.amazonaws.com -u admin -p --ssl-mode=DISABLED",
            "",
            "Comparer parameter groups entre environnements:",
            "  diff <(aws rds describe-db-parameters --db-parameter-group-name prod-params) \\",
            "       <(aws rds describe-db-parameters --db-parameter-group-name dev-params)"
        ],
        references=[
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithParamGroups.html",
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html",
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.html"
        ]
    ),

    Question(
        id="RDS-005",
        question="Auto minor version upgrade activé et maintenance window configurée pour automated patching?",
        description="Vérifier automated patching RDS avec minor version upgrades et maintenance windows appropriées",
        severity="MEDIUM",
        category="RDS",
        compliance=["CIS Benchmark", "AWS Well-Architected"],
        technical_details="""
        RDS Automated patching et maintenance:

        Auto Minor Version Upgrade:
        - Applique automatiquement patches sécurité mineurs
        - Example: MySQL 5.7.30 → 5.7.31
        - Appliqué durant maintenance window
        - Recommandé ON pour production (sécurité > stabilité)

        Maintenance Window:
        - Fenêtre hebdomadaire de 30 min minimum
        - Durant cette fenêtre: patches, upgrades, modifications
        - Choisir heures creuses (ex: Dimanche 3-4 AM)
        - Multi-AZ: patching sur standby d'abord (moins downtime)

        Types de maintenance:
        - Required: patches sécurité critiques (forcé)
        - Available: upgrades optionnels (manuel)
        - Next window: maintenance programmée

        Major version upgrades:
        - Jamais automatique (breaking changes possibles)
        - Doit être fait manuellement
        - Tester en non-prod d'abord!

        Downtime durant patching:
        - Single-AZ: downtime de quelques minutes
        - Multi-AZ: minimal (failover vers standby patché)
        - Aurora: rolling upgrades, quasi zero downtime

        Deferring maintenance:
        - Peut defer jusqu'à deadline AWS
        - Après deadline: appliqué de force
        """,
        remediation=[
            "1. Activer auto minor version upgrade:",
            "   aws rds modify-db-instance \\",
            "     --db-instance-identifier mydb \\",
            "     --auto-minor-version-upgrade \\",
            "     --apply-immediately",
            "",
            "2. Configurer maintenance window:",
            "   aws rds modify-db-instance \\",
            "     --db-instance-identifier mydb \\",
            "     --preferred-maintenance-window sun:03:00-sun:04:00",
            "",
            "   Format: ddd:hh24:mi-ddd:hh24:mi (UTC)",
            "",
            "3. Appliquer maintenance immédiatement (test):",
            "   aws rds apply-pending-maintenance-action \\",
            "     --resource-identifier arn:aws:rds:region:account:db:mydb \\",
            "     --apply-action system-update \\",
            "     --opt-in-type immediate",
            "",
            "4. Vérifier pending maintenance actions:",
            "   aws rds describe-pending-maintenance-actions",
            "",
            "5. Major version upgrade (manuel seulement!):",
            "   # Test en non-prod d'abord!",
            "   aws rds modify-db-instance \\",
            "     --db-instance-identifier mydb \\",
            "     --engine-version 8.0.28 \\",
            "     --allow-major-version-upgrade \\",
            "     --apply-immediately",
            "",
            "6. Créer alarme pour pending maintenance:",
            "   # SNS notification quand maintenance programmée",
            "",
            "7. Documenter patching calendar:",
            "   # Maintenance windows par environnement",
            "   # Dev: Samedi 2 AM",
            "   # Staging: Samedi 3 AM",
            "   # Prod: Dimanche 3 AM"
        ],
        verification_steps=[
            "Vérifier auto minor version upgrade status:",
            "  aws rds describe-db-instances \\",
            "    --query 'DBInstances[].[DBInstanceIdentifier,AutoMinorVersionUpgrade,PreferredMaintenanceWindow]' \\",
            "    --output table",
            "",
            "Identifier DB sans auto upgrade (risque sécurité):",
            "  aws rds describe-db-instances \\",
            "    --query 'DBInstances[?AutoMinorVersionUpgrade==`false`].[DBInstanceIdentifier,Engine,EngineVersion]' \\",
            "    --output table",
            "",
            "Vérifier pending maintenance actions:",
            "  aws rds describe-pending-maintenance-actions \\",
            "    --query 'PendingMaintenanceActions[].[ResourceIdentifier,PendingMaintenanceActionDetails[0].[Action,CurrentApplyDate]]' \\",
            "    --output table",
            "",
            "Vérifier engine versions actuelles:",
            "  aws rds describe-db-instances \\",
            "    --query 'DBInstances[].[DBInstanceIdentifier,Engine,EngineVersion]' \\",
            "    --output table",
            "",
            "Comparer avec latest available version:",
            "  aws rds describe-db-engine-versions \\",
            "    --engine mysql \\",
            "    --engine-version 5.7 \\",
            "    --query 'DBEngineVersions[0].ValidUpgradeTarget[*].EngineVersion'",
            "",
            "RDS events history (patches appliqués):",
            "  aws rds describe-events \\",
            "    --source-type db-instance \\",
            "    --duration 10080 \\",
            "    --query 'Events[?contains(Message,`upgrade`)||contains(Message,`patch`)].[Date,SourceIdentifier,Message]' \\",
            "    --output table",
            "",
            "Maintenance windows par environnement:",
            "  for env in dev staging prod; do",
            "    echo \"=== $env ===\"",
            "    aws rds describe-db-instances \\",
            "      --filters Name=tag:Environment,Values=$env \\",
            "      --query 'DBInstances[].[DBInstanceIdentifier,PreferredMaintenanceWindow]'",
            "  done"
        ],
        references=[
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Maintenance.html",
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Upgrading.html"
        ]
    ),

    Question(
        id="RDS-006",
        question="Enhanced Monitoring et Performance Insights activés pour monitoring détaillé et troubleshooting?",
        description="Vérifier Enhanced Monitoring (OS metrics) et Performance Insights (DB performance) activés sur instances RDS",
        severity="MEDIUM",
        category="RDS",
        compliance=["AWS Well-Architected"],
        technical_details="""
        RDS Monitoring avancé:

        Enhanced Monitoring:
        - Metrics OS-level en temps réel
        - CPU, memory, file system, disk I/O
        - Granularité: 1, 5, 10, 15, 30, 60 secondes
        - Agent CloudWatch sur instance RDS (hypervisor level)
        - Logs vers CloudWatch Logs
        - Coût: selon granularité et volume logs

        Metrics disponibles:
        - cpuUtilization (par core)
        - memory (used, free, cached)
        - swap usage
        - disk I/O (read/write throughput, IOPS)
        - network throughput
        - active processes

        Performance Insights:
        - DB load analysis et wait events
        - Visualisation queries lentes
        - Top SQL statements par latency/exec count
        - Rétention: 7 jours gratuit, jusqu'à 2 ans payant
        - Dashboard détaillé dans console

        Métriques Performance Insights:
        - DBLoad: nb sessions actives
        - Wait events: CPU, I/O, lock, etc.
        - Top queries par temps total
        - Dimensions: SQL, wait, user, host

        Différence CloudWatch vs Enhanced Monitoring:
        - CloudWatch: métriques hypervisor-level
        - Enhanced: métriques OS-level (plus précis)
        - Enhanced peut voir processes, CloudWatch non

        Use cases:
        - Enhanced: troubleshooting performance, capacity planning
        - Performance Insights: optimisation queries, DB tuning
        - Alerting: CloudWatch Alarms sur métriques
        """,
        remediation=[
            "1. Activer Enhanced Monitoring:",
            "   aws rds modify-db-instance \\",
            "     --db-instance-identifier mydb \\",
            "     --monitoring-interval 60 \\",
            "     --monitoring-role-arn arn:aws:iam::account:role/rds-monitoring-role",
            "",
            "   Granularité: 1,5,10,15,30,60 secondes",
            "   Plus fréquent = plus coûteux",
            "",
            "2. Créer IAM role pour Enhanced Monitoring (si pas existe):",
            "   aws iam create-role \\",
            "     --role-name rds-monitoring-role \\",
            "     --assume-role-policy-document '{",
            '       "Version": "2012-10-17",',
            '       "Statement": [{',
            '         "Effect": "Allow",',
            '         "Principal": {"Service": "monitoring.rds.amazonaws.com"},',
            '         "Action": "sts:AssumeRole"',
            "       }]",
            "     }'",
            "",
            "   aws iam attach-role-policy \\",
            "     --role-name rds-monitoring-role \\",
            "     --policy-arn arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole",
            "",
            "3. Activer Performance Insights:",
            "   aws rds modify-db-instance \\",
            "     --db-instance-identifier mydb \\",
            "     --enable-performance-insights \\",
            "     --performance-insights-retention-period 7",
            "",
            "   Retention: 7 jours (free) ou 731 jours (paid)",
            "",
            "4. Activer Performance Insights avec KMS:",
            "   aws rds modify-db-instance \\",
            "     --db-instance-identifier mydb \\",
            "     --enable-performance-insights \\",
            "     --performance-insights-kms-key-id arn:aws:kms:region:account:key/xxxx \\",
            "     --performance-insights-retention-period 31",
            "",
            "5. Créer CloudWatch Alarm sur CPU élevé:",
            "   aws cloudwatch put-metric-alarm \\",
            "     --alarm-name rds-high-cpu \\",
            "     --alarm-description 'RDS CPU > 80%' \\",
            "     --metric-name CPUUtilization \\",
            "     --namespace AWS/RDS \\",
            "     --statistic Average \\",
            "     --period 300 \\",
            "     --evaluation-periods 2 \\",
            "     --threshold 80 \\",
            "     --comparison-operator GreaterThanThreshold \\",
            "     --dimensions Name=DBInstanceIdentifier,Value=mydb",
            "",
            "6. Query Performance Insights via CLI:",
            "   aws pi get-resource-metrics \\",
            "     --service-type RDS \\",
            "     --identifier db-XXXXX \\",
            "     --metric-queries '[{\"Metric\":\"db.load.avg\"}]' \\",
            "     --start-time 2024-01-15T00:00:00Z \\",
            "     --end-time 2024-01-15T23:59:59Z \\",
            "     --period-in-seconds 3600",
            "",
            "7. Exporter Enhanced Monitoring logs vers S3 (long-term):",
            "   # Via Kinesis Firehose depuis CloudWatch Logs"
        ],
        verification_steps=[
            "Vérifier Enhanced Monitoring status:",
            "  aws rds describe-db-instances \\",
            "    --query 'DBInstances[].[DBInstanceIdentifier,MonitoringInterval,MonitoringRoleArn]' \\",
            "    --output table",
            "",
            "Identifier DB sans Enhanced Monitoring:",
            "  aws rds describe-db-instances \\",
            "    --query 'DBInstances[?MonitoringInterval==`0`].[DBInstanceIdentifier,DBInstanceClass]' \\",
            "    --output table",
            "",
            "Vérifier Performance Insights status:",
            "  aws rds describe-db-instances \\",
            "    --query 'DBInstances[].[DBInstanceIdentifier,PerformanceInsightsEnabled,PerformanceInsightsRetentionPeriod]' \\",
            "    --output table",
            "",
            "Lister DB sans Performance Insights:",
            "  aws rds describe-db-instances \\",
            "    --query 'DBInstances[?PerformanceInsightsEnabled==`false`].[DBInstanceIdentifier]' \\",
            "    --output table",
            "",
            "Consulter Enhanced Monitoring logs CloudWatch:",
            "  aws logs describe-log-groups --log-group-name-prefix RDSOSMetrics",
            "",
            "  aws logs tail RDSOSMetrics --follow",
            "",
            "Top queries via Performance Insights:",
            "  # Via console: RDS > Performance Insights",
            "  # ou API:",
            "  aws pi describe-dimension-keys \\",
            "    --service-type RDS \\",
            "    --identifier db-XXXXX \\",
            "    --metric db.load.avg \\",
            "    --group-by '{\"Group\":\"db.sql\"}' \\",
            "    --start-time 2024-01-15T00:00:00Z \\",
            "    --end-time 2024-01-15T23:59:59Z \\",
            "    --period-in-seconds 3600",
            "",
            "CloudWatch métriques RDS standards:",
            "  aws cloudwatch get-metric-statistics \\",
            "    --namespace AWS/RDS \\",
            "    --metric-name CPUUtilization \\",
            "    --dimensions Name=DBInstanceIdentifier,Value=mydb \\",
            "    --start-time 2024-01-15T00:00:00Z \\",
            "    --end-time 2024-01-15T23:59:59Z \\",
            "    --period 3600 \\",
            "    --statistics Average",
            "",
            "Vérifier alarmes configurées:",
            "  aws cloudwatch describe-alarms --alarm-name-prefix rds-"
        ],
        references=[
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Monitoring.OS.html",
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PerfInsights.html",
            "https://aws.amazon.com/rds/performance-insights/"
        ]
    ),

    Question(
        id="RDS-007",
        question="IAM Database Authentication activée pour accès DB sans password stockés/rotés?",
        description="Vérifier que IAM Database Authentication est utilisée pour authentification temporaire via tokens IAM au lieu de passwords statiques",
        severity="HIGH",
        category="RDS",
        compliance=["AWS Well-Architected", "Least Privilege", "Zero Trust"],
        technical_details="""
        IAM Database Authentication = auth DB via IAM tokens

        Fonctionnement:
        - Application obtient auth token via AWS SDK (GetAuthToken)
        - Token valide 15 minutes
        - Token utilisé comme password pour connexion DB
        - Authentification via SSL/TLS obligatoire
        - Credentials jamais stockés dans app

        Avantages vs passwords:
        - Pas de password statique à gérer
        - Pas de rotation password nécessaire
        - Credentials temporaires (15 min)
        - Audit via CloudTrail (qui obtient tokens)
        - Integration IAM: policies, roles, MFA
        - Révocation instantanée via IAM policy

        Engines supportés:
        - MySQL 5.6+ (pas MariaDB)
        - PostgreSQL 9.5+
        - Aurora MySQL
        - Aurora PostgreSQL

        Limitations:
        - Max 200 connexions/seconde par DB instance
        - SSL/TLS requis (overhead performance)
        - Application doit régénérer tokens avant expiration
        - Pas supporté: SQL Server, Oracle, MariaDB

        Architecture typique:
        - Lambda function avec IAM role
        - IAM policy: rds-db:connect sur resource DB user
        - Function génère token avec rds.generate_db_auth_token()
        - Connexion DB avec token comme password
        - Token expiré → régénérer automatiquement

        Use cases:
        - Applications serverless (Lambda, ECS)
        - Microservices avec IAM roles
        - Environnements highly regulated (no static passwords)
        - Short-lived connections (IAM token parfait)
        - Centralized access management via IAM

        Vs alternatives:
        1. Static passwords: rotation complexe, risque leak
        2. Secrets Manager: coût, latency, still passwords
        3. IAM DB Auth: gratuit, zero management, temporary
        """,
        remediation=[
            "1. Activer IAM Database Authentication sur RDS:",
            "   aws rds modify-db-instance \\",
            "     --db-instance-identifier mydb \\",
            "     --enable-iam-database-authentication \\",
            "     --apply-immediately",
            "",
            "   # Pour Aurora cluster:",
            "   aws rds modify-db-cluster \\",
            "     --db-cluster-identifier mycluster \\",
            "     --enable-iam-database-authentication",
            "",
            "2. Créer DB user avec IAM authentication:",
            "   # MySQL:",
            "   CREATE USER 'iamuser' IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS';",
            "   GRANT SELECT, INSERT, UPDATE ON mydb.* TO 'iamuser'@'%';",
            "",
            "   # PostgreSQL:",
            "   CREATE USER iamuser;",
            "   GRANT rds_iam TO iamuser;",
            "   GRANT CONNECT ON DATABASE mydb TO iamuser;",
            "",
            "3. Créer IAM policy pour DB user access:",
            "   {",
            '     "Version": "2012-10-17",',
            '     "Statement": [{',
            '       "Effect": "Allow",',
            '       "Action": "rds-db:connect",',
            '       "Resource": "arn:aws:rds-db:region:account:dbuser:db-RESOURCEID/iamuser"',
            "     }]",
            "   }",
            "",
            "   # Récupérer Resource ID:",
            "   aws rds describe-db-instances \\",
            "     --db-instance-identifier mydb \\",
            "     --query 'DBInstances[0].DbiResourceId'",
            "",
            "4. Attacher policy à IAM role (Lambda, EC2, etc.):",
            "   aws iam attach-role-policy \\",
            "     --role-name MyAppRole \\",
            "     --policy-arn arn:aws:iam::account:policy/RDSIAMAuthPolicy",
            "",
            "5. Code application pour générer token (Python):",
            "   import boto3",
            "   import pymysql",
            "",
            "   rds = boto3.client('rds')",
            "   ",
            "   # Générer auth token",
            "   token = rds.generate_db_auth_token(",
            "     DBHostname='mydb.region.rds.amazonaws.com',",
            "     Port=3306,",
            "     DBUsername='iamuser',",
            "     Region='us-east-1'",
            "   )",
            "",
            "   # Connexion avec token",
            "   conn = pymysql.connect(",
            "     host='mydb.region.rds.amazonaws.com',",
            "     user='iamuser',",
            "     password=token,  # Token as password",
            "     database='mydb',",
            "     ssl_ca='/path/to/rds-ca-bundle.pem',  # SSL requis",
            "     ssl_verify_cert=True",
            "   )",
            "",
            "6. NodeJS exemple:",
            "   const AWS = require('aws-sdk');",
            "   const mysql = require('mysql2/promise');",
            "",
            "   const signer = new AWS.RDS.Signer({",
            "     region: 'us-east-1',",
            "     hostname: 'mydb.region.rds.amazonaws.com',",
            "     port: 3306,",
            "     username: 'iamuser'",
            "   });",
            "",
            "   const token = await signer.getAuthToken();",
            "",
            "   const connection = await mysql.createConnection({",
            "     host: 'mydb.region.rds.amazonaws.com',",
            "     user: 'iamuser',",
            "     password: token,",
            "     database: 'mydb',",
            "     ssl: 'Amazon RDS'",
            "   });",
            "",
            "7. Télécharger RDS CA bundle pour SSL:",
            "   wget https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem",
            "",
            "8. Monitoring usage IAM auth:",
            "   CloudTrail: rechercher GenerateDataKey events",
            "   CloudWatch metric: DatabaseConnections",
            "",
            "9. Désactiver password authentication (force IAM only):",
            "   # MySQL: supprimer users avec mysql_native_password",
            "   # PostgreSQL: configurer pg_hba.conf (managed, use IAM users only)"
        ],
        verification_steps=[
            "Vérifier IAM DB Auth activé:",
            "  aws rds describe-db-instances \\",
            "    --db-instance-identifier mydb \\",
            "    --query 'DBInstances[0].IAMDatabaseAuthenticationEnabled'",
            "  # Expected: true",
            "",
            "Lister DB instances sans IAM auth:",
            "  aws rds describe-db-instances \\",
            "    --query 'DBInstances[?IAMDatabaseAuthenticationEnabled==`false`].[DBInstanceIdentifier,Engine]'",
            "",
            "Récupérer Resource ID pour IAM policy:",
            "  aws rds describe-db-instances \\",
            "    --db-instance-identifier mydb \\",
            "    --query 'DBInstances[0].DbiResourceId' \\",
            "    --output text",
            "",
            "Tester génération token (CLI):",
            "  aws rds generate-db-auth-token \\",
            "    --hostname mydb.region.rds.amazonaws.com \\",
            "    --port 3306 \\",
            "    --username iamuser \\",
            "    --region us-east-1",
            "  # Devrait retourner un token JWT-like",
            "",
            "Vérifier DB users IAM (MySQL):",
            "  mysql> SELECT user, host, plugin FROM mysql.user WHERE plugin='AWSAuthenticationPlugin';",
            "",
            "Vérifier DB users IAM (PostgreSQL):",
            "  SELECT rolname FROM pg_roles WHERE rolname IN (",
            "    SELECT member::regrole::text FROM pg_auth_members WHERE roleid = 'rds_iam'::regrole",
            "  );",
            "",
            "Test connexion avec IAM token:",
            "  # Python:",
            "  python test_iam_connection.py",
            "  # Devrait réussir connexion sans erreur",
            "",
            "CloudTrail audit - voir qui obtient tokens:",
            "  aws cloudtrail lookup-events \\",
            "    --lookup-attributes AttributeKey=EventName,AttributeValue=GenerateDataKey \\",
            "    --max-results 50",
            "",
            "Vérifier SSL enforced:",
            "  # MySQL:",
            "  SHOW VARIABLES LIKE 'require_secure_transport';",
            "  # Should be ON",
            "",
            "  # PostgreSQL:",
            "  SHOW ssl;",
            "  # Should be on"
        ],
        references=[
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html",
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.Connecting.html",
            "https://aws.amazon.com/blogs/database/using-iam-authentication-to-connect-with-sql-workbenchj-to-amazon-aurora-mysql-or-amazon-rds-for-mysql/"
        ]
    ),

    Question(
        id="RDS-008",
        question="RDS Proxy déployé pour connection pooling, failover automatique et sécurité credentials?",
        description="Vérifier que RDS Proxy est utilisé pour gérer pool de connexions DB, améliorer failover et stocker credentials de manière sécurisée",
        severity="MEDIUM",
        category="RDS",
        compliance=["AWS Well-Architected", "High Availability"],
        technical_details="""
        RDS Proxy = managed connection pooler pour RDS/Aurora

        Avantages RDS Proxy:
        1. Connection pooling:
           - Réduit overhead connexions DB
           - Réutilise connexions existantes
           - Évite épuisement max_connections DB
           - Idéal pour serverless (Lambda spike)

        2. Improved failover:
           - Détection failure 66% plus rapide qu'app
           - Réduction downtime jusqu'à 79%
           - Connexions préservées pendant failover
           - Transparent pour application

        3. Security:
           - Credentials stockés dans Secrets Manager
           - Rotation automatique sans redémarrage app
           - IAM authentication supportée
           - Enforce SSL/TLS connections
           - Pas de credentials dans code

        4. Observability:
           - CloudWatch metrics détaillées
           - Logs query performance
           - Monitoring connection pool

        Architecture:
        App → RDS Proxy (VPC) → RDS/Aurora
        - Proxy dans subnets privés
        - Security Group control access
        - ENI dans subnet (HA multi-AZ)

        Engines supportés:
        - MySQL (5.6+)
        - PostgreSQL (10+)
        - Aurora MySQL
        - Aurora PostgreSQL
        - MariaDB (10.2+)

        Use cases:
        - Applications serverless (Lambda)
        - Microservices avec bursty traffic
        - Pooling pour réduire connexions DB
        - Failover automatique sans code change
        - Rotation credentials sans downtime

        Pinning vs pooling:
        - Pinned: connexion dédiée (session variables)
        - Pooled: connexions partagées (défaut)
        - Certaines operations forcent pinning (PREPARE)

        Coût:
        - $0.015/hour per vCPU
        - 2 vCPU minimum (HA)
        - ~$22/month minimum

        Limitations:
        - Latency: +1-2ms vs direct connection
        - Pas de support: SQL Server, Oracle
        - Pinning réduit efficiency pooling
        """,
        remediation=[
            "1. Créer secret pour DB credentials:",
            "   aws secretsmanager create-secret \\",
            "     --name rds-db-credentials \\",
            "     --secret-string '{",
            '       "username": "admin",',
            '       "password": "SecurePassword123!",',
            '       "engine": "mysql",',
            '       "host": "mydb.region.rds.amazonaws.com",',
            '       "port": 3306,',
            '       "dbname": "mydb"',
            "     }'",
            "",
            "2. Créer IAM role pour RDS Proxy:",
            "   aws iam create-role \\",
            "     --role-name rds-proxy-role \\",
            "     --assume-role-policy-document '{",
            '       "Version": "2012-10-17",',
            '       "Statement": [{',
            '         "Effect": "Allow",',
            '         "Principal": {"Service": "rds.amazonaws.com"},',
            '         "Action": "sts:AssumeRole"',
            "       }]",
            "     }'",
            "",
            "   # Attacher policy Secrets Manager:",
            "   aws iam attach-role-policy \\",
            "     --role-name rds-proxy-role \\",
            "     --policy-arn arn:aws:iam::aws:policy/SecretsManagerReadWrite",
            "",
            "3. Créer RDS Proxy:",
            "   aws rds create-db-proxy \\",
            "     --db-proxy-name mydb-proxy \\",
            "     --engine-family MYSQL \\",
            "     --auth '[{",
            '       "AuthScheme": "SECRETS",',
            '       "SecretArn": "arn:aws:secretsmanager:region:account:secret:rds-db-credentials",',
            '       "IAMAuth": "DISABLED"',  # or REQUIRED for IAM",
            "     }]' \\",
            "     --role-arn arn:aws:iam::account:role/rds-proxy-role \\",
            "     --vpc-subnet-ids subnet-1 subnet-2 subnet-3 \\",
            "     --require-tls",
            "",
            "4. Configurer target (RDS instance ou Aurora cluster):",
            "   aws rds register-db-proxy-targets \\",
            "     --db-proxy-name mydb-proxy \\",
            "     --db-instance-identifiers mydb",
            "",
            "   # Pour Aurora cluster:",
            "   aws rds register-db-proxy-targets \\",
            "     --db-proxy-name mydb-proxy \\",
            "     --db-cluster-identifiers mycluster",
            "",
            "5. Configurer Security Group proxy:",
            "   aws ec2 authorize-security-group-ingress \\",
            "     --group-id sg-proxy \\",
            "     --protocol tcp \\",
            "     --port 3306 \\",
            "     --source-group sg-app  # Lambda/ECS security group",
            "",
            "6. Modifier DB Security Group (autoriser proxy):",
            "   aws ec2 authorize-security-group-ingress \\",
            "     --group-id sg-db \\",
            "     --protocol tcp \\",
            "     --port 3306 \\",
            "     --source-group sg-proxy",
            "",
            "7. Obtenir endpoint proxy:",
            "   aws rds describe-db-proxies \\",
            "     --db-proxy-name mydb-proxy \\",
            "     --query 'DBProxies[0].Endpoint'",
            "",
            "8. Modifier app pour utiliser proxy endpoint:",
            "   # Au lieu de: mydb.region.rds.amazonaws.com",
            "   # Utiliser: mydb-proxy.proxy-xxxxx.region.rds.amazonaws.com",
            "",
            "   # Python:",
            "   conn = pymysql.connect(",
            "     host='mydb-proxy.proxy-xxxxx.region.rds.amazonaws.com',",
            "     user='admin',",
            "     password='password',  # Ou IAM token",
            "     database='mydb'",
            "   )",
            "",
            "9. Configurer connection pool settings:",
            "   aws rds modify-db-proxy \\",
            "     --db-proxy-name mydb-proxy \\",
            "     --connection-pool-config '{",
            '       "MaxConnectionsPercent": 90,',  # 90% of max_connections",
            '       "MaxIdleConnectionsPercent": 50,',
            '       "ConnectionBorrowTimeout": 120,',  # seconds",
            '       "SessionPinningFilters": ["EXCLUDE_VARIABLE_SETS"]',
            "     }'",
            "",
            "10. Activer CloudWatch Logs:",
            "    aws rds modify-db-proxy \\",
            "      --db-proxy-name mydb-proxy \\",
            "      --debug-logging",
            "",
            "11. Rotation automatique credentials:",
            "    aws secretsmanager rotate-secret \\",
            "      --secret-id rds-db-credentials \\",
            "      --rotation-lambda-arn arn:aws:lambda:region:account:function:SecretsManagerRDSRotation \\",
            "      --rotation-rules AutomaticallyAfterDays=30"
        ],
        verification_steps=[
            "Lister RDS Proxies:",
            "  aws rds describe-db-proxies",
            "",
            "Vérifier status proxy:",
            "  aws rds describe-db-proxies --db-proxy-name mydb-proxy \\",
            "    --query 'DBProxies[0].[DBProxyName,Status,Endpoint,RequireTLS]'",
            "  # Expected Status: available",
            "",
            "Vérifier targets enregistrés:",
            "  aws rds describe-db-proxy-targets --db-proxy-name mydb-proxy",
            "",
            "Test connexion via proxy:",
            "  mysql -h mydb-proxy.proxy-xxxxx.region.rds.amazonaws.com -u admin -p",
            "  # Devrait se connecter normalement",
            "",
            "CloudWatch metrics - connexions:",
            "  aws cloudwatch get-metric-statistics \\",
            "    --namespace AWS/RDS \\",
            "    --metric-name DatabaseConnections \\",
            "    --dimensions Name=DBProxyName,Value=mydb-proxy \\",
            "    --start-time 2024-01-15T00:00:00Z \\",
            "    --end-time 2024-01-15T23:59:59Z \\",
            "    --period 3600 \\",
            "    --statistics Average,Maximum",
            "",
            "Vérifier connection pool efficiency:",
            "  # CloudWatch metric: ClientConnections vs DatabaseConnections",
            "  # Ratio > 1 = pooling works (multiple clients share DB connections)",
            "",
            "Vérifier debug logs (si activé):",
            "  aws logs tail /aws/rds/proxy/mydb-proxy --follow",
            "",
            "Test failover behavior:",
            "  # Déclencher failover Aurora:",
            "  aws rds failover-db-cluster --db-cluster-identifier mycluster",
            "  # App connections via proxy devraient rester up",
            "",
            "Vérifier Security Groups:",
            "  aws ec2 describe-security-groups --group-ids sg-proxy --query 'SecurityGroups[].IpPermissions'",
            "",
            "Vérifier secret rotation:",
            "  aws secretsmanager describe-secret --secret-id rds-db-credentials \\",
            "    --query 'RotationEnabled'",
            "",
            "Performance test - latency overhead:",
            "  # Direct: ~5ms",
            "  # Via Proxy: ~6-7ms (+1-2ms overhead acceptable)"
        ],
        references=[
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.html",
            "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/rds-proxy.html",
            "https://aws.amazon.com/blogs/compute/using-amazon-rds-proxy-with-aws-lambda/"
        ]
    ),

    Question(
        id="RDS-009",
        question="Database audit logging activé et intégré à CloudWatch Logs pour compliance et forensics?",
        description="Vérifier que audit logs sont activés sur RDS/Aurora (query logs, error logs, slow query) et exportés vers CloudWatch pour retention et analyse",
        severity="HIGH",
        category="RDS",
        compliance=["PCI-DSS", "HIPAA", "SOC2", "GDPR", "Audit Trail"],
        technical_details="""
        RDS Audit Logging = capture activité DB pour compliance

        Types de logs RDS:
        1. Error logs:
           - Erreurs DB engine
           - Warnings et informational messages
           - Toujours activé par défaut

        2. Slow query logs (MySQL/MariaDB):
           - Queries > long_query_time threshold
           - Queries sans index (log_queries_not_using_indexes)
           - Performance tuning

        3. General logs (MySQL/MariaDB):
           - Toutes queries SQL
           - Connexions/déconnexions clients
           - ATTENTION: performance impact, volume élevé

        4. Audit logs (MySQL/MariaDB via plugin):
           - Connexions (successful/failed)
           - Queries par user
           - Schema changes (DDL)
           - Compliance requirements

        5. PostgreSQL logs:
           - Connection logs
           - Disconnection logs
           - DDL statements
           - DML statements (configurable)

        Aurora Advanced Auditing:
        - Audit Plugin pour MySQL/MariaDB
        - Capture: CONNECTION, QUERY, TABLE, QUERY_DDL, QUERY_DML
        - Filtrage granulaire par user/database/table
        - Lower performance impact vs general log

        CloudWatch Logs integration:
        - Export automatique logs RDS → CloudWatch
        - Retention configurable (1 jour à 10 ans)
        - Analyse avec CloudWatch Logs Insights
        - Alarmes sur patterns (failed logins, DROP TABLE, etc.)
        - Export S3 pour archivage long-term

        Compliance use cases:
        - PCI-DSS: tracking all access to cardholder data
        - HIPAA: audit trail for PHI access
        - GDPR: logging personal data access
        - SOC2: monitoring privileged operations

        Performance impact:
        - Error logs: minimal
        - Slow query: low (only slow queries)
        - General log: HIGH (avoid in production)
        - Audit log: medium (filter to minimize)

        Retention best practices:
        - Production: 90 days minimum (compliance)
        - CloudWatch: 30-90 days
        - S3 archive: 7 years (regulatory)
        - Glacier: long-term cold storage
        """,
        remediation=[
            "1. Activer slow query log (MySQL/MariaDB):",
            "   # Créer/modifier parameter group:",
            "   aws rds create-db-parameter-group \\",
            "     --db-parameter-group-name mysql-audit-params \\",
            "     --db-parameter-group-family mysql8.0 \\",
            "     --description 'MySQL with audit logging'",
            "",
            "   # Configurer slow query log:",
            "   aws rds modify-db-parameter-group \\",
            "     --db-parameter-group-name mysql-audit-params \\",
            "     --parameters \\",
            "       'ParameterName=slow_query_log,ParameterValue=1,ApplyMethod=immediate' \\",
            "       'ParameterName=long_query_time,ParameterValue=2,ApplyMethod=immediate' \\",
            "       'ParameterName=log_queries_not_using_indexes,ParameterValue=1,ApplyMethod=immediate'",
            "",
            "2. Activer general log (MySQL - USE WITH CAUTION):",
            "   aws rds modify-db-parameter-group \\",
            "     --db-parameter-group-name mysql-audit-params \\",
            "     --parameters 'ParameterName=general_log,ParameterValue=1,ApplyMethod=immediate'",
            "",
            "3. Configurer Aurora MySQL Audit Plugin:",
            "   # Parameter group:",
            "   aws rds modify-db-cluster-parameter-group \\",
            "     --db-cluster-parameter-group-name aurora-mysql-audit \\",
            "     --parameters \\",
            "       'ParameterName=server_audit_logging,ParameterValue=1,ApplyMethod=immediate' \\",
            "       'ParameterName=server_audit_events,ParameterValue=CONNECT,QUERY_DDL,QUERY_DML,ApplyMethod=immediate' \\",
            "       'ParameterName=server_audit_excl_users,ParameterValue=rdsadmin,ApplyMethod=immediate'",
            "",
            "4. PostgreSQL logging configuration:",
            "   aws rds modify-db-parameter-group \\",
            "     --db-parameter-group-name postgres-audit-params \\",
            "     --parameters \\",
            "       'ParameterName=log_connections,ParameterValue=1,ApplyMethod=immediate' \\",
            "       'ParameterName=log_disconnections,ParameterValue=1,ApplyMethod=immediate' \\",
            "       'ParameterName=log_statement,ParameterValue=ddl,ApplyMethod=immediate' \\",
            "       'ParameterName=log_min_duration_statement,ParameterValue=1000,ApplyMethod=immediate'",
            "",
            "5. Associer parameter group à DB:",
            "   aws rds modify-db-instance \\",
            "     --db-instance-identifier mydb \\",
            "     --db-parameter-group-name mysql-audit-params \\",
            "     --apply-immediately",
            "",
            "6. Activer CloudWatch Logs publishing:",
            "   # MySQL:",
            "   aws rds modify-db-instance \\",
            "     --db-instance-identifier mydb \\",
            "     --cloudwatch-logs-export-configuration '{",
            '       "LogTypesToEnable": ["error", "general", "slowquery", "audit"]',
            "     }'",
            "",
            "   # PostgreSQL:",
            "   aws rds modify-db-instance \\",
            "     --db-instance-identifier mydb \\",
            "     --cloudwatch-logs-export-configuration '{",
            '       "LogTypesToEnable": ["postgresql"]',
            "     }'",
            "",
            "   # Aurora:",
            "   aws rds modify-db-cluster \\",
            "     --db-cluster-identifier mycluster \\",
            "     --cloudwatch-logs-export-configuration '{",
            '       "LogTypesToEnable": ["audit", "error", "general", "slowquery"]',
            "     }'",
            "",
            "7. Configurer CloudWatch Logs retention:",
            "   aws logs put-retention-policy \\",
            "     --log-group-name /aws/rds/instance/mydb/audit \\",
            "     --retention-in-days 90",
            "",
            "8. Créer metric filter pour failed logins:",
            "   aws logs put-metric-filter \\",
            "     --log-group-name /aws/rds/instance/mydb/audit \\",
            "     --filter-name FailedLogins \\",
            "     --filter-pattern '[time, thread, type=FAILED_CONNECT*, ...]' \\",
            "     --metric-transformations \\",
            "       'metricName=FailedLoginAttempts,metricNamespace=RDS/Security,metricValue=1'",
            "",
            "9. Créer CloudWatch Alarm sur failed logins:",
            "   aws cloudwatch put-metric-alarm \\",
            "     --alarm-name rds-failed-logins \\",
            "     --metric-name FailedLoginAttempts \\",
            "     --namespace RDS/Security \\",
            "     --statistic Sum \\",
            "     --period 300 \\",
            "     --evaluation-periods 1 \\",
            "     --threshold 5 \\",
            "     --comparison-operator GreaterThanThreshold \\",
            "     --alarm-actions arn:aws:sns:region:account:security-alerts",
            "",
            "10. Metric filter pour DDL changes:",
            "    aws logs put-metric-filter \\",
            "      --log-group-name /aws/rds/instance/mydb/audit \\",
            "      --filter-name DDLChanges \\",
            "      --filter-pattern '[..., query=*DROP* || query=*ALTER* || query=*CREATE*]' \\",
            "      --metric-transformations \\",
            "        'metricName=DDLOperations,metricNamespace=RDS/Security,metricValue=1'",
            "",
            "11. Export vers S3 pour archivage long-term:",
            "    aws logs create-export-task \\",
            "      --log-group-name /aws/rds/instance/mydb/audit \\",
            "      --from $(date -d '30 days ago' +%s)000 \\",
            "      --to $(date +%s)000 \\",
            "      --destination rds-audit-logs-archive \\",
            "      --destination-prefix rds/mydb/audit/",
            "",
            "12. Analyse avec CloudWatch Logs Insights:",
            "    # Top 10 users par nombre de queries:",
            "    fields @timestamp, user, query",
            "    | stats count() by user",
            "    | sort count desc",
            "    | limit 10"
        ],
        verification_steps=[
            "Vérifier parameter group logging config:",
            "  aws rds describe-db-parameters \\",
            "    --db-parameter-group-name mysql-audit-params \\",
            "    --query 'Parameters[?ParameterName==`slow_query_log` || ParameterName==`general_log` || ParameterName==`server_audit_logging`]'",
            "",
            "Vérifier CloudWatch Logs enabled:",
            "  aws rds describe-db-instances --db-instance-identifier mydb \\",
            "    --query 'DBInstances[0].EnabledCloudwatchLogsExports'",
            "  # Expected: [\"error\", \"slowquery\", \"audit\"]",
            "",
            "Lister DB instances sans audit logging:",
            "  aws rds describe-db-instances \\",
            "    --query 'DBInstances[?!EnabledCloudwatchLogsExports || length(EnabledCloudwatchLogsExports)==`0`].[DBInstanceIdentifier]'",
            "",
            "Vérifier log groups créés:",
            "  aws logs describe-log-groups --log-group-name-prefix /aws/rds/",
            "",
            "Consulter recent audit logs:",
            "  aws logs tail /aws/rds/instance/mydb/audit --follow --since 10m",
            "",
            "CloudWatch Logs Insights - failed login attempts:",
            "  Query:",
            "  fields @timestamp, @message",
            "  | filter @message like /FAILED_CONNECT/",
            "  | stats count() by bin(5m)",
            "",
            "CloudWatch Logs Insights - DDL operations:",
            "  Query:",
            "  fields @timestamp, user, query",
            "  | filter query like /DROP|ALTER|CREATE/",
            "  | sort @timestamp desc",
            "",
            "Vérifier retention policy:",
            "  aws logs describe-log-groups \\",
            "    --log-group-name-prefix /aws/rds/ \\",
            "    --query 'logGroups[].[logGroupName,retentionInDays]'",
            "",
            "Vérifier metric filters configurés:",
            "  aws logs describe-metric-filters \\",
            "    --log-group-name /aws/rds/instance/mydb/audit",
            "",
            "Vérifier alarmes actives:",
            "  aws cloudwatch describe-alarms --alarm-name-prefix rds-",
            "",
            "Test: déclencher failed login et vérifier log:",
            "  mysql -h mydb.region.rds.amazonaws.com -u wronguser -p",
            "  # Puis vérifier dans CloudWatch Logs",
            "",
            "Performance impact check:",
            "  # Comparer CPU/IOPS avant et après activation general log",
            "  # General log peut ajouter 10-30% overhead CPU"
        ],
        references=[
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.html",
            "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Auditing.html",
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.Procedural.UploadtoCloudWatch.html",
            "https://aws.amazon.com/blogs/database/auditing-an-amazon-aurora-cluster/"
        ]
    )
]

# ==================== LAMBDA & SERVERLESS ====================
LAMBDA_QUESTIONS = [
    Question(
        id="LAMBDA-001",
        question="Lambda execution roles suivent principe least privilege, avec managed policies ou inline policies minimales?",
        description="Vérifier IAM execution roles Lambda avec permissions strictement nécessaires, pas de wildcard excessif",
        severity="HIGH",
        category="Lambda",
        compliance=["AWS Well-Architected", "CIS Benchmark", "SOC2"],
        technical_details="""
        Lambda IAM Execution Role security:

        Execution Role:
        - IAM role assumé par Lambda lors de l'exécution
        - Définit les permissions AWS services que Lambda peut utiliser
        - Trust policy permettant lambda.amazonaws.com d'assume role

        Principe Least Privilege:
        - Permissions minimales strictement nécessaires
        - Éviter AmazonLambdaFullAccess ou policies wildcard
        - Scope resources avec ARNs spécifiques
        - Utiliser conditions IAM quand possible

        Policies communes (mais trop permissives):
        - AWSLambdaBasicExecutionRole: logs CloudWatch (OK)
        - AWSLambdaVPCAccessExecutionRole: ENI VPC (OK si VPC)
        - AWSLambdaFullAccess: TROP PERMISSIF, ne jamais utiliser

        Best practices:
        - Un role par fonction ou groupe de fonctions similaires
        - Inline policies pour permissions spécifiques
        - Resource-based policies pour cross-account access
        - Monitorer avec CloudTrail & Access Analyzer

        Resource-based policies:
        - Contrôle qui peut invoke la fonction
        - S3, SNS, EventBridge peuvent invoke avec resource policy
        - Préférer resource policy à IAM role pour cross-account

        Permission boundaries:
        - Limite maximale de permissions qu'un role peut avoir
        - Utile dans organisations multi-équipes
        """,
        remediation=[
            "1. Créer execution role minimal pour Lambda logging:",
            "   aws iam create-role \\",
            "     --role-name lambda-basic-execution \\",
            "     --assume-role-policy-document '{",
            '       "Version": "2012-10-17",',
            '       "Statement": [{',
            '         "Effect": "Allow",',
            '         "Principal": {"Service": "lambda.amazonaws.com"},',
            '         "Action": "sts:AssumeRole"',
            "       }]",
            "     }'",
            "",
            "   aws iam attach-role-policy \\",
            "     --role-name lambda-basic-execution \\",
            "     --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            "",
            "2. Créer inline policy pour DynamoDB (exemple):",
            "   aws iam put-role-policy \\",
            "     --role-name lambda-dynamodb-reader \\",
            "     --policy-name ReadDynamoDBTable \\",
            "     --policy-document '{",
            '       "Version": "2012-10-17",',
            '       "Statement": [{',
            '         "Effect": "Allow",',
            '         "Action": ["dynamodb:GetItem", "dynamodb:Query"],',
            '         "Resource": "arn:aws:dynamodb:us-east-1:account:table/MyTable"',
            "       }]",
            "     }'",
            "",
            "3. Attacher role à fonction Lambda:",
            "   aws lambda create-function \\",
            "     --function-name myfunction \\",
            "     --runtime python3.11 \\",
            "     --role arn:aws:iam::account:role/lambda-basic-execution \\",
            "     --handler index.handler \\",
            "     --zip-file fileb://function.zip",
            "",
            "4. Update existing function avec nouveau role:",
            "   aws lambda update-function-configuration \\",
            "     --function-name myfunction \\",
            "     --role arn:aws:iam::account:role/lambda-minimal-role",
            "",
            "5. Ajouter resource-based policy (allow S3 invoke):",
            "   aws lambda add-permission \\",
            "     --function-name myfunction \\",
            "     --statement-id s3-invoke \\",
            "     --action lambda:InvokeFunction \\",
            "     --principal s3.amazonaws.com \\",
            "     --source-arn arn:aws:s3:::mybucket",
            "",
            "6. Utiliser IAM Access Analyzer pour trouver overly permissive roles:",
            "   aws accessanalyzer list-findings \\",
            "     --analyzer-arn arn:aws:access-analyzer:region:account:analyzer/ConsoleAnalyzer",
            "",
            "7. Créer permission boundary:",
            "   aws iam put-role-permissions-boundary \\",
            "     --role-name lambda-dev-role \\",
            "     --permissions-boundary arn:aws:iam::account:policy/LambdaPermissionBoundary"
        ],
        verification_steps=[
            "Lister toutes Lambda functions et leurs roles:",
            "  aws lambda list-functions \\",
            "    --query 'Functions[].[FunctionName,Role]' \\",
            "    --output table",
            "",
            "Vérifier policies attachées au role:",
            "  ROLE_NAME=$(aws lambda get-function --function-name myfunction --query 'Configuration.Role' --output text | awk -F'/' '{print $NF}')",
            "",
            "  aws iam list-attached-role-policies --role-name $ROLE_NAME",
            "  aws iam list-role-policies --role-name $ROLE_NAME",
            "",
            "Identifier functions avec policies trop permissives:",
            "  for func in $(aws lambda list-functions --query 'Functions[].FunctionName' --output text); do",
            "    role=$(aws lambda get-function --function-name $func --query 'Configuration.Role' --output text)",
            "    role_name=$(echo $role | awk -F'/' '{print $NF}')",
            "    policies=$(aws iam list-attached-role-policies --role-name $role_name --query 'AttachedPolicies[].PolicyName' --output text)",
            "    if echo $policies | grep -q 'FullAccess\\|Admin'; then",
            "      echo \"OVERPERMISSIVE: $func - $role_name - $policies\"",
            "    fi",
            "  done",
            "",
            "Obtenir policy document:",
            "  aws iam get-role-policy --role-name lambda-role --policy-name MyPolicy",
            "",
            "Vérifier resource-based policy de la fonction:",
            "  aws lambda get-policy --function-name myfunction",
            "",
            "Vérifier dernière utilisation des permissions (CloudTrail):",
            "  aws cloudtrail lookup-events \\",
            "    --lookup-attributes AttributeKey=Username,AttributeValue=lambda-role \\",
            "    --max-results 50",
            "",
            "IAM Access Analyzer findings:",
            "  aws accessanalyzer list-findings \\",
            "    --analyzer-arn arn:aws:access-analyzer:region:account:analyzer/ConsoleAnalyzer \\",
            "    --filter '{\"resourceType\":{\"eq\":[\"AWS::Lambda::Function\"]}}'",
            "",
            "Vérifier permission boundaries:",
            "  aws iam get-role --role-name lambda-role --query 'Role.PermissionsBoundary'"
        ],
        references=[
            "https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html",
            "https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html"
        ]
    ),

    Question(
        id="LAMBDA-002",
        question="Secrets (credentials, API keys) stockés dans Secrets Manager ou Parameter Store avec encryption KMS, pas en environment variables?",
        description="Vérifier que secrets Lambda utilisent Secrets Manager/Parameter Store chiffrés KMS au lieu de plaintext env vars",
        severity="CRITICAL",
        category="Lambda",
        compliance=["PCI-DSS", "HIPAA", "SOC2", "ISO 27001"],
        technical_details="""
        Lambda Secrets Management:

        Problèmes avec environment variables:
        - Visibles en plaintext dans console Lambda
        - Apparaissent dans CloudTrail logs
        - Stockées non chiffrées par défaut
        - Accessibles à quiconque a lambda:GetFunction
        - Max 4KB de env vars total

        AWS Secrets Manager:
        - Stockage chiffré avec KMS
        - Rotation automatique des credentials
        - Versioning des secrets
        - Fine-grained IAM access control
        - Audit via CloudTrail
        - Coût: $0.40/secret/month + $0.05 per 10k API calls

        AWS Systems Manager Parameter Store:
        - Standard parameters: gratuit
        - SecureString: chiffrement KMS
        - Advanced parameters: 8KB max
        - Parameter hierarchies (/prod/db/password)
        - Parameter policies (expiration, notification)

        Retrieval depuis Lambda:
        - SDK call dans function code (boto3)
        - Lambda extension pour caching local
        - Reduce latency avec caching
        - IAM permissions requises sur secret

        Best practices:
        - Un secret par credential/API key
        - Rotation automatique (RDS, Aurora)
        - Caching dans Lambda avec TTL court
        - Monitorer accès avec CloudTrail
        - Utiliser VPC endpoints pour Secrets Manager

        Lambda extension for parameters:
        - AWS Parameters and Secrets Lambda Extension
        - Cache local dans /tmp
        - HTTP API local (localhost:2773)
        - Réduit latency & coût API calls
        """,
        remediation=[
            "1. Créer secret dans Secrets Manager:",
            "   aws secretsmanager create-secret \\",
            "     --name prod/myapp/dbpassword \\",
            "     --description 'Production database password' \\",
            "     --secret-string '{\"username\":\"admin\",\"password\":\"xxx\",\"host\":\"db.example.com\"}'",
            "",
            "2. Créer secret avec KMS key spécifique:",
            "   aws secretsmanager create-secret \\",
            "     --name prod/api-key \\",
            "     --kms-key-id arn:aws:kms:region:account:key/xxxx \\",
            "     --secret-string 'my-api-key-value'",
            "",
            "3. Créer SecureString dans Parameter Store:",
            "   aws ssm put-parameter \\",
            "     --name /prod/myapp/dbpassword \\",
            "     --value 'mypassword' \\",
            "     --type SecureString \\",
            "     --key-id alias/aws/ssm \\",
            "     --description 'DB password'",
            "",
            "4. Ajouter IAM permissions au Lambda role:",
            "   {",
            '     "Effect": "Allow",',
            '     "Action": [',
            '       "secretsmanager:GetSecretValue",',
            '       "kms:Decrypt"',
            "     ],",
            '     "Resource": [',
            '       "arn:aws:secretsmanager:region:account:secret:prod/myapp/*",',
            '       "arn:aws:kms:region:account:key/xxxx"',
            "     ]",
            "   }",
            "",
            "5. Retrieval dans Lambda code (Python):",
            "   import boto3",
            "   import json",
            "",
            "   client = boto3.client('secretsmanager')",
            "   response = client.get_secret_value(SecretId='prod/myapp/dbpassword')",
            "   secret = json.loads(response['SecretString'])",
            "   db_password = secret['password']",
            "",
            "6. Avec caching pour réduire coût:",
            "   import boto3",
            "   from functools import lru_cache",
            "",
            "   @lru_cache(maxsize=1)",
            "   def get_secret():",
            "       client = boto3.client('secretsmanager')",
            "       return client.get_secret_value(SecretId='prod/myapp/dbpassword')",
            "",
            "7. Utiliser Lambda Extension (alternative):",
            "   # Ajouter layer: arn:aws:lambda:region:AWS_ACCOUNT:layer:AWS-Parameters-and-Secrets-Lambda-Extension:VERSION",
            "   # Dans code:",
            "   import requests",
            "   url = 'http://localhost:2773/secretsmanager/get?secretId=prod/myapp/dbpassword'",
            "   headers = {'X-Aws-Parameters-Secrets-Token': os.environ['AWS_SESSION_TOKEN']}",
            "   response = requests.get(url, headers=headers)",
            "",
            "8. Activer rotation automatique:",
            "   aws secretsmanager rotate-secret \\",
            "     --secret-id prod/myapp/dbpassword \\",
            "     --rotation-lambda-arn arn:aws:lambda:region:account:function:SecretsManagerRotation \\",
            "     --rotation-rules AutomaticallyAfterDays=30"
        ],
        verification_steps=[
            "Lister functions avec environment variables (suspects):",
            "  aws lambda list-functions \\",
            "    --query 'Functions[?Environment!=`null`].[FunctionName,Environment.Variables]' \\",
            "    --output json",
            "",
            "Identifier env vars contenant mots-clés sensibles:",
            "  for func in $(aws lambda list-functions --query 'Functions[].FunctionName' --output text); do",
            "    env_vars=$(aws lambda get-function-configuration --function-name $func --query 'Environment.Variables' --output json 2>/dev/null)",
            "    if echo $env_vars | grep -iE 'password|secret|key|token|credential' > /dev/null; then",
            "      echo \"POTENTIAL SECRET in $func: $env_vars\"",
            "    fi",
            "  done",
            "",
            "Lister secrets dans Secrets Manager:",
            "  aws secretsmanager list-secrets --query 'SecretList[].[Name,KmsKeyId,LastAccessedDate]' --output table",
            "",
            "Vérifier quelles Lambda ont accès Secrets Manager:",
            "  for func in $(aws lambda list-functions --query 'Functions[].FunctionName' --output text); do",
            "    role=$(aws lambda get-function --function-name $func --query 'Configuration.Role' --output text | awk -F'/' '{print $NF}')",
            "    policies=$(aws iam get-role-policy --role-name $role --policy-name SecretsManagerAccess 2>/dev/null)",
            "    if [ $? -eq 0 ]; then",
            "      echo \"$func has Secrets Manager access\"",
            "    fi",
            "  done",
            "",
            "Vérifier accès aux secrets via CloudTrail:",
            "  aws cloudtrail lookup-events \\",
            "    --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \\",
            "    --max-results 50",
            "",
            "Lister SecureString parameters:",
            "  aws ssm describe-parameters \\",
            "    --query 'Parameters[?Type==`SecureString`].[Name,KeyId,LastModifiedDate]' \\",
            "    --output table",
            "",
            "Audit rotation des secrets:",
            "  aws secretsmanager describe-secret --secret-id prod/myapp/dbpassword \\",
            "    --query '[RotationEnabled,RotationLambdaARN,RotationRules]'",
            "",
            "Vérifier KMS key utilisée:",
            "  aws secretsmanager describe-secret --secret-id prod/myapp/dbpassword \\",
            "    --query 'KmsKeyId'"
        ],
        references=[
            "https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html",
            "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html",
            "https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets_lambda.html"
        ]
    ),

    Question(
        id="LAMBDA-003",
        question="Lambda functions dans VPC avec security groups restrictifs si accès ressources privées (RDS, ElastiCache)?",
        description="Vérifier configuration VPC Lambda pour accès sécurisé aux ressources privées avec SG appropriés",
        severity="HIGH",
        category="Lambda",
        compliance=["AWS Well-Architected", "CIS Benchmark"],
        technical_details="""
        Lambda VPC configuration:

        Quand utiliser VPC:
        - Accès RDS/Aurora dans VPC privé
        - Accès ElastiCache, Redshift
        - Accès ressources on-premise via VPN/Direct Connect
        - Compliance requiert network isolation

        Quand ne PAS utiliser VPC:
        - Accès uniquement services publics AWS (S3, DynamoDB, etc.)
        - Meilleure performance (no cold start VPC ENI)
        - Utiliser VPC endpoints pour S3/DynamoDB si needed

        VPC Lambda architecture:
        - Lambda crée ENI (Elastic Network Interface) dans subnets
        - ENI persistent après cold start (depuis 2019 improvement)
        - Un ENI partagé par multiples concurrent executions
        - Attaché aux security groups spécifiés

        Cold start considerations:
        - Premier invoke: 10-30s pour créer ENI (pre-2019)
        - Maintenant: ENI préalloués, cold start minimal
        - Hyperplane ENIs: partage cross-functions

        Security Groups:
        - Outbound: autoriser accès RDS, ElastiCache (port 3306, 6379, etc.)
        - Inbound: généralement vide (Lambda initie connections)
        - SG du RDS doit autoriser inbound depuis SG Lambda

        Subnets:
        - Utiliser private subnets (pas d'IGW direct)
        - Minimum 2 subnets dans 2 AZs (HA)
        - NAT Gateway requis si Lambda doit accéder internet

        Internet access depuis VPC Lambda:
        - Route via NAT Gateway dans subnet public
        - Ou VPC endpoints pour services AWS (S3, DynamoDB, etc.)
        - PrivateLink endpoints pour Secrets Manager, etc.

        IAM permissions requises:
        - ec2:CreateNetworkInterface
        - ec2:DescribeNetworkInterfaces
        - ec2:DeleteNetworkInterface
        - AWSLambdaVPCAccessExecutionRole managed policy

        Best practices:
        - Dédier subnets pour Lambda uniquement
        - Prévoir suffisamment d'IPs (/24 minimum)
        - Monitorer ENI utilization
        """,
        remediation=[
            "1. Créer security group pour Lambda:",
            "   aws ec2 create-security-group \\",
            "     --group-name lambda-sg \\",
            "     --description 'Security group for Lambda functions' \\",
            "     --vpc-id vpc-xxxxx",
            "",
            "2. Autoriser outbound vers RDS (exemple):",
            "   aws ec2 authorize-security-group-egress \\",
            "     --group-id sg-lambda \\",
            "     --protocol tcp \\",
            "     --port 3306 \\",
            "     --source-group sg-rds",
            "",
            "3. Update RDS security group (inbound depuis Lambda):",
            "   aws ec2 authorize-security-group-ingress \\",
            "     --group-id sg-rds \\",
            "     --protocol tcp \\",
            "     --port 3306 \\",
            "     --source-group sg-lambda",
            "",
            "4. Ajouter Lambda au VPC:",
            "   aws lambda update-function-configuration \\",
            "     --function-name myfunction \\",
            "     --vpc-config SubnetIds=subnet-xxx,subnet-yyy,SecurityGroupIds=sg-lambda",
            "",
            "5. Ajouter VPC execution permissions au role:",
            "   aws iam attach-role-policy \\",
            "     --role-name lambda-vpc-role \\",
            "     --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole",
            "",
            "6. Créer VPC endpoint pour S3 (éviter NAT Gateway):",
            "   aws ec2 create-vpc-endpoint \\",
            "     --vpc-id vpc-xxxxx \\",
            "     --service-name com.amazonaws.region.s3 \\",
            "     --route-table-ids rtb-xxxxx",
            "",
            "7. Créer VPC endpoint pour Secrets Manager:",
            "   aws ec2 create-vpc-endpoint \\",
            "     --vpc-id vpc-xxxxx \\",
            "     --vpc-endpoint-type Interface \\",
            "     --service-name com.amazonaws.region.secretsmanager \\",
            "     --subnet-ids subnet-xxx subnet-yyy \\",
            "     --security-group-ids sg-endpoints",
            "",
            "8. Remove Lambda from VPC (si plus nécessaire):",
            "   aws lambda update-function-configuration \\",
            "     --function-name myfunction \\",
            "     --vpc-config SubnetIds=[],SecurityGroupIds=[]"
        ],
        verification_steps=[
            "Lister Lambda functions avec VPC config:",
            "  aws lambda list-functions \\",
            "    --query 'Functions[?VpcConfig.VpcId!=`null`].[FunctionName,VpcConfig.VpcId,VpcConfig.SubnetIds,VpcConfig.SecurityGroupIds]' \\",
            "    --output table",
            "",
            "Identifier functions SANS VPC mais accédant RDS:",
            "  # Nécessite analyse code ou environnement",
            "  for func in $(aws lambda list-functions --query 'Functions[?VpcConfig.VpcId==`null`].FunctionName' --output text); do",
            "    env=$(aws lambda get-function-configuration --function-name $func --query 'Environment.Variables' --output json)",
            "    if echo $env | grep -iE 'rds|database|db_host' > /dev/null; then",
            "      echo \"POTENTIAL ISSUE: $func accesses RDS but not in VPC\"",
            "    fi",
            "  done",
            "",
            "Vérifier security groups Lambda:",
            "  aws lambda get-function-configuration --function-name myfunction \\",
            "    --query 'VpcConfig.SecurityGroupIds'",
            "",
            "Inspecter security group rules:",
            "  SG_ID=$(aws lambda get-function-configuration --function-name myfunction --query 'VpcConfig.SecurityGroupIds[0]' --output text)",
            "  aws ec2 describe-security-groups --group-ids $SG_ID",
            "",
            "Vérifier subnets utilisés:",
            "  aws lambda get-function-configuration --function-name myfunction \\",
            "    --query 'VpcConfig.SubnetIds[]' --output table",
            "",
            "Vérifier disponibilité IPs dans subnets Lambda:",
            "  for subnet in subnet-xxx subnet-yyy; do",
            "    aws ec2 describe-subnets --subnet-ids $subnet \\",
            "      --query 'Subnets[].[SubnetId,AvailableIpAddressCount,CidrBlock]'",
            "  done",
            "",
            "Vérifier NAT Gateway pour internet access:",
            "  aws ec2 describe-nat-gateways \\",
            "    --filter Name=vpc-id,Values=vpc-xxxxx \\",
            "    --query 'NatGateways[].[NatGatewayId,State,SubnetId]'",
            "",
            "Lister VPC endpoints configurés:",
            "  aws ec2 describe-vpc-endpoints \\",
            "    --filters Name=vpc-id,Values=vpc-xxxxx \\",
            "    --query 'VpcEndpoints[].[VpcEndpointId,ServiceName,State]' \\",
            "    --output table",
            "",
            "Vérifier ENI créées par Lambda:",
            "  aws ec2 describe-network-interfaces \\",
            "    --filters Name=description,Values='AWS Lambda VPC ENI*' \\",
            "    --query 'NetworkInterfaces[].[NetworkInterfaceId,Status,PrivateIpAddress,SubnetId]'"
        ],
        references=[
            "https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html",
            "https://aws.amazon.com/blogs/compute/announcing-improved-vpc-networking-for-aws-lambda-functions/",
            "https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc-endpoints.html"
        ]
    ),

    Question(
        id="LAMBDA-004",
        question="Reserved concurrency configurée pour functions critiques et throttling pour éviter runaway costs?",
        description="Vérifier gestion concurrence Lambda avec reserved concurrency, provisioned concurrency, et limites appropriées",
        severity="MEDIUM",
        category="Lambda",
        compliance=["AWS Well-Architected", "FinOps"],
        technical_details="""
        Lambda Concurrency Management:

        Account-level concurrency limit:
        - Default: 1000 concurrent executions par région
        - Peut être augmenté via support ticket
        - Partagé entre toutes fonctions dans région

        Reserved Concurrency:
        - Réserve un pool de concurrency pour fonction
        - Garantit que fonction peut scale jusqu'à ce nombre
        - Réduit concurrency disponible pour autres fonctions
        - Use case: fonctions critiques, SLA garantees

        Unreserved Concurrency:
        - Pool partagé: account limit - sum(reserved)
        - Minimum 100 pour unreserved pool
        - Fonctions sans reserved puisent dans ce pool

        Provisioned Concurrency:
        - Pre-warm instances toujours prêts
        - Zero cold start latency
        - Coût: $0.015/GB-hour provisioned
        - Use case: latency-sensitive APIs, real-time

        Throttling behavior:
        - Si concurrency dépassée: HTTP 429 TooManyRequestsException
        - Synchronous invoke: erreur au client
        - Asynchronous (SQS, SNS): retry automatique 2x, puis DLQ
        - Event source (Kinesis, DynamoDB): retries jusqu'à data expiration

        Burst concurrency:
        - Initial burst: 3000 (us-east-1, us-west-2, eu-west-1)
        - Initial burst: 1000 (autres régions)
        - Puis: +500 per minute

        Cost implications:
        - Runaway concurrency = runaway costs
        - Mettre reserved concurrency pour cap costs
        - Monitorer ConcurrentExecutions metric

        Monitoring:
        - CloudWatch: ConcurrentExecutions
        - CloudWatch: Throttles
        - CloudWatch: UnreservedConcurrentExecutions
        """,
        remediation=[
            "1. Vérifier account-level concurrency limit:",
            "   aws service-quotas get-service-quota \\",
            "     --service-code lambda \\",
            "     --quota-code L-B99A9384",
            "",
            "2. Demander augmentation limite (si nécessaire):",
            "   aws service-quotas request-service-quota-increase \\",
            "     --service-code lambda \\",
            "     --quota-code L-B99A9384 \\",
            "     --desired-value 3000",
            "",
            "3. Set reserved concurrency pour fonction critique:",
            "   aws lambda put-function-concurrency \\",
            "     --function-name critical-function \\",
            "     --reserved-concurrent-executions 100",
            "",
            "   Note: garantit 100 concurrent executions disponibles",
            "",
            "4. Set reserved concurrency pour limiter coût:",
            "   aws lambda put-function-concurrency \\",
            "     --function-name dev-function \\",
            "     --reserved-concurrent-executions 10",
            "",
            "   Cap à 10 concurrent executions (cost control)",
            "",
            "5. Remove reserved concurrency:",
            "   aws lambda delete-function-concurrency --function-name myfunction",
            "",
            "6. Configure provisioned concurrency:",
            "   aws lambda put-provisioned-concurrency-config \\",
            "     --function-name api-function \\",
            "     --provisioned-concurrent-executions 50 \\",
            "     --qualifier prod",
            "",
            "   Note: nécessite function version ou alias",
            "",
            "7. Auto-scaling provisioned concurrency:",
            "   aws application-autoscaling register-scalable-target \\",
            "     --service-namespace lambda \\",
            "     --resource-id function:api-function:prod \\",
            "     --scalable-dimension lambda:function:ProvisionedConcurrentExecutions \\",
            "     --min-capacity 5 \\",
            "     --max-capacity 50",
            "",
            "   aws application-autoscaling put-scaling-policy \\",
            "     --policy-name lambda-scaling-policy \\",
            "     --service-namespace lambda \\",
            "     --resource-id function:api-function:prod \\",
            "     --scalable-dimension lambda:function:ProvisionedConcurrentExecutions \\",
            "     --policy-type TargetTrackingScaling \\",
            "     --target-tracking-scaling-policy-configuration '{",
            '       "TargetValue": 0.70,',
            '       "PredefinedMetricSpecification": {',
            '         "PredefinedMetricType": "LambdaProvisionedConcurrencyUtilization"',
            "       }",
            "     }'",
            "",
            "8. Créer alarme sur throttling:",
            "   aws cloudwatch put-metric-alarm \\",
            "     --alarm-name lambda-throttling \\",
            "     --alarm-description 'Lambda function throttled' \\",
            "     --metric-name Throttles \\",
            "     --namespace AWS/Lambda \\",
            "     --statistic Sum \\",
            "     --period 60 \\",
            "     --evaluation-periods 1 \\",
            "     --threshold 1 \\",
            "     --comparison-operator GreaterThanThreshold \\",
            "     --dimensions Name=FunctionName,Value=myfunction"
        ],
        verification_steps=[
            "Vérifier account concurrency limit:",
            "  aws lambda get-account-settings --query 'AccountLimit.ConcurrentExecutions'",
            "",
            "Lister functions avec reserved concurrency:",
            "  aws lambda list-functions \\",
            "    --query 'Functions[?ReservedConcurrentExecutions!=`null`].[FunctionName,ReservedConcurrentExecutions]' \\",
            "    --output table",
            "",
            "Calculer unreserved pool disponible:",
            "  TOTAL=$(aws lambda get-account-settings --query 'AccountLimit.ConcurrentExecutions' --output text)",
            "  RESERVED=$(aws lambda list-functions --query 'sum(Functions[].ReservedConcurrentExecutions)')",
            "  echo \"Unreserved pool: $((TOTAL - RESERVED))\"",
            "",
            "Vérifier provisioned concurrency:",
            "  aws lambda get-provisioned-concurrency-config \\",
            "    --function-name api-function \\",
            "    --qualifier prod",
            "",
            "Monitorer concurrent executions temps réel:",
            "  aws cloudwatch get-metric-statistics \\",
            "    --namespace AWS/Lambda \\",
            "    --metric-name ConcurrentExecutions \\",
            "    --dimensions Name=FunctionName,Value=myfunction \\",
            "    --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \\",
            "    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \\",
            "    --period 60 \\",
            "    --statistics Maximum",
            "",
            "Vérifier throttling events:",
            "  aws cloudwatch get-metric-statistics \\",
            "    --namespace AWS/Lambda \\",
            "    --metric-name Throttles \\",
            "    --dimensions Name=FunctionName,Value=myfunction \\",
            "    --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%S) \\",
            "    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \\",
            "    --period 3600 \\",
            "    --statistics Sum",
            "",
            "Identifier functions sans concurrency limits (cost risk):",
            "  aws lambda list-functions \\",
            "    --query 'Functions[?ReservedConcurrentExecutions==`null`].[FunctionName]' \\",
            "    --output table",
            "",
            "Coût estimé provisioned concurrency:",
            "  # $0.015 per GB-hour",
            "  # Exemple: 50 provisioned x 1GB x 730h/month = 50 x 730 x 0.015 = $547.50/month"
        ],
        references=[
            "https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html",
            "https://docs.aws.amazon.com/lambda/latest/dg/provisioned-concurrency.html",
            "https://aws.amazon.com/blogs/compute/managing-aws-lambda-function-concurrency/"
        ]
    ),

    Question(
        id="LAMBDA-005",
        question="Dead Letter Queue (DLQ) configurée pour asynchronous invocations et X-Ray tracing activé pour debugging?",
        description="Vérifier DLQ SQS/SNS pour failed async invocations et X-Ray pour distributed tracing et performance analysis",
        severity="MEDIUM",
        category="Lambda",
        compliance=["AWS Well-Architected", "Observability"],
        technical_details="""
        Lambda Error Handling & Observability:

        Dead Letter Queue (DLQ):
        - Capture failed async Lambda invocations
        - Après 2 retries automatiques (total 3 tentatives)
        - DLQ peut être SQS queue ou SNS topic
        - Messages contiennent payload + error details
        - Permet investigation et reprocessing

        Async invocation sources:
        - S3 events
        - SNS notifications
        - EventBridge rules
        - SES email actions
        - CloudWatch Logs subscription filters

        DLQ vs Destinations:
        - DLQ: legacy, envoie vers SQS/SNS uniquement
        - Destinations: modern, plus options (S3, EventBridge, Lambda, SQS, SNS)
        - Destinations: separate success vs failure
        - Recommandation: Destinations over DLQ

        Event source mapping failures:
        - Kinesis, DynamoDB Streams, SQS: different error handling
        - Pas de DLQ, utiliser event source mapping config
        - On-Failure Destination pour Kinesis/DynamoDB

        X-Ray Tracing:
        - Distributed tracing pour Lambda + downstream services
        - Visualize service map et latency
        - Identify bottlenecks et errors
        - Active ou PassThrough mode

        X-Ray data collecté:
        - Latency distribution
        - HTTP requests traces
        - SQL queries (avec instrumentation)
        - AWS SDK calls (DynamoDB, S3, etc.)
        - Subsegments pour custom logic

        X-Ray coût:
        - $5 per million traces recorded
        - $0.50 per million traces retrieved/scanned
        - Free tier: 100k traces/month

        Sampling:
        - Réduit coût avec sampling rules
        - Default: 1 request/second + 5% de reste
        - Custom rules par route, service, etc.

        CloudWatch Logs vs X-Ray:
        - Logs: text-based, debugging details
        - X-Ray: visual traces, performance analysis
        - Complémentaires, utiliser les deux
        """,
        remediation=[
            "1. Créer SQS queue pour DLQ:",
            "   aws sqs create-queue --queue-name lambda-dlq",
            "",
            "2. Configurer DLQ sur Lambda function:",
            "   aws lambda update-function-configuration \\",
            "     --function-name myfunction \\",
            "     --dead-letter-config TargetArn=arn:aws:sqs:region:account:lambda-dlq",
            "",
            "3. Ajouter IAM permissions pour DLQ:",
            "   {",
            '     "Effect": "Allow",',
            '     "Action": ["sqs:SendMessage"],',
            '     "Resource": "arn:aws:sqs:region:account:lambda-dlq"',
            "   }",
            "",
            "4. Alternative: configurer Destinations (modern):",
            "   aws lambda put-function-event-invoke-config \\",
            "     --function-name myfunction \\",
            "     --destination-config '{",
            '       "OnFailure": {',
            '         "Destination": "arn:aws:sqs:region:account:failure-queue"',
            "       },",
            '       "OnSuccess": {',
            '         "Destination": "arn:aws:sqs:region:account:success-queue"',
            "       }",
            "     }' \\",
            "     --maximum-retry-attempts 2",
            "",
            "5. Activer X-Ray tracing:",
            "   aws lambda update-function-configuration \\",
            "     --function-name myfunction \\",
            "     --tracing-config Mode=Active",
            "",
            "6. Ajouter IAM permissions pour X-Ray:",
            "   aws iam attach-role-policy \\",
            "     --role-name lambda-role \\",
            "     --policy-arn arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess",
            "",
            "7. Instrumenter code Python avec X-Ray SDK:",
            "   from aws_xray_sdk.core import xray_recorder",
            "   from aws_xray_sdk.core import patch_all",
            "",
            "   patch_all()  # Auto-instrument AWS SDK, requests, etc.",
            "",
            "   @xray_recorder.capture('my_function')",
            "   def lambda_handler(event, context):",
            "       # Code here automatically traced",
            "       pass",
            "",
            "8. Custom subsegments pour instrumentation détaillée:",
            "   from aws_xray_sdk.core import xray_recorder",
            "",
            "   subsegment = xray_recorder.begin_subsegment('database_query')",
            "   try:",
            "       # Database query code",
            "       subsegment.put_annotation('query_type', 'SELECT')",
            "       subsegment.put_metadata('query', sql_query)",
            "   finally:",
            "       xray_recorder.end_subsegment()",
            "",
            "9. Configurer X-Ray sampling rules:",
            "   aws xray create-sampling-rule --cli-input-json file://sampling-rule.json",
            "",
            "   # sampling-rule.json:",
            "   {",
            '     "SamplingRule": {',
            '       "RuleName": "prod-apis",',
            '       "Priority": 100,',
            '       "FixedRate": 0.05,',
            '       "ReservoirSize": 1,',
            '       "ServiceName": "api-function",',
            '       "ServiceType": "AWS::Lambda::Function",',
            '       "Host": "*",',
            '       "HTTPMethod": "*",',
            '       "URLPath": "*",',
            '       "Version": 1',
            "     }",
            "   }"
        ],
        verification_steps=[
            "Lister functions avec DLQ configurée:",
            "  aws lambda list-functions \\",
            "    --query 'Functions[?DeadLetterConfig!=`null`].[FunctionName,DeadLetterConfig.TargetArn]' \\",
            "    --output table",
            "",
            "Identifier functions async SANS DLQ (risque):",
            "  # Functions invoked by S3, SNS, EventBridge sans DLQ",
            "  aws lambda list-functions \\",
            "    --query 'Functions[?DeadLetterConfig==`null`].[FunctionName]' \\",
            "    --output table",
            "",
            "Vérifier Destinations config:",
            "  aws lambda get-function-event-invoke-config --function-name myfunction",
            "",
            "Vérifier messages dans DLQ:",
            "  DLQ_URL=$(aws sqs get-queue-url --queue-name lambda-dlq --query 'QueueUrl' --output text)",
            "  aws sqs receive-message --queue-url $DLQ_URL --max-number-of-messages 10",
            "",
            "Vérifier X-Ray tracing status:",
            "  aws lambda get-function-configuration --function-name myfunction \\",
            "    --query 'TracingConfig.Mode'",
            "",
            "Lister functions SANS X-Ray:",
            "  aws lambda list-functions \\",
            "    --query 'Functions[?TracingConfig.Mode!=`Active`].[FunctionName,TracingConfig.Mode]' \\",
            "    --output table",
            "",
            "Consulter X-Ray service map:",
            "  # Via console: X-Ray > Service map",
            "  # ou API:",
            "  aws xray get-service-graph \\",
            "    --start-time $(date -u -d '1 hour ago' +%s) \\",
            "    --end-time $(date -u +%s)",
            "",
            "Rechercher traces avec errors:",
            "  aws xray get-trace-summaries \\",
            "    --start-time $(date -u -d '1 hour ago' +%s) \\",
            "    --end-time $(date -u +%s) \\",
            "    --filter-expression 'error = true'",
            "",
            "Obtenir trace détaillée:",
            "  aws xray batch-get-traces --trace-ids <trace-id>",
            "",
            "CloudWatch Insights query pour errors:",
            "  aws logs start-query \\",
            "    --log-group-name /aws/lambda/myfunction \\",
            "    --start-time $(date -d '1 hour ago' +%s) \\",
            "    --end-time $(date +%s) \\",
            "    --query-string 'fields @timestamp, @message | filter @message like /ERROR/'",
            "",
            "Vérifier sampling rules:",
            "  aws xray get-sampling-rules"
        ],
        references=[
            "https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html",
            "https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-concepts.html#gettingstarted-concepts-dlq",
            "https://docs.aws.amazon.com/lambda/latest/dg/lambda-x-ray.html",
            "https://docs.aws.amazon.com/xray/latest/devguide/xray-sdk-python.html"
        ]
    ),

    Question(
        id="LAMBDA-006",
        question="Lambda Function URLs: access control IAM/CORS configuré et HTTPS obligatoire, pas d'exposition publique non sécurisée?",
        description="Vérifier que les Function URLs Lambda sont sécurisées avec IAM auth ou authz appropriée, CORS configuré strictement, et pas d'accès public non intentionnel",
        severity="HIGH",
        category="Lambda",
        compliance=["Zero Trust", "AWS Well-Architected", "Least Privilege"],
        technical_details="""
        Lambda Function URLs = HTTP(S) endpoint natif pour Lambda

        Avantages Function URLs:
        - Pas besoin d'API Gateway pour simple HTTP
        - Coût réduit (pas de API Gateway charges)
        - Latence réduite (direct invoke)
        - Setup simple (1 commande)
        - Intégration streaming response

        Auth types:
        1. AWS_IAM:
           - Signature SigV4 requise
           - Caller doit avoir IAM permission lambda:InvokeFunctionUrl
           - Secure, granular control
           - Pour internal services

        2. NONE:
           - Aucune authentication
           - Public Internet access
           - DANGEREUX si pas intentionnel
           - Pour webhooks, public APIs, CDN origin

        Différence vs API Gateway:
        | Feature              | Function URL | API Gateway |
        |----------------------|--------------|-------------|
        | Auth                 | IAM or None  | IAM, Cognito, Lambda auth, API keys |
        | WAF                  | ❌           | ✅          |
        | Rate limiting        | ❌           | ✅          |
        | Request validation   | ❌           | ✅          |
        | Caching              | ❌           | ✅          |
        | Custom domains       | ❌ (CloudFront) | ✅       |
        | Cost                 | $0           | $3.50/M req |
        | Use case             | Simple, internal | Production APIs |

        CORS configuration:
        - Permet browser requests cross-origin
        - AllowOrigins: specific domains (pas "*" en prod)
        - AllowMethods: GET, POST, etc.
        - AllowHeaders: custom headers autorisés
        - ExposeHeaders: headers exposés au client
        - MaxAge: cache preflight requests
        - AllowCredentials: cookies/auth headers

        Security best practices:
        - Utiliser AWS_IAM auth par défaut
        - NONE auth seulement si vraiment public
        - CORS: restrictif AllowOrigins (pas *)
        - CloudFront devant si NONE auth (WAF, DDoS)
        - API Gateway si besoin WAF/rate limiting
        - Secrets dans environment variables (encrypted)
        - Input validation dans function code

        Monitoring:
        - CloudWatch Logs: tous invocations
        - CloudWatch Metrics: InvocationCount, Errors
        - VPC Flow Logs: si function in VPC
        - CloudTrail: CreateFunctionUrlConfig, UpdateFunctionUrlConfig

        Use cases Function URL:
        ✅ Webhooks (GitHub, Stripe, etc.)
        ✅ Internal microservices communication
        ✅ CDN origin (CloudFront → Lambda)
        ✅ Simple prototypes/testing
        ❌ Production customer-facing API (use API Gateway)
        ❌ Besoin WAF/DDoS protection
        ❌ Complex auth/authz logic
        """,
        remediation=[
            "1. Créer Function URL avec IAM auth (secure):",
            "   aws lambda create-function-url-config \\",
            "     --function-name myfunction \\",
            "     --auth-type AWS_IAM \\",
            "     --cors '{",
            '       "AllowOrigins": ["https://myapp.example.com"],',
            '       "AllowMethods": ["GET", "POST"],',
            '       "AllowHeaders": ["Content-Type", "X-Api-Key"],',
            '       "ExposeHeaders": ["X-Request-Id"],',
            '       "MaxAge": 300,',
            '       "AllowCredentials": true',
            "     }'",
            "",
            "2. Ajouter IAM policy pour autoriser invocation:",
            "   # Permet specific IAM role/user:",
            "   aws lambda add-permission \\",
            "     --function-name myfunction \\",
            "     --statement-id AllowInvokeFromRole \\",
            "     --action lambda:InvokeFunctionUrl \\",
            "     --principal arn:aws:iam::account:role/MyAppRole",
            "",
            "3. Créer Function URL NONE auth (PUBLIC - use with caution):",
            "   aws lambda create-function-url-config \\",
            "     --function-name webhook-handler \\",
            "     --auth-type NONE \\",
            "     --cors '{",
            '       "AllowOrigins": ["*"],',  # Public webhook",
            '       "AllowMethods": ["POST"],',
            '       "MaxAge": 86400',
            "     }'",
            "",
            "   # Ajouter resource-based policy pour public access:",
            "   aws lambda add-permission \\",
            "     --function-name webhook-handler \\",
            "     --statement-id FunctionURLAllowPublicAccess \\",
            "     --action lambda:InvokeFunctionUrl \\",
            "     --principal '*' \\",
            "     --function-url-auth-type NONE",
            "",
            "4. Obtenir Function URL:",
            "   aws lambda get-function-url-config \\",
            "     --function-name myfunction \\",
            "     --query 'FunctionUrl' \\",
            "     --output text",
            "",
            "5. Tester invocation avec IAM auth (Python):",
            "   import boto3",
            "   from botocore.auth import SigV4Auth",
            "   from botocore.awsrequest import AWSRequest",
            "   import requests",
            "",
            "   session = boto3.Session()",
            "   credentials = session.get_credentials()",
            "",
            "   url = 'https://abc123.lambda-url.us-east-1.on.aws/'",
            "   request = AWSRequest(method='GET', url=url)",
            "   SigV4Auth(credentials, 'lambda', 'us-east-1').add_auth(request)",
            "",
            "   response = requests.get(url, headers=dict(request.headers))",
            "",
            "6. Mettre CloudFront devant Function URL (WAF, caching):",
            "   aws cloudfront create-distribution \\",
            "     --origin-domain-name abc123.lambda-url.us-east-1.on.aws \\",
            "     --default-root-object '' \\",
            "     --web-acl-id <waf-acl-id>",
            "",
            "7. Audit Function URLs avec NONE auth:",
            "   for func in $(aws lambda list-functions --query 'Functions[].FunctionName' --output text); do",
            "     auth=$(aws lambda get-function-url-config --function-name $func 2>/dev/null | jq -r '.AuthType')",
            "     [ \"$auth\" = \"NONE\" ] && echo \"PUBLIC: $func\"",
            "   done",
            "",
            "8. Désactiver Function URL:",
            "   aws lambda delete-function-url-config --function-name myfunction",
            "",
            "9. Update CORS config:",
            "   aws lambda update-function-url-config \\",
            "     --function-name myfunction \\",
            "     --cors '{",
            '       "AllowOrigins": ["https://app.example.com", "https://admin.example.com"],',
            '       "AllowMethods": ["GET", "POST", "PUT"],',
            '       "AllowHeaders": ["Content-Type", "Authorization"],',
            '       "MaxAge": 600',
            "     }'",
            "",
            "10. Function code input validation (defense in depth):",
            "    def lambda_handler(event, context):",
            "        # Validate request",
            "        if event.get('requestContext', {}).get('http', {}).get('method') not in ['GET', 'POST']:",
            "            return {'statusCode': 405, 'body': 'Method Not Allowed'}",
            "        ",
            "        # Validate headers",
            "        headers = event.get('headers', {})",
            "        if 'x-api-key' not in headers:",
            "            return {'statusCode': 401, 'body': 'Unauthorized'}",
            "        ",
            "        # Your logic here"
        ],
        verification_steps=[
            "Lister toutes Function URLs:",
            "  for func in $(aws lambda list-functions --query 'Functions[].FunctionName' --output text); do",
            "    aws lambda get-function-url-config --function-name $func 2>/dev/null",
            "  done",
            "",
            "Identifier Function URLs avec NONE auth (public):",
            "  for func in $(aws lambda list-functions --query 'Functions[].FunctionName' --output text); do",
            "    config=$(aws lambda get-function-url-config --function-name $func 2>/dev/null)",
            "    auth=$(echo $config | jq -r '.AuthType')",
            "    [ \"$auth\" = \"NONE\" ] && echo \"$func: PUBLIC ACCESS\"",
            "  done",
            "",
            "Vérifier CORS config:",
            "  aws lambda get-function-url-config --function-name myfunction | jq '.Cors'",
            "",
            "Test IAM auth Function URL (avec credentials):",
            "  # Doit retourner 200 avec valid SigV4:",
            "  aws lambda invoke-url \\",
            "    --function-url https://abc123.lambda-url.us-east-1.on.aws/ \\",
            "    output.json",
            "",
            "Test NONE auth Function URL (sans credentials):",
            "  curl https://abc123.lambda-url.us-east-1.on.aws/",
            "  # Devrait fonctionner si AuthType=NONE",
            "",
            "Vérifier permissions resource-based:",
            "  aws lambda get-policy --function-name myfunction | jq '.Policy | fromjson'",
            "",
            "CloudWatch Logs - voir invocations:",
            "  aws logs tail /aws/lambda/myfunction --follow",
            "",
            "CloudWatch Metrics - invocation count:",
            "  aws cloudwatch get-metric-statistics \\",
            "    --namespace AWS/Lambda \\",
            "    --metric-name Invocations \\",
            "    --dimensions Name=FunctionName,Value=myfunction \\",
            "    --start-time $(date -u -d '1 hour ago' +%s) \\",
            "    --end-time $(date -u +%s) \\",
            "    --period 300 \\",
            "    --statistics Sum",
            "",
            "CloudTrail audit - creation/modification Function URL:",
            "  aws cloudtrail lookup-events \\",
            "    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateFunctionUrlConfig \\",
            "    --max-results 50",
            "",
            "Test CORS preflight:",
            "  curl -X OPTIONS https://abc123.lambda-url.us-east-1.on.aws/ \\",
            "    -H 'Origin: https://myapp.example.com' \\",
            "    -H 'Access-Control-Request-Method: POST' \\",
            "    -v",
            "  # Check Access-Control-Allow-Origin header in response"
        ],
        references=[
            "https://docs.aws.amazon.com/lambda/latest/dg/lambda-urls.html",
            "https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html",
            "https://docs.aws.amazon.com/lambda/latest/dg/urls-configuration.html"
        ]
    ),

    Question(
        id="LAMBDA-007",
        question="Lambda Layers: dépendances sécurisées, versioning strict, et pas de secrets dans layers?",
        description="Vérifier que Lambda Layers contiennent uniquement dépendances sécurisées et à jour, avec versioning approprié, et que secrets ne sont jamais stockés dans layers",
        severity="MEDIUM",
        category="Lambda",
        compliance=["AWS Well-Architected", "Supply Chain Security"],
        technical_details="""
        Lambda Layers = packages réutilisables entre functions

        Use cases Layers:
        - Dépendances communes (libraries, SDKs)
        - Runtime custom (ex: Python 3.11 avec patches)
        - Configuration partagée (pas secrets!)
        - Tools communs (monitoring agents)
        - Frameworks (ex: boto3 upgraded version)

        Structure Layer:
        - /opt/python/ → Python libraries
        - /opt/nodejs/ → Node.js modules
        - /opt/bin/ → Executables
        - /opt/lib/ → Shared libraries
        - Max 5 layers par function
        - Max 250 MB unzipped (all layers + function)

        Security concerns:
        1. Vulnerable dependencies:
           - Outdated libraries avec CVEs
           - Malicious packages (supply chain attack)
           - Unverified sources

        2. Secrets exposure:
           - API keys, passwords dans layer
           - Layer = immutable, shareable
           - Rotation impossible si secrets dans layer
           - Use Secrets Manager/Parameter Store instead

        3. Excessive permissions:
           - Layer partagé entre many functions
           - Over-privileged functions héritent risk
           - Principle of least privilege

        4. Version management:
           - Old layer versions orphaned
           - Incompatibilité version conflicts
           - Breaking changes sans notice

        Versioning strategy:
        - Semantic versioning: layer-name-v1, v2, v3
        - Immutable: jamais modifier layer existante
        - Publish new version pour updates
        - Delete old versions (après migration functions)
        - $LATEST = current, mais prefer explicit versions

        Layer sharing:
        - Private: account-only (défaut)
        - Cross-account: via layer permissions
        - Public: everyone (AWS Serverless Application Repo)
        - AWS-provided layers: disponibles publiquement

        Dependency scanning:
        - Scan vulnerabilities avec Snyk, Dependabot
        - Check SBOM (Software Bill of Materials)
        - Automated updates via CI/CD
        - Pin versions exactes (pas "latest")

        Best practices:
        - Un layer = un purpose (pas monolith)
        - Requirements.txt versionné avec layer
        - Documentation: what's in each version
        - Automated testing layer avec function
        - Cleanup unused layers (cost + clutter)
        - Never secrets (use Secrets Manager)
        """,
        remediation=[
            "1. Créer Lambda Layer (Python exemple):",
            "   # Structure locale:",
            "   mkdir -p layer/python",
            "   pip install requests -t layer/python/",
            "",
            "   # Créer ZIP:",
            "   cd layer && zip -r ../layer.zip . && cd ..",
            "",
            "   # Publish layer:",
            "   aws lambda publish-layer-version \\",
            "     --layer-name common-dependencies \\",
            "     --description 'requests v2.28.1' \\",
            "     --zip-file fileb://layer.zip \\",
            "     --compatible-runtimes python3.9 python3.10",
            "",
            "2. Attacher layer à function:",
            "   aws lambda update-function-configuration \\",
            "     --function-name myfunction \\",
            "     --layers arn:aws:lambda:region:account:layer:common-dependencies:1",
            "",
            "3. Lister layers et versions:",
            "   aws lambda list-layers",
            "   aws lambda list-layer-versions --layer-name common-dependencies",
            "",
            "4. Partager layer cross-account:",
            "   aws lambda add-layer-version-permission \\",
            "     --layer-name common-dependencies \\",
            "     --version-number 1 \\",
            "     --statement-id xaccount \\",
            "     --action lambda:GetLayerVersion \\",
            "     --principal 123456789012  # Target account",
            "",
            "5. Scanner vulnerabilities dependencies (Python):",
            "   pip install safety",
            "   safety check --file requirements.txt",
            "",
            "   # Ou avec Snyk:",
            "   snyk test --file=requirements.txt",
            "",
            "6. Automated layer updates (CI/CD pipeline):",
            "   # .github/workflows/update-layer.yml",
            "   - name: Build layer",
            "     run: |",
            "       pip install -r requirements.txt -t layer/python/",
            "       cd layer && zip -r ../layer.zip .",
            "   - name: Publish layer",
            "     run: |",
            "       aws lambda publish-layer-version \\",
            "         --layer-name common-deps \\",
            "         --zip-file fileb://layer.zip",
            "",
            "7. Cleanup old layer versions:",
            "   # Lister versions:",
            "   aws lambda list-layer-versions --layer-name common-dependencies",
            "",
            "   # Supprimer old version:",
            "   aws lambda delete-layer-version \\",
            "     --layer-name common-dependencies \\",
            "     --version-number 1",
            "",
            "8. Utiliser AWS-managed layers:",
            "   # AWS Parameters and Secrets Lambda Extension:",
            "   arn:aws:lambda:region:account:layer:AWS-Parameters-and-Secrets-Lambda-Extension:4",
            "",
            "   # AWS Lambda Powertools:",
            "   arn:aws:lambda:region:017000801446:layer:AWSLambdaPowertoolsPythonV2:21",
            "",
            "9. Document layer contents:",
            "   # requirements.txt alongside layer",
            "   requests==2.28.1",
            "   boto3==1.26.90",
            "   pydantic==1.10.7",
            "",
            "   # README.md:",
            "   # common-dependencies layer v1",
            "   # - requests 2.28.1: HTTP library",
            "   # - boto3 1.26.90: AWS SDK (upgraded from runtime default)",
            "   # - pydantic 1.10.7: Data validation",
            "",
            "10. Verify NO secrets in layer:",
            "    # Before publishing, scan for secrets:",
            "    cd layer",
            "    git secrets --scan -r .",
            "    trufflehog filesystem . --only-verified",
            "",
            "    # Never include:",
            "    # - .env files",
            "    # - config.json avec passwords",
            "    # - AWS credentials",
            "    # - API keys"
        ],
        verification_steps=[
            "Lister tous les layers:",
            "  aws lambda list-layers --query 'Layers[].[LayerName,LatestMatchingVersion.Version]'",
            "",
            "Lister functions utilisant un layer specific:",
            "  for func in $(aws lambda list-functions --query 'Functions[].FunctionName' --output text); do",
            "    layers=$(aws lambda get-function-configuration --function-name $func --query 'Layers[].Arn' --output text)",
            "    echo \"$func: $layers\"",
            "  done | grep common-dependencies",
            "",
            "Vérifier layer contents (download et inspect):",
            "  # Get layer version ARN:",
            "  LAYER_ARN=$(aws lambda get-layer-version --layer-name common-dependencies --version-number 1 --query 'Content.Location' --output text)",
            "",
            "  # Download:",
            "  wget -O layer.zip $LAYER_ARN",
            "",
            "  # Extract et inspect:",
            "  unzip layer.zip -d layer/",
            "  ls -R layer/",
            "",
            "Scan vulnerabilities dans layer:",
            "  # Extraire requirements:",
            "  pip list --path layer/python/ > installed-packages.txt",
            "  safety check --stdin < installed-packages.txt",
            "",
            "Vérifier layer permissions (qui peut utiliser):",
            "  aws lambda get-layer-version-policy \\",
            "    --layer-name common-dependencies \\",
            "    --version-number 1",
            "",
            "Identifier orphaned layer versions (pas utilisées):",
            "  # Lister all layers:",
            "  aws lambda list-layers --query 'Layers[].LayerName' --output text | while read layer; do",
            "    echo \"=== Layer: $layer ===\"",
            "    aws lambda list-layer-versions --layer-name $layer --query 'LayerVersions[].[Version,Description]'",
            "  done",
            "",
            "  # Manual review: check which versions are in use",
            "",
            "Vérifier size total layers + function:",
            "  aws lambda get-function-configuration --function-name myfunction \\",
            "    --query '[CodeSize, Layers[].CodeSize]'",
            "  # Total doit être < 250 MB unzipped",
            "",
            "CloudTrail audit - layer creation/updates:",
            "  aws cloudtrail lookup-events \\",
            "    --lookup-attributes AttributeKey=EventName,AttributeValue=PublishLayerVersion \\",
            "    --max-results 50",
            "",
            "Test function avec layer:",
            "  aws lambda invoke \\",
            "    --function-name myfunction \\",
            "    --payload '{}' \\",
            "    output.json",
            "  cat output.json",
            "",
            "Vérifier runtime compatibility:",
            "  aws lambda get-layer-version --layer-name common-dependencies --version-number 1 \\",
            "    --query 'CompatibleRuntimes'"
        ],
        references=[
            "https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html",
            "https://docs.aws.amazon.com/lambda/latest/dg/creating-deleting-layers.html",
            "https://aws.amazon.com/blogs/compute/working-with-lambda-layers-and-extensions-in-container-images/"
        ]
    )
]

# ==================== API GATEWAY ====================
APIGATEWAY_QUESTIONS = [
    Question(
        id="APIGW-001",
        question="Authorizers (Cognito/Lambda/IAM) configurés pour toutes APIs, pas de methods publiques sans authentification?",
        description="Vérifier que toutes APIs REST/HTTP ont authorizers configurés pour contrôle d'accès strict",
        severity="CRITICAL",
        category="API Gateway",
        compliance=["OWASP API Security", "PCI-DSS", "SOC2"],
        technical_details="Cognito User Pools pour JWT validation automatique. Lambda authorizers pour logique custom (OAuth, API keys). IAM pour service-to-service avec SigV4",
        remediation=[
            "aws apigateway create-authorizer --rest-api-id ID --name CognitoAuth --type COGNITO_USER_POOLS --provider-arns arn:aws:cognito-idp:region:account:userpool/ID",
            "aws apigateway update-method --rest-api-id ID --resource-id ID --http-method GET --patch-operations op=replace,path=/authorizationType,value=COGNITO_USER_POOLS",
            "Vérifier aucune method avec authorizationType=NONE en production"
        ],
        verification_steps=[
            "aws apigateway get-authorizers --rest-api-id ID",
            "aws apigateway get-method --rest-api-id ID --resource-id ID --http-method GET | grep authorizationType",
            "Identifier toutes methods avec NONE: aws apigateway get-resources --rest-api-id ID"
        ],
        references=[
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-to-api.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html"
        ]
    ),

    Question(
        id="APIGW-002",
        question="AWS WAF Web ACL attaché avec managed rules (Core Rule Set, SQL injection, XSS) et rate-based rules?",
        description="Vérifier protection WAF contre OWASP Top 10 et DDoS avec rate limiting par IP",
        severity="CRITICAL",
        category="API Gateway",
        compliance=["OWASP API Security", "PCI-DSS", "CIS Benchmark"],
        technical_details="WAF managed rules: AWSManagedRulesCommonRuleSet (OWASP), Known Bad Inputs, SQL Database. Rate-based rule: 2000 req/5min par IP",
        remediation=[
            "aws wafv2 create-web-acl --name api-waf --scope REGIONAL --default-action Allow={} --rules file://rules.json",
            "aws wafv2 associate-web-acl --web-acl-arn ARN --resource-arn arn:aws:apigateway:region::/restapis/ID/stages/prod",
            "Ajouter managed rule groups: Core Rule Set, SQL Database, Known Bad Inputs"
        ],
        verification_steps=[
            "aws wafv2 list-web-acls --scope REGIONAL",
            "aws wafv2 get-web-acl-for-resource --resource-arn arn:aws:apigateway:region::/restapis/ID/stages/prod",
            "CloudWatch metrics: aws cloudwatch get-metric-statistics --namespace AWS/WAFV2 --metric-name BlockedRequests"
        ],
        references=[
            "https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-aws-waf.html"
        ]
    ),

    Question(
        id="APIGW-003",
        question="Throttling configuré (usage plans avec rate limits) et response caching activé pour performance?",
        description="Vérifier usage plans avec throttling par client et caching pour réduire backend load",
        severity="HIGH",
        category="API Gateway",
        compliance=["AWS Well-Architected", "FinOps"],
        technical_details="Usage plans: rate limit (req/s), burst capacity, quotas mensuels. Cache: 0.5-237GB, TTL 0-3600s, réduit latency et coûts backend",
        remediation=[
            "aws apigateway create-usage-plan --name premium --throttle rateLimit=1000,burstLimit=2000 --quota limit=1000000,period=MONTH",
            "aws apigateway update-stage --rest-api-id ID --stage-name prod --patch-operations op=replace,path=/cacheClusterEnabled,value=true",
            "aws apigateway create-api-key --name customer-key --enabled | aws apigateway create-usage-plan-key"
        ],
        verification_steps=[
            "aws apigateway get-usage-plans",
            "aws apigateway get-stage --rest-api-id ID --stage-name prod | grep cacheCluster",
            "CloudWatch: CacheHitCount vs CacheMissCount pour calculer hit ratio"
        ],
        references=[
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html"
        ]
    ),

    Question(
        id="APIGW-004",
        question="Request validation activée avec JSON schemas et CloudWatch Logs (access + execution) configurés?",
        description="Vérifier validation request body/parameters avant invoke backend et logging détaillé pour audit",
        severity="MEDIUM",
        category="API Gateway",
        compliance=["AWS Well-Architected", "OWASP API Security"],
        technical_details="Request validators avec JSON Schema Draft 4 pour body validation. CloudWatch Logs: execution logs (debugging) + access logs (analytics structurés)",
        remediation=[
            "aws apigateway create-request-validator --rest-api-id ID --name validator --validate-request-body --validate-request-parameters",
            "aws apigateway create-model --rest-api-id ID --name UserModel --content-type application/json --schema file://schema.json",
            "aws apigateway update-stage --rest-api-id ID --stage-name prod --patch-operations op=replace,path=/logging/loglevel,value=INFO"
        ],
        verification_steps=[
            "aws apigateway get-request-validators --rest-api-id ID",
            "aws apigateway get-models --rest-api-id ID",
            "aws logs tail /aws/apigateway/ID --follow",
            "Test avec payload invalide: curl -X POST https://api/resource -d '{\"invalid\":\"data\"}' (doit retourner 400)"
        ],
        references=[
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-request-validation.html",
            "https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html"
        ]
    )
]

# ==================== CLOUDTRAIL & LOGGING ====================
CLOUDTRAIL_QUESTIONS = [
    Question(
        id="TRAIL-001",
        question="CloudTrail multi-région activé avec log file validation, logs chiffrés KMS, et organization trail?",
        description="Vérifier trail multi-région pour capture complète, validation integrity, encryption KMS, et trail organization-wide",
        severity="CRITICAL",
        category="CloudTrail",
        compliance=["PCI-DSS", "HIPAA", "SOC2", "CIS Benchmark", "ISO 27001"],
        technical_details="Multi-region trail capture toutes régions automatiquement. Log validation détecte modifications/suppressions avec digest files. KMS encryption at rest. Organization trail centralise logging tous comptes AWS Organizations",
        remediation=[
            "aws cloudtrail create-trail --name org-trail --s3-bucket-name cloudtrail-bucket --is-multi-region-trail --enable-log-file-validation --kms-key-id arn:aws:kms:region:account:key/ID --is-organization-trail",
            "aws cloudtrail start-logging --name org-trail",
            "Vérifier S3 bucket policy autorise CloudTrail: Action s3:PutObject avec Condition StringEquals aws:SourceArn"
        ],
        verification_steps=[
            "aws cloudtrail describe-trails --query 'trailList[].[Name,IsMultiRegionTrail,LogFileValidationEnabled,KmsKeyId,IsOrganizationTrail]' --output table",
            "aws cloudtrail get-trail-status --name org-trail",
            "aws cloudtrail validate-logs --trail-arn ARN --start-time 2024-01-01T00:00:00Z",
            "Identifier trails sans validation: aws cloudtrail describe-trails --query 'trailList[?LogFileValidationEnabled==`false`].Name'"
        ],
        references=[
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html",
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html",
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-trail-organization.html"
        ]
    ),

    Question(
        id="TRAIL-002",
        question="CloudWatch Logs integration activée pour alerting temps réel et metric filters configurés?",
        description="Vérifier streaming CloudTrail vers CloudWatch Logs avec metric filters pour security events",
        severity="HIGH",
        category="CloudTrail",
        compliance=["CIS Benchmark", "Security Monitoring", "SOC2"],
        technical_details="CloudWatch Logs permet query temps réel et metric filters transforment log patterns en métriques. CIS Benchmark section 3: monitoring unauthorized API calls, console login without MFA, IAM policy changes, etc.",
        remediation=[
            "aws cloudtrail update-trail --name trail --cloud-watch-logs-log-group-arn arn:aws:logs:region:account:log-group:/aws/cloudtrail/logs --cloud-watch-logs-role-arn arn:aws:iam::account:role/CloudTrail_CloudWatchLogs_Role",
            "aws logs put-metric-filter --log-group-name /aws/cloudtrail/logs --filter-name UnauthorizedAPICalls --filter-pattern '{($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\")}' --metric-transformations metricName=UnauthorizedAPICalls,metricNamespace=CloudTrailMetrics,metricValue=1",
            "aws cloudwatch put-metric-alarm --alarm-name UnauthorizedAPICallsAlarm --metric-name UnauthorizedAPICalls --namespace CloudTrailMetrics --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold"
        ],
        verification_steps=[
            "aws cloudtrail describe-trails --query 'trailList[].[Name,CloudWatchLogsLogGroupArn,CloudWatchLogsRoleArn]'",
            "aws logs describe-metric-filters --log-group-name /aws/cloudtrail/logs",
            "aws cloudwatch describe-alarms --alarm-name-prefix CloudTrail",
            "Test: aws logs tail /aws/cloudtrail/logs --follow | grep errorCode"
        ],
        references=[
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html",
            "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html"
        ]
    ),

    Question(
        id="TRAIL-003",
        question="S3 bucket CloudTrail sécurisé: MFA Delete, versioning, lifecycle, bucket policy restrictive, access logging?",
        description="Vérifier sécurité bucket S3 stockant logs CloudTrail avec protections contre suppression/modification",
        severity="HIGH",
        category="CloudTrail",
        compliance=["Audit Integrity", "Forensics", "Compliance Retention"],
        technical_details="Bucket CloudTrail doit avoir: versioning (historique), MFA Delete (protection suppression), lifecycle (Glacier après 90j), bucket policy deny modifications sauf CloudTrail, S3 access logging (audit accès bucket)",
        remediation=[
            "aws s3api put-bucket-versioning --bucket cloudtrail-bucket --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa 'arn:aws:iam::account:mfa/user 123456'",
            "aws s3api put-bucket-lifecycle-configuration --bucket cloudtrail-bucket --lifecycle-configuration file://lifecycle.json",
            "aws s3api put-bucket-logging --bucket cloudtrail-bucket --bucket-logging-status file://logging.json",
            "Bucket policy: Deny s3:DeleteObject, s3:PutObject sauf Principal Service cloudtrail.amazonaws.com"
        ],
        verification_steps=[
            "aws s3api get-bucket-versioning --bucket cloudtrail-bucket",
            "aws s3api get-bucket-lifecycle-configuration --bucket cloudtrail-bucket",
            "aws s3api get-bucket-logging --bucket cloudtrail-bucket",
            "aws s3api get-bucket-policy --bucket cloudtrail-bucket | jq '.Policy | fromjson'",
            "Test MFA Delete: aws s3api delete-object --bucket cloudtrail-bucket --key test (doit échouer sans MFA)"
        ],
        references=[
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html#MultiFactorAuthenticationDelete"
        ]
    ),

    Question(
        id="TRAIL-004",
        question="Data events activés (S3, Lambda) et CloudTrail Insights pour anomaly detection?",
        description="Vérifier logging data events S3/Lambda et Insights ML pour détection activité inhabituelle",
        severity="MEDIUM",
        category="CloudTrail",
        compliance=["Security Analytics", "Threat Detection"],
        technical_details="Data events: capture S3 GetObject/PutObject/DeleteObject et Lambda Invoke (coût supplémentaire). Insights: ML détecte anomalies comme burst API calls, error rate spikes. Management events: gratuits, toujours loggés",
        remediation=[
            "aws cloudtrail put-event-selectors --trail-name trail --event-selectors '[{\"ReadWriteType\":\"All\",\"IncludeManagementEvents\":true,\"DataResources\":[{\"Type\":\"AWS::S3::Object\",\"Values\":[\"arn:aws:s3:::sensitive-bucket/*\"]},{\"Type\":\"AWS::Lambda::Function\",\"Values\":[\"arn:aws:lambda:*:*:function/*\"]}]}]'",
            "aws cloudtrail put-insight-selectors --trail-name trail --insight-selectors '[{\"InsightType\":\"ApiCallRateInsight\"}]'",
            "Attention coûts: data events = $0.10 per 100k events"
        ],
        verification_steps=[
            "aws cloudtrail get-event-selectors --trail-name trail",
            "aws cloudtrail get-insight-selectors --trail-name trail",
            "aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceType,AttributeValue=AWS::S3::Object --max-results 10",
            "CloudTrail Insights events: aws cloudtrail lookup-insights-events --event-source awsinsights.amazonaws.com"
        ],
        references=[
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html",
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-insights-events-with-cloudtrail.html"
        ]
    ),

    Question(
        id="TRAIL-005",
        question="CloudTrail Lake configuré pour querying SQL et analytics long-term des audit logs?",
        description="Vérifier que CloudTrail Lake est utilisé pour retention long-term et requêtes SQL avancées sur events CloudTrail pour investigations sécurité",
        severity="MEDIUM",
        category="CloudTrail",
        compliance=["Security Analytics", "Forensics", "Compliance Reporting"],
        technical_details="""
        CloudTrail Lake = managed data lake pour CloudTrail events

        Avantages vs S3 logs traditionnels:
        - Query SQL sans setup Athena tables
        - Retention jusqu'à 7 ans (S3 = illimité mais coûteux)
        - Aggregation multi-account, multi-region
        - Performance optimisée pour analytics
        - Immutable storage avec AWS-managed encryption

        Fonctionnalités:
        - SQL queries sur billions events en secondes
        - Aggregate events from Organizations
        - Federated query (non-AWS sources)
        - Event data stores: containers logiques
        - Pricing: ingestion $2.50 per GB, queries $0.005 per GB scanned

        Use cases:
        - Security investigations (qui a fait quoi?)
        - Compliance audits (PCI-DSS, HIPAA)
        - Forensic analysis post-incident
        - Cost attribution par tag
        - Compliance reporting automatisé

        Retention tiers:
        - 7 days: gratuit (via CloudTrail standard)
        - 90 days: typical compliance
        - 1 year: extended retention
        - 7 years: regulatory requirements (financial)

        Exemple queries:
        - Tous IAM policy changes derniers 30j
        - Failed login attempts par user
        - S3 DeleteObject events
        - EC2 RunInstances sans encryption
        - Root account usage

        Différence vs Athena:
        - Lake: fully managed, no table creation
        - Athena: DIY, mais flexible pour custom data
        - Lake: optimized for audit logs
        - Athena: general-purpose analytics

        Intégration:
        - CloudTrail → Lake (auto-ingestion)
        - Organizations: aggregate tous accounts
        - QuickSight: dashboards
        - EventBridge: alertes sur query results
        """,
        remediation=[
            "1. Créer CloudTrail Lake event data store:",
            "   aws cloudtrail create-event-data-store \\",
            "     --name security-audit-lake \\",
            "     --retention-period 365 \\",  # 365 days = 1 year",
            "     --multi-region-enabled \\",
            "     --organization-enabled \\",  # Aggregate all accounts",
            "     --advanced-event-selectors file://selectors.json",
            "",
            "   selectors.json (all management + data events):",
            "   [{",
            '     "Name": "All management events",',
            '     "FieldSelectors": [{',
            '       "Field": "eventCategory",',
            '       "Equals": ["Management"]',
            "     }]",
            "   },",
            "   {",
            '     "Name": "S3 data events",',
            '     "FieldSelectors": [{',
            '       "Field": "resources.type",',
            '       "Equals": ["AWS::S3::Object"]',
            "     }]",
            "   }]",
            "",
            "2. Enable ingestion depuis CloudTrail trail:",
            "   # CloudTrail Lake auto-ingests depuis trails actifs",
            "   # Vérifier trail existe et log vers S3:",
            "   aws cloudtrail describe-trails",
            "",
            "3. Run SQL query pour security investigation:",
            "   aws cloudtrail start-query \\",
            "     --query-statement \"",
            "       SELECT userIdentity.principalId, eventName, eventTime, sourceIPAddress",
            "       FROM <event-data-store-id>",
            "       WHERE eventName = 'DeleteBucket'",
            "         AND eventTime > '2024-01-01 00:00:00'",
            "       ORDER BY eventTime DESC",
            "     \"",
            "",
            "4. Query IAM policy changes:",
            "   aws cloudtrail start-query \\",
            "     --query-statement \"",
            "       SELECT eventTime, userIdentity.principalId, eventName, requestParameters",
            "       FROM <event-data-store-id>",
            "       WHERE eventName IN ('PutUserPolicy', 'AttachUserPolicy', 'PutRolePolicy', 'AttachRolePolicy')",
            "         AND eventTime > CURRENT_TIMESTAMP - INTERVAL '30' DAY",
            "       ORDER BY eventTime DESC",
            "     \"",
            "",
            "5. Query failed authentication attempts:",
            "   aws cloudtrail start-query \\",
            "     --query-statement \"",
            "       SELECT eventTime, userIdentity.principalId, sourceIPAddress, errorCode, errorMessage",
            "       FROM <event-data-store-id>",
            "       WHERE errorCode IN ('AccessDenied', 'UnauthorizedOperation', 'InvalidClientTokenId')",
            "         AND eventTime > CURRENT_TIMESTAMP - INTERVAL '7' DAY",
            "       GROUP BY sourceIPAddress",
            "       HAVING COUNT(*) > 10",
            "       ORDER BY COUNT(*) DESC",
            "     \"",
            "",
            "6. Obtenir résultats query:",
            "   # Get query ID from start-query response",
            "   aws cloudtrail get-query-results --query-id <query-id>",
            "",
            "7. Créer saved query pour réutilisation:",
            "   # Via console CloudTrail Lake → Saved queries",
            "   # Ou garder SQL dans repository Git",
            "",
            "8. Configurer retention appropriée:",
            "   aws cloudtrail update-event-data-store \\",
            "     --event-data-store <id> \\",
            "     --retention-period 2555  # 7 years",
            "",
            "9. Monitor coûts ingestion/queries:",
            "   # CloudWatch metrics:",
            "   # - IngestedBytes",
            "   # - QueriedBytes",
            "   # Cost Explorer tag CloudTrail Lake resources",
            "",
            "10. Federated query (optionnel - non-AWS sources):",
            "    # Intégrer logs non-AWS (on-prem, third-party):",
            "    aws cloudtrail put-resource-policy --resource-arn <data-store-arn> --resource-policy file://policy.json"
        ],
        verification_steps=[
            "Lister event data stores:",
            "  aws cloudtrail list-event-data-stores",
            "",
            "Vérifier configuration data store:",
            "  aws cloudtrail get-event-data-store --event-data-store <id> \\",
            "    --query '{Name:Name,Retention:RetentionPeriod,MultiRegion:MultiRegionEnabled,OrgEnabled:OrganizationEnabled}'",
            "",
            "Lister queries récentes:",
            "  aws cloudtrail list-queries --event-data-store <id>",
            "",
            "Test query - count events par service:",
            "  aws cloudtrail start-query --query-statement \"",
            "    SELECT eventSource, COUNT(*) as event_count",
            "    FROM <event-data-store-id>",
            "    WHERE eventTime > CURRENT_TIMESTAMP - INTERVAL '1' DAY",
            "    GROUP BY eventSource",
            "    ORDER BY event_count DESC",
            "    LIMIT 10",
            "  \"",
            "",
            "Vérifier ingestion active:",
            "  # CloudWatch metric: IngestedBytes",
            "  aws cloudwatch get-metric-statistics \\",
            "    --namespace AWS/CloudTrail \\",
            "    --metric-name IngestedBytes \\",
            "    --dimensions Name=EventDataStore,Value=<id> \\",
            "    --start-time $(date -u -d '1 day ago' +%s) \\",
            "    --end-time $(date -u +%s) \\",
            "    --period 3600 \\",
            "    --statistics Sum",
            "",
            "Test forensic query - root usage:",
            "  aws cloudtrail start-query --query-statement \"",
            "    SELECT eventTime, eventName, sourceIPAddress",
            "    FROM <event-data-store-id>",
            "    WHERE userIdentity.type = 'Root'",
            "      AND eventTime > CURRENT_TIMESTAMP - INTERVAL '90' DAY",
            "    ORDER BY eventTime DESC",
            "  \"",
            "",
            "Vérifier coûts queries:",
            "  aws ce get-cost-and-usage \\",
            "    --time-period Start=2024-01-01,End=2024-01-31 \\",
            "    --granularity MONTHLY \\",
            "    --metrics UnblendedCost \\",
            "    --filter file://cloudtrail-lake-filter.json"
        ],
        references=[
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake.html",
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/query-event-data-store-cloudtrail.html",
            "https://aws.amazon.com/blogs/mt/announcing-aws-cloudtrail-lake-a-managed-audit-and-security-lake/"
        ]
    ),

    Question(
        id="TRAIL-006",
        question="Multi-region trail activé et log file integrity validation configurée pour protection tampering?",
        description="Vérifier que trail capture events de toutes régions et que validation d'intégrité empêche modification malveillante des logs",
        severity="HIGH",
        category="CloudTrail",
        compliance=["Audit Trail", "Forensics", "Non-Repudiation", "PCI-DSS"],
        technical_details="""
        Multi-region CloudTrail = single trail pour toutes régions

        Avantages multi-region:
        - Un trail → logs de toutes régions AWS
        - Pas de gap si ressources créées dans nouvelle région
        - Centralized logging dans un S3 bucket
        - Simplifie gestion et coûts
        - Compliance: preuve de logging global

        Single region trail (legacy):
        - Capture seulement events de SA région
        - Gap si attacker utilise autre région
        - Nécessite multiple trails (complexité)
        - Risque: région non monitorée

        Log File Integrity Validation:
        - Signature cryptographique (SHA-256 + RSA)
        - Digest files toutes les heures
        - Prouve logs non altérés
        - Forensic requirement: chain of custody
        - Détecte tampering: modification, suppression, déplacement

        Comment ça marche:
        1. CloudTrail crée log file
        2. Compute SHA-256 hash
        3. Sign avec RSA private key
        4. Publish digest file (hash + signature)
        5. Validation: verify signature + hash match

        Digest file structure:
        - logFiles: array of log file hashes
        - digestS3Bucket, digestS3Object: location
        - previousDigestHashValue: chaînage
        - digestPublicKeyFingerprint: clé publique

        Use cases validation:
        - Legal: preuve logs authentiques
        - Forensics: chain of custody
        - Compliance: non-repudiation (PCI-DSS, HIPAA)
        - Incident response: identifier tampering attempts

        Threat model:
        - Attacker avec S3 access tente delete/modify logs
        - Sans validation: pas détectable
        - Avec validation: hash mismatch → alert

        Protection layers:
        1. S3 bucket policy: deny delete (même root)
        2. S3 Object Lock: WORM (compliance mode)
        3. Log file validation: cryptographic proof
        4. CloudTrail itself logged: recursive audit
        5. Cross-account logging: attacker no access

        Global events:
        - IAM, STS, CloudFront: générés dans us-east-1
        - Multi-region trail capture automatiquement
        - Single-region trail: peut manquer ces events
        """,
        remediation=[
            "1. Créer multi-region trail avec validation:",
            "   aws cloudtrail create-trail \\",
            "     --name organization-trail \\",
            "     --s3-bucket-name cloudtrail-logs-org \\",
            "     --is-multi-region-trail \\",
            "     --enable-log-file-validation \\",
            "     --is-organization-trail  # Si AWS Organizations",
            "",
            "2. Start logging trail:",
            "   aws cloudtrail start-logging --name organization-trail",
            "",
            "3. Vérifier trail capture global events (IAM, etc):",
            "   aws cloudtrail get-trail --name organization-trail \\",
            "     --query 'Trail.IncludeGlobalServiceEvents'",
            "   # Doit être true",
            "",
            "4. Upgrade existing single-region trail to multi-region:",
            "   aws cloudtrail update-trail \\",
            "     --name existing-trail \\",
            "     --is-multi-region-trail",
            "",
            "5. Enable log file validation (if not already):",
            "   aws cloudtrail update-trail \\",
            "     --name organization-trail \\",
            "     --enable-log-file-validation",
            "",
            "6. Validate log file integrity:",
            "   aws cloudtrail validate-logs \\",
            "     --trail-arn arn:aws:cloudtrail:region:account:trail/organization-trail \\",
            "     --start-time 2024-01-15T00:00:00Z \\",
            "     --end-time 2024-01-16T00:00:00Z",
            "",
            "   # Output:",
            "   # - VALID: log file unchanged",
            "   # - INVALID: tampering detected!",
            "   # - NOT_FOUND: log missing",
            "",
            "7. Automated validation script (Python):",
            "   import boto3",
            "   ct = boto3.client('cloudtrail')",
            "",
            "   response = ct.validate_logs(",
            "     TrailARN='arn:aws:cloudtrail:...',",
            "     StartTime=datetime(2024, 1, 15),",
            "     EndTime=datetime(2024, 1, 16)",
            "   )",
            "",
            "   for result in response['ValidationResults']:",
            "     if result['Status'] != 'VALID':",
            "       print(f\"ALERT: {result['S3Object']} - {result['Status']}\")",
            "",
            "8. S3 bucket policy - prevent log deletion:",
            "   {",
            '     "Version": "2012-10-17",',
            '     "Statement": [{',
            '       "Sid": "PreventLogDeletion",',
            '       "Effect": "Deny",',
            '       "Principal": "*",',
            '       "Action": "s3:DeleteObject",',
            '       "Resource": "arn:aws:s3:::cloudtrail-logs-org/*"',
            "     }]",
            "   }",
            "",
            "9. S3 Object Lock pour WORM (immutability):",
            "   # Enable versioning first:",
            "   aws s3api put-bucket-versioning --bucket cloudtrail-logs-org --versioning-configuration Status=Enabled",
            "",
            "   # Enable Object Lock:",
            "   aws s3api put-object-lock-configuration \\",
            "     --bucket cloudtrail-logs-org \\",
            "     --object-lock-configuration '{",
            '       "ObjectLockEnabled": "Enabled",',
            '       "Rule": {',
            '         "DefaultRetention": {',
            '           "Mode": "COMPLIANCE",',
            '           "Days": 365',
            "         }",
            "       }",
            "     }'",
            "",
            "10. CloudWatch alarm - trail stopped:",
            "    aws cloudwatch put-metric-alarm \\",
            "      --alarm-name cloudtrail-stopped \\",
            "      --metric-name IsLogging \\",
            "      --namespace AWS/CloudTrail \\",
            "      --statistic Average \\",
            "      --period 300 \\",
            "      --evaluation-periods 1 \\",
            "      --threshold 0.5 \\",
            "      --comparison-operator LessThanThreshold \\",
            "      --dimensions Name=TrailName,Value=organization-trail \\",
            "      --alarm-actions arn:aws:sns:region:account:security-alerts"
        ],
        verification_steps=[
            "Vérifier trail est multi-region:",
            "  aws cloudtrail get-trail --name organization-trail \\",
            "    --query 'Trail.IsMultiRegionTrail'",
            "  # Expected: true",
            "",
            "Vérifier log file validation activée:",
            "  aws cloudtrail get-trail --name organization-trail \\",
            "    --query 'Trail.LogFileValidationEnabled'",
            "  # Expected: true",
            "",
            "Vérifier trail logging status:",
            "  aws cloudtrail get-trail-status --name organization-trail \\",
            "    --query 'IsLogging'",
            "  # Expected: true",
            "",
            "Lister tous trails (audit single-region):",
            "  aws cloudtrail describe-trails \\",
            "    --query 'trailList[].[Name,IsMultiRegionTrail,LogFileValidationEnabled]' \\",
            "    --output table",
            "",
            "Test validation integrity recent logs:",
            "  aws cloudtrail validate-logs \\",
            "    --trail-arn arn:aws:cloudtrail:region:account:trail/organization-trail \\",
            "    --start-time $(date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%SZ) \\",
            "    --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ)",
            "  # All logs should be VALID",
            "",
            "Vérifier digest files dans S3:",
            "  aws s3 ls s3://cloudtrail-logs-org/AWSLogs/account/CloudTrail-Digest/",
            "  # Digest files: <trail>_<region>_CloudTrail-Digest_<date>.json.gz",
            "",
            "Download et inspect digest file:",
            "  aws s3 cp s3://cloudtrail-logs-org/.../digest.json.gz .",
            "  gunzip digest.json.gz",
            "  cat digest.json | jq '.logFiles[] | {file: .s3Object, hash: .hashValue}'",
            "",
            "Vérifier S3 bucket policy deny delete:",
            "  aws s3api get-bucket-policy --bucket cloudtrail-logs-org | jq '.Policy | fromjson'",
            "  # Check Deny s3:DeleteObject statement",
            "",
            "Vérifier Object Lock configuré:",
            "  aws s3api get-object-lock-configuration --bucket cloudtrail-logs-org",
            "",
            "CloudWatch alarm status:",
            "  aws cloudwatch describe-alarms --alarm-names cloudtrail-stopped",
            "",
            "CloudTrail events - vérifier pas de StopLogging malveillant:",
            "  aws cloudtrail lookup-events \\",
            "    --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \\",
            "    --max-results 50"
        ],
        references=[
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html",
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html",
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-cli.html"
        ]
    )
]



# ==================== CLOUDFORMATION ====================
CLOUDFORMATION_QUESTIONS = [
    Question(
        id="CFN-001",
        question="Drift detection activé et stack policies configurées pour protéger ressources critiques?",
        description="Vérifier drift detection régulier et stack policies empêchant modification/suppression ressources",
        severity="HIGH",
        category="CloudFormation",
        compliance=["AWS Well-Architected", "Change Management"],
        technical_details="Drift detection identifie changements manuels. Stack policies protègent contre updates accidentels",
        remediation=["aws cloudformation detect-stack-drift", "Créer stack policy JSON", "aws cloudformation set-stack-policy"],
        verification_steps=["aws cloudformation describe-stack-drift-detection-status", "aws cloudformation get-stack-policy"],
        references=["https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-drift.html"]
    ),
    
    Question(
        id="CFN-002",
        question="Secrets et credentials gérés via Secrets Manager/Parameter Store, pas de hardcoded values?",
        description="Vérifier que templates CloudFormation utilisent dynamic references, pas de secrets en clair",
        severity="CRITICAL",
        category="CloudFormation",
        compliance=["Security Best Practices", "PCI-DSS"],
        technical_details="Utiliser {{resolve:secretsmanager:secret-id}} et {{resolve:ssm-secure:parameter}} dans templates",
        remediation=["Migrer secrets vers Secrets Manager", "Utiliser dynamic references CFN", "Scan templates pour secrets hardcodés"],
        verification_steps=["git-secrets ou trufflehog sur repo", "aws cloudformation get-template", "Vérifier NoEcho sur parameters sensibles"],
        references=["https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html"]
    ),
    
    Question(
        id="CFN-003",
        question="ChangeSets utilisés avant tout déploiement pour review et StackSets pour déploiements multi-comptes?",
        description="Vérifier utilisation change sets (preview changes) et StackSets pour governance multi-account",
        severity="MEDIUM",
        category="CloudFormation",
        compliance=["Change Management", "Multi-Account Strategy"],
        technical_details="Change Sets = dry-run montrant impact changes. StackSets = déploiement centralisé multi-comptes/régions",
        remediation=["aws cloudformation create-change-set", "Review avant execute-change-set", "create-stack-set pour multi-account"],
        verification_steps=["Vérifier CI/CD utilise change-set", "aws cloudformation list-stack-sets", "describe-stack-set-operation"],
        references=["https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-changesets.html"]
    )
]

# ==================== CLOUDWATCH ====================
CLOUDWATCH_QUESTIONS = [
    Question(
        id="CW-001",
        question="Alarmes CloudWatch critiques configurées (CPU, StatusCheckFailed, disk, RDS) avec SNS notifications?",
        description="Vérifier alarmes pour métriques critiques avec actions SNS/Auto Scaling",
        severity="HIGH",
        category="CloudWatch",
        compliance=["AWS Well-Architected", "Operational Excellence"],
        technical_details="Alarmes sur EC2 CPU > 80%, StatusCheckFailed, RDS CPU/FreeableMemory, Lambda errors, etc.",
        remediation=["aws cloudwatch put-metric-alarm", "Créer SNS topic", "subscribe email/SMS", "Alarmes composite pour AND/OR logic"],
        verification_steps=["aws cloudwatch describe-alarms", "Tester avec set-alarm-state", "Vérifier actions configurées"],
        references=["https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"]
    ),
    
    Question(
        id="CW-002",
        question="Log retention configurée (30-90+ jours) et log aggregation pour toutes applications critiques?",
        description="Vérifier CloudWatch Logs retention policies et centralization multi-account",
        severity="MEDIUM",
        category="CloudWatch",
        compliance=["Compliance Retention", "Forensics"],
        technical_details="Retention par défaut = indefinite (coûteux). Set 30/90/365 jours selon compliance. Cross-account logging.",
        remediation=["aws logs put-retention-policy", "Subscription filters vers central account", "Kinesis Data Firehose vers S3 long-term"],
        verification_steps=["aws logs describe-log-groups --query 'logGroups[?!retentionInDays]'", "Identifier groupes sans retention"],
        references=["https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html"]
    ),
    
    Question(
        id="CW-003",
        question="Metric filters configurés pour events sécurité (unauthorized API calls, IAM changes, root usage)?",
        description="Vérifier metric filters CloudWatch Logs pour détecter activité suspecte et violations",
        severity="HIGH",
        category="CloudWatch",
        compliance=["CIS Benchmark", "Security Monitoring"],
        technical_details="Metric filters transforment log patterns en métriques CloudWatch. Alarmes sur métriques pour alerting.",
        remediation=["Créer filters: UnauthorizedAPICalls, RootAccountUsage, IAMPolicyChanges", "aws logs put-metric-filter", "Alarmes sur metrics"],
        verification_steps=["aws logs describe-metric-filters", "CIS Benchmark section 3 (Monitoring)", "Test avec unauthorized API call"],
        references=["https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html"]
    )
]

# ==================== CLOUDFRONT ====================
CLOUDFRONT_QUESTIONS = [
    Question(
        id="CF-001",
        question="CloudFront avec HTTPS obligatoire, TLS 1.2+ enforced, et WAF attaché?",
        description="Vérifier CloudFront distributions utilisent HTTPS only, TLS moderne, et AWS WAF",
        severity="CRITICAL",
        category="CloudFront",
        compliance=["PCI-DSS", "OWASP"],
        technical_details="Viewer Protocol Policy=redirect-to-https. Origin Protocol Policy=https-only. Security policy TLSv1.2_2021",
        remediation=["update-distribution viewer-protocol-policy", "Attacher Web ACL WAF", "Security policy minimum TLS 1.2"],
        verification_steps=["aws cloudfront get-distribution", "Vérifier ViewerProtocolPolicy, WebACLId, MinimumProtocolVersion"],
        references=["https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html"]
    ),
    
    Question(
        id="CF-002",
        question="CloudFront logging activé vers S3 et Origin Access Identity (OAI) pour S3 origins?",
        description="Vérifier access logs CloudFront et OAI pour sécuriser accès S3 (pas de public access)",
        severity="HIGH",
        category="CloudFront",
        compliance=["Audit Trail", "Security"],
        technical_details="Logging capture toutes requests. OAI = identité CloudFront, bucket policy autorise seulement OAI",
        remediation=["update-distribution --logging-config", "create-cloud-front-origin-access-identity", "Update S3 bucket policy"],
        verification_steps=["get-distribution --query 'Distribution.DistributionConfig.Logging'", "Vérifier OAI dans Origins"],
        references=["https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html"]
    ),
    
    Question(
        id="CF-003",
        question="Geo-restriction et signed URLs/cookies pour contenu privé si applicable?",
        description="Vérifier geo-blocking et signed URLs pour restreindre accès contenu sensible",
        severity="MEDIUM",
        category="CloudFront",
        compliance=["Access Control"],
        technical_details="Geo-restriction whitelist/blacklist pays. Signed URLs/cookies avec expiration pour contenu privé",
        remediation=["update-distribution --restrictions", "Générer signed URLs avec CloudFront key pair", "Lambda@Edge pour auth custom"],
        verification_steps=["get-distribution --query 'Distribution.DistributionConfig.Restrictions'", "Test signed URL generation"],
        references=["https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/PrivateContent.html"]
    )
]

# ==================== KMS ====================
KMS_QUESTIONS = [
    Question(
        id="KMS-001",
        question="KMS customer-managed keys avec rotation automatique activée et key policies least privilege?",
        description="Vérifier CMKs avec auto-rotation annuelle et policies restrictives (pas de wildcard principals)",
        severity="HIGH",
        category="KMS",
        compliance=["PCI-DSS", "HIPAA", "Cryptographic Standards"],
        technical_details="Auto-rotation yearly. Key policies contrôlent qui peut utiliser/gérer keys. Séparer encrypt vs decrypt permissions",
        remediation=["enable-key-rotation", "Créer key policy avec principals spécifiques", "Separate keys par environment/data classification"],
        verification_steps=["aws kms get-key-rotation-status", "get-key-policy", "Identifier keys sans rotation ou policies trop permissives"],
        references=["https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html"]
    ),
    
    Question(
        id="KMS-002",
        question="CloudTrail logging actif pour toutes opérations KMS et alarmes sur usage anormal?",
        description="Vérifier CloudTrail capture KMS API calls et alarmes sur disable-key, delete-key, policy changes",
        severity="CRITICAL",
        category="KMS",
        compliance=["Audit", "Security Monitoring"],
        technical_details="CloudTrail logs Decrypt, Encrypt, GenerateDataKey calls. Metric filters pour suspicious activity",
        remediation=["CloudTrail enabled", "Metric filters: DisableKey, ScheduleKeyDeletion, PutKeyPolicy", "Alarmes CloudWatch"],
        verification_steps=["CloudTrail lookup-events EventName=DisableKey", "aws cloudwatch describe-alarms | grep KMS"],
        references=["https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html"]
    ),
    
    Question(
        id="KMS-003",
        question="Key deletion protection et délai minimum 30 jours avant suppression effective?",
        description="Vérifier ScheduleKeyDeletion avec PendingWindowInDays >= 30 et monitoring sur scheduled deletions",
        severity="HIGH",
        category="KMS",
        compliance=["Data Protection", "Disaster Recovery"],
        technical_details="KMS keys jamais supprimées immédiatement. Waiting period 7-30 jours. Permet cancel si erreur",
        remediation=["schedule-key-deletion --pending-window-in-days 30", "Alarme sur ScheduleKeyDeletion events", "Cancel avec cancel-key-deletion"],
        verification_steps=["describe-key --query 'KeyMetadata.KeyState'", "Identifier keys dans PendingDeletion state"],
        references=["https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html"]
    )
]

# ==================== ECS/EKS ====================
CONTAINER_QUESTIONS = [
    Question(
        id="CONTAINER-001",
        question="Container images scannées pour vulnérabilités (ECR scan ou Trivy) et provenant de registries approuvés?",
        description="Vérifier scanning automatique images ECR et policies empêchant images non-scannées/vulnérables",
        severity="CRITICAL",
        category="Containers",
        compliance=["Security Scanning", "Supply Chain"],
        technical_details="ECR scan on push avec findings CRITICAL/HIGH. Image policies bloquer deploy si vulnérabilités. Trusted registries only",
        remediation=["put-image-scanning-configuration scanOnPush=true", "Review scan findings", "OPA/Admission controller pour K8s"],
        verification_steps=["describe-image-scan-findings", "Lister images avec CRITICAL findings", "Vérifier scan récent < 7 jours"],
        references=["https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html"]
    ),
    
    Question(
        id="CONTAINER-002",
        question="ECS tasks/EKS pods avec IAM roles (pas de credentials hardcodés), secrets via Secrets Manager?",
        description="Vérifier task definitions utilisent taskRoleArn et secrets injectés depuis Secrets Manager/Parameter Store",
        severity="CRITICAL",
        category="Containers",
        compliance=["Least Privilege", "Secrets Management"],
        technical_details="Task IAM role pour permissions AWS. Execution role pour pull image ECR. Secrets injection via environment valueFrom",
        remediation=["register-task-definition avec taskRoleArn", "Secrets dans secrets section valueFrom", "EKS: ExternalSecrets Operator"],
        verification_steps=["describe-task-definition", "Chercher hardcoded AWS credentials", "Vérifier taskRoleArn présent"],
        references=["https://docs.aws.amazon.com/AmazonECS/latest/developerguide/specifying-sensitive-data-secrets.html"]
    ),
    
    Question(
        id="CONTAINER-003",
        question="EKS: RBAC configuré restrictif, PSP/PSA pour pod security, network policies actives?",
        description="Vérifier Kubernetes RBAC least privilege, Pod Security Standards, et Network Policies segmentation",
        severity="HIGH",
        category="Containers",
        compliance=["K8s Security", "Zero Trust"],
        technical_details="RBAC roles/rolebindings par namespace. PSA restricted mode. Network Policies deny-all par défaut puis allow specific",
        remediation=["kubectl create role/rolebinding", "Pod Security admission: restricted", "kubectl apply network-policy"],
        verification_steps=["kubectl get rolebindings --all-namespaces", "kubectl get psp ou admission config", "kubectl get networkpolicies"],
        references=["https://kubernetes.io/docs/concepts/security/rbac-good-practices/"]
    )
]

# ==================== ROUTE53 ====================
ROUTE53_QUESTIONS = [
    Question(
        id="R53-001",
        question="DNSSEC activé sur hosted zones publiques et Route53 Resolver DNS Firewall configuré?",
        description="Vérifier DNSSEC signing pour authenticity et DNS Firewall pour bloquer domaines malicieux",
        severity="HIGH",
        category="Route53",
        compliance=["DNS Security", "Threat Protection"],
        technical_details="DNSSEC cryptographic signing empêche DNS spoofing. DNS Firewall filtre queries vers domaines malveillants",
        remediation=["enable-hosted-zone-dnssec", "create-firewall-rule-group avec managed domain lists", "associate-firewall-rule-group to VPC"],
        verification_steps=["aws route53 get-dnssec --hosted-zone-id", "list-firewall-rule-groups", "Test dig +dnssec domain"],
        references=["https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-dnssec.html"]
    ),
    
    Question(
        id="R53-002",
        question="Query logging activé vers CloudWatch pour audit et health checks configurés avec alarmes?",
        description="Vérifier Route53 query logging et health checks avec SNS notifications sur failures",
        severity="MEDIUM",
        category="Route53",
        compliance=["Audit Trail", "Availability Monitoring"],
        technical_details="Query logging capture toutes DNS queries. Health checks monitoring endpoints avec failover automatique",
        remediation=["create-query-logging-config", "create-health-check avec AlarmConfiguration", "SNS topic pour notifications"],
        verification_steps=["list-query-logging-configs", "list-health-checks", "CloudWatch Logs groupe /aws/route53/"],
        references=["https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/query-logs.html"]
    )
]


# Export ALL_QUESTIONS
ALL_QUESTIONS = (IAM_QUESTIONS + VPC_QUESTIONS + EC2_QUESTIONS + S3_QUESTIONS + 
                 RDS_QUESTIONS + LAMBDA_QUESTIONS + APIGATEWAY_QUESTIONS + CLOUDTRAIL_QUESTIONS +
                 CLOUDFORMATION_QUESTIONS + CLOUDWATCH_QUESTIONS + CLOUDFRONT_QUESTIONS + 
                 KMS_QUESTIONS + CONTAINER_QUESTIONS + ROUTE53_QUESTIONS)

# Export des listes pour l'app
__all__ = ['ALL_QUESTIONS', 'IAM_QUESTIONS', 'VPC_QUESTIONS', 'EC2_QUESTIONS', 'S3_QUESTIONS',
           'RDS_QUESTIONS', 'LAMBDA_QUESTIONS', 'APIGATEWAY_QUESTIONS', 'CLOUDTRAIL_QUESTIONS',
           'CLOUDFORMATION_QUESTIONS', 'CLOUDWATCH_QUESTIONS', 'CLOUDFRONT_QUESTIONS',
           'KMS_QUESTIONS', 'CONTAINER_QUESTIONS', 'ROUTE53_QUESTIONS', 'Question']
