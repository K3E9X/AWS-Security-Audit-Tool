"""
Exemples d'utilisation de l'API AWS Security Audit

Ce script montre comment interroger l'API pour obtenir des questions d'audit.
"""

import requests
import json

# URL de base de l'API (à adapter selon votre configuration)
BASE_URL = "http://localhost:8000"


def print_json(data):
    """Affiche le JSON de manière formatée"""
    print(json.dumps(data, indent=2, ensure_ascii=False))


def example_1_get_all_questions():
    """Exemple 1: Récupérer toutes les questions"""
    print("\n" + "="*80)
    print("EXEMPLE 1: Récupérer toutes les questions d'audit")
    print("="*80)

    response = requests.get(f"{BASE_URL}/questions")
    data = response.json()

    print(f"\nNombre total de questions: {data['total']}")
    print(f"\nPremière question:")
    print_json(data['questions'][0])


def example_2_get_by_category():
    """Exemple 2: Récupérer les questions IAM"""
    print("\n" + "="*80)
    print("EXEMPLE 2: Récupérer les questions de la catégorie IAM")
    print("="*80)

    response = requests.get(f"{BASE_URL}/questions?category=iam")
    data = response.json()

    print(f"\nNombre de questions IAM: {data['total']}")
    for q in data['questions'][:3]:  # Afficher les 3 premières
        print(f"\n- [{q['id']}] {q['question']}")
        print(f"  Sévérité: {q['severity']}")


def example_3_get_critical_questions():
    """Exemple 3: Récupérer uniquement les questions critiques"""
    print("\n" + "="*80)
    print("EXEMPLE 3: Récupérer les questions critiques")
    print("="*80)

    response = requests.get(f"{BASE_URL}/questions?severity=critical")
    data = response.json()

    print(f"\nNombre de questions critiques: {data['total']}")
    for q in data['questions']:
        print(f"\n- [{q['id']}] {q['question']}")
        print(f"  Catégorie: {q['category']}")
        print(f"  Services: {', '.join(q['aws_services'])}")


def example_4_get_by_service():
    """Exemple 4: Récupérer les questions pour S3"""
    print("\n" + "="*80)
    print("EXEMPLE 4: Récupérer les questions concernant S3")
    print("="*80)

    response = requests.get(f"{BASE_URL}/service/S3")
    data = response.json()

    print(f"\nNombre de questions pour S3: {data['total']}")
    for q in data['questions']:
        print(f"\n- [{q['id']}] {q['question']}")
        print(f"  Description: {q['description']}")


def example_5_get_by_compliance():
    """Exemple 5: Récupérer les questions PCI-DSS"""
    print("\n" + "="*80)
    print("EXEMPLE 5: Récupérer les questions liées à PCI-DSS")
    print("="*80)

    response = requests.get(f"{BASE_URL}/compliance/PCI-DSS")
    data = response.json()

    print(f"\nNombre de questions PCI-DSS: {data['total']}")
    for q in data['questions'][:5]:  # Afficher les 5 premières
        print(f"\n- [{q['id']}] {q['question']}")


def example_6_get_categories():
    """Exemple 6: Lister toutes les catégories"""
    print("\n" + "="*80)
    print("EXEMPLE 6: Lister toutes les catégories disponibles")
    print("="*80)

    response = requests.get(f"{BASE_URL}/categories")
    data = response.json()

    print("\nCatégories disponibles:\n")
    for cat in data['categories']:
        print(f"- {cat['name']}")
        print(f"  {cat['description']}")
        print(f"  Nombre de questions: {cat['question_count']}\n")


def example_7_get_specific_question():
    """Exemple 7: Récupérer une question spécifique par ID"""
    print("\n" + "="*80)
    print("EXEMPLE 7: Récupérer la question IAM-001")
    print("="*80)

    response = requests.get(f"{BASE_URL}/questions/IAM-001")
    question = response.json()

    print(f"\nID: {question['id']}")
    print(f"Question: {question['question']}")
    print(f"Description: {question['description']}")
    print(f"Sévérité: {question['severity']}")
    print(f"Services AWS: {', '.join(question['aws_services'])}")
    print(f"Frameworks: {', '.join(question['compliance_frameworks'])}")

    print(f"\nÉtapes de remédiation:")
    for i, step in enumerate(question['remediation_steps'], 1):
        print(f"  {i}. {step}")


def example_8_get_statistics():
    """Exemple 8: Récupérer les statistiques"""
    print("\n" + "="*80)
    print("EXEMPLE 8: Récupérer les statistiques globales")
    print("="*80)

    response = requests.get(f"{BASE_URL}/stats")
    stats = response.json()

    print(f"\nNombre total de questions: {stats['total_questions']}")
    print(f"Services AWS couverts: {stats['total_services']}")
    print(f"Frameworks de conformité: {stats['total_frameworks']}")

    print("\nRépartition par sévérité:")
    for severity, count in stats['by_severity'].items():
        print(f"  - {severity}: {count}")


def example_9_combined_filters():
    """Exemple 9: Combiner plusieurs filtres"""
    print("\n" + "="*80)
    print("EXEMPLE 9: Questions critiques de la catégorie Network")
    print("="*80)

    response = requests.get(
        f"{BASE_URL}/questions?category=network&severity=critical"
    )
    data = response.json()

    print(f"\nNombre de questions: {data['total']}")
    for q in data['questions']:
        print(f"\n- [{q['id']}] {q['question']}")
        print(f"  Services: {', '.join(q['aws_services'])}")


def example_10_generate_audit_checklist():
    """Exemple 10: Générer une checklist d'audit complète"""
    print("\n" + "="*80)
    print("EXEMPLE 10: Générer une checklist d'audit par catégorie")
    print("="*80)

    # Récupérer toutes les catégories
    response = requests.get(f"{BASE_URL}/categories")
    categories_data = response.json()

    print("\n--- CHECKLIST D'AUDIT DE SÉCURITÉ AWS ---\n")

    for cat_info in categories_data['categories']:
        category = cat_info['category']
        print(f"\n### {cat_info['name']}")
        print(f"{cat_info['description']}\n")

        # Récupérer les questions de cette catégorie
        response = requests.get(
            f"{BASE_URL}/questions/category/{category}"
        )
        data = response.json()

        # Trier par sévérité
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        questions = sorted(
            data['questions'],
            key=lambda x: severity_order[x['severity']]
        )

        for q in questions:
            print(f"[ ] [{q['severity'].upper()}] {q['question']}")

        print(f"\nTotal: {len(questions)} questions\n")


if __name__ == "__main__":
    print("\n" + "="*80)
    print("EXEMPLES D'UTILISATION DE L'API AWS SECURITY AUDIT")
    print("="*80)
    print("\nAssurez-vous que l'API est lancée (python main.py)")

    try:
        # Vérifier que l'API est accessible
        response = requests.get(f"{BASE_URL}/health")
        if response.status_code == 200:
            print(f"\nAPI accessible: {response.json()}")

            # Exécuter tous les exemples
            example_1_get_all_questions()
            example_2_get_by_category()
            example_3_get_critical_questions()
            example_4_get_by_service()
            example_5_get_by_compliance()
            example_6_get_categories()
            example_7_get_specific_question()
            example_8_get_statistics()
            example_9_combined_filters()
            example_10_generate_audit_checklist()

            print("\n" + "="*80)
            print("Tous les exemples ont été exécutés avec succès!")
            print("="*80 + "\n")

    except requests.exceptions.ConnectionError:
        print("\n❌ ERREUR: Impossible de se connecter à l'API")
        print("Assurez-vous que l'API est lancée avec: python main.py")
        print("="*80 + "\n")
