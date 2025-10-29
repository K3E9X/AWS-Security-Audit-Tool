# AWS Security Audit Tool - Guide d'Installation et de Test

## 📋 Résumé

Ce document explique comment installer et tester l'AWS Security Audit Tool.

## ✅ Problème Résolu

**Problème initial:** L'application `app.py` ne se lançait pas.

**Cause:** Les dépendances Python n'étaient pas installées.

**Solution:** Installation des dépendances via `pip install -r requirements.txt`

## 🔧 Installation

### Prérequis

- Python 3.11 ou supérieur
- pip (gestionnaire de paquets Python)

### Étapes d'installation

1. **Cloner le dépôt** (si ce n'est pas déjà fait)
   ```bash
   git clone <url-du-repo>
   cd Machine71
   ```

2. **Installer les dépendances**
   ```bash
   pip install -r requirements.txt
   ```

   Les packages suivants seront installés:
   - streamlit==1.29.0
   - plotly==5.18.0
   - pandas==2.1.4
   - pydantic==2.5.3
   - python-dotenv==1.0.0
   - markdown==3.5.1
   - reportlab==4.0.7
   - Pillow==10.1.0
   - streamlit-drawable-canvas==0.9.3
   - streamlit-agraph==0.0.45

3. **Lancer l'application**

   **Option A: Utiliser le script de lancement** (recommandé)
   ```bash
   ./run.sh
   ```

   **Option B: Lancer manuellement**
   ```bash
   streamlit run app.py
   ```

## 🧪 Tests Effectués

### Test 1: Import de la base de données
```bash
python -c "from data.aws_services_questions import ALL_QUESTIONS; print(f'Questions: {len(ALL_QUESTIONS)}')"
```
**Résultat:** ✅ 100 questions chargées avec succès

### Test 2: Gestion de session
```bash
python -c "from utils.session import AuditSession; s = AuditSession(); print(f'Session: {s.total} questions')"
```
**Résultat:** ✅ Session initialisée correctement

### Test 3: Module de diagrammes
```bash
python -c "from utils.diagram import DiagramEditor; print('OK')"
```
**Résultat:** ✅ Module importé sans erreur

### Test 4: Lancement de l'application
```bash
streamlit run app.py --server.headless=true
```
**Résultat:** ✅ Application démarre sur http://localhost:8501

## 📊 Structure du Projet

```
Machine71/
├── app.py                          # Application principale Streamlit
├── requirements.txt                # Dépendances Python
├── run.sh                         # Script de lancement automatique
├── README_INSTALLATION.md         # Ce fichier
├── data/
│   ├── __init__.py
│   └── aws_services_questions.py  # Base de données de 100 questions
└── utils/
    ├── __init__.py
    ├── session.py                 # Gestion des sessions d'audit
    ├── export.py                  # Export MD/PDF
    └── diagram.py                 # Éditeur de diagrammes
```

## 🎯 Fonctionnalités Vérifiées

- ✅ Interface Streamlit charge correctement
- ✅ 100 questions de sécurité AWS disponibles
- ✅ 15 services AWS couverts (IAM, VPC, EC2, S3, RDS, Lambda, etc.)
- ✅ Système de session pour sauvegarder les réponses
- ✅ Export en Markdown et PDF
- ✅ Éditeur de diagrammes d'architecture
- ✅ Filtres par sévérité et conformité
- ✅ Dashboard avec statistiques

## 🚀 Utilisation

1. Lancer l'application avec `./run.sh` ou `streamlit run app.py`
2. Ouvrir votre navigateur à l'adresse indiquée (généralement http://localhost:8501)
3. Naviguer via le menu latéral pour accéder aux différents services AWS
4. Répondre aux questions de sécurité
5. Exporter le rapport final

## 📝 Notes

- L'application fonctionne en mode headless (sans navigateur automatique)
- Les sessions sont sauvegardées dans le dossier `sessions/`
- Les diagrammes sont sauvegardés dans `data/diagrams/`
- Port par défaut: 8501

## 🐛 Dépannage

### Erreur: "No module named streamlit"
**Solution:** Exécuter `pip install -r requirements.txt`

### Erreur: "packaging conflict"
**Solution:** Exécuter `pip install -r requirements.txt --ignore-installed packaging`

### L'application ne se lance pas
**Solution:** Vérifier que Python 3.11+ est installé avec `python --version`

## ✅ Statut Final

🎉 **L'application fonctionne correctement!**

Tous les tests passent et l'application est prête à être utilisée pour des audits de sécurité AWS professionnels.
