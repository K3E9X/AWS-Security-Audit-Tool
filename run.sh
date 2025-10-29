#!/bin/bash

# Script de lancement de l'AWS Security Audit Tool
# Ce script vérifie les dépendances et lance l'application Streamlit

echo "🔒 AWS Security Audit Tool - Démarrage"
echo "========================================"

# Vérifier si Python est installé
if ! command -v python &> /dev/null; then
    echo "❌ Erreur: Python n'est pas installé"
    exit 1
fi

echo "✓ Python détecté: $(python --version)"

# Vérifier si les dépendances sont installées
if ! python -c "import streamlit" &> /dev/null; then
    echo "⚠️  Les dépendances ne sont pas installées"
    echo "📦 Installation des dépendances..."
    pip install -r requirements.txt

    if [ $? -ne 0 ]; then
        echo "❌ Erreur lors de l'installation des dépendances"
        exit 1
    fi
    echo "✓ Dépendances installées avec succès"
else
    echo "✓ Dépendances déjà installées"
fi

# Vérifier que la base de données de questions est accessible
echo "📋 Vérification de la base de données..."
QUESTION_COUNT=$(python -c "from data.aws_services_questions import ALL_QUESTIONS; print(len(ALL_QUESTIONS))" 2>/dev/null)

if [ $? -eq 0 ]; then
    echo "✓ Base de données chargée: $QUESTION_COUNT questions disponibles"
else
    echo "❌ Erreur lors du chargement de la base de données"
    exit 1
fi

# Lancer l'application
echo ""
echo "🚀 Lancement de l'application..."
echo "📍 L'application sera accessible via votre navigateur"
echo ""

streamlit run app.py
