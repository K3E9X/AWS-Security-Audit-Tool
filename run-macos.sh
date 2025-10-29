#!/bin/bash

# Script de lancement pour macOS
# AWS Security Audit Tool

echo "🔒 AWS Security Audit Tool - Démarrage (macOS)"
echo "================================================"

# Vérifier si Python est installé
if ! command -v python3 &> /dev/null; then
    echo "❌ Erreur: Python 3 n'est pas installé"
    echo "   Installer avec: brew install python@3.11"
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo "✓ Python détecté: $PYTHON_VERSION"

# Vérifier la version de Python (minimum 3.9)
PYTHON_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
PYTHON_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 9 ]); then
    echo "❌ Python 3.9+ requis (actuellement: $PYTHON_VERSION)"
    echo "   Installer avec: brew install python@3.11"
    exit 1
fi

# Vérifier si un environnement virtuel existe
if [ ! -d "venv" ]; then
    echo "📦 Création d'un environnement virtuel..."
    python3 -m venv venv

    if [ $? -ne 0 ]; then
        echo "❌ Erreur lors de la création de l'environnement virtuel"
        exit 1
    fi
    echo "✓ Environnement virtuel créé"
fi

# Activer l'environnement virtuel
echo "🔧 Activation de l'environnement virtuel..."
source venv/bin/activate

# Mettre à jour pip, setuptools et wheel
echo "📦 Mise à jour de pip, setuptools et wheel..."
python3 -m pip install --upgrade pip setuptools wheel

# Vérifier si les dépendances sont installées
if ! python3 -c "import streamlit" &> /dev/null; then
    echo "⚠️  Les dépendances ne sont pas installées"
    echo "📦 Installation des dépendances pour macOS..."
    echo ""

    # Option 1: Essayer d'installer avec les wheels précompilés
    echo "🔄 Tentative d'installation avec wheels précompilés..."
    python3 -m pip install --only-binary :all: numpy pandas 2>/dev/null

    if [ $? -eq 0 ]; then
        echo "✓ numpy et pandas installés (wheels précompilés)"
    else
        echo "⚠️  Installation avec wheels précompilés échouée, installation standard..."
        python3 -m pip install numpy pandas
    fi

    # Installer le reste des dépendances
    python3 -m pip install -r requirements-macos.txt

    if [ $? -ne 0 ]; then
        echo ""
        echo "❌ Erreur lors de l'installation des dépendances"
        echo ""
        echo "Solutions alternatives:"
        echo "1. Installer Xcode Command Line Tools:"
        echo "   xcode-select --install"
        echo ""
        echo "2. Utiliser Homebrew pour installer numpy:"
        echo "   brew install numpy"
        echo ""
        echo "3. Essayer avec conda:"
        echo "   conda create -n aws-audit python=3.11"
        echo "   conda activate aws-audit"
        echo "   conda install numpy pandas"
        echo "   pip install -r requirements-macos.txt"
        exit 1
    fi
    echo "✓ Dépendances installées avec succès"
else
    echo "✓ Dépendances déjà installées"
fi

# Vérifier que la base de données de questions est accessible
echo "📋 Vérification de la base de données..."
QUESTION_COUNT=$(python3 -c "from data.aws_services_questions import ALL_QUESTIONS; print(len(ALL_QUESTIONS))" 2>/dev/null)

if [ $? -eq 0 ]; then
    echo "✓ Base de données chargée: $QUESTION_COUNT questions disponibles"
else
    echo "❌ Erreur lors du chargement de la base de données"
    exit 1
fi

# Lancer l'application
echo ""
echo "🚀 Lancement de l'application..."
echo "📍 L'application s'ouvrira dans votre navigateur"
echo ""
echo "💡 Pour arrêter: Ctrl+C"
echo ""

python3 -m streamlit run app.py

# Désactiver l'environnement virtuel à la sortie
deactivate
