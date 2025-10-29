#!/bin/bash

# Script de diagnostic et correction pour macOS
# AWS Security Audit Tool

echo "🔍 Diagnostic macOS - AWS Security Audit Tool"
echo "=============================================="
echo ""

# Détection de la version Python
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)' 2>/dev/null)
PYTHON_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)' 2>/dev/null)

echo "🐍 Python détecté: $PYTHON_VERSION"
echo ""

# Vérifier si Python 3.14
if [ "$PYTHON_MAJOR" = "3" ] && [ "$PYTHON_MINOR" -ge "14" ]; then
    echo "⚠️  ATTENTION: Python 3.14+ détecté"
    echo ""
    echo "Python 3.14 est très récent et certains packages (pyarrow, pandas)"
    echo "n'ont pas encore de wheels précompilés pour cette version."
    echo ""
    echo "📋 SOLUTIONS RECOMMANDÉES:"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Option 1: Utiliser Python 3.11 ou 3.12 (RECOMMANDÉ)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "# Installer Python 3.11 via Homebrew"
    echo "brew install python@3.11"
    echo ""
    echo "# Créer l'environnement avec Python 3.11"
    echo "python3.11 -m venv venv"
    echo "source venv/bin/activate"
    echo "pip install -r requirements-macos.txt"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Option 2: Installer cmake et compiler pyarrow"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "# Installer cmake via Homebrew"
    echo "brew install cmake apache-arrow"
    echo ""
    echo "# Puis réessayer l'installation"
    echo "./run-macos.sh"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Option 3: Utiliser Conda (Alternative)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "# Créer un environnement conda"
    echo "conda create -n aws-audit python=3.11"
    echo "conda activate aws-audit"
    echo "conda install -c conda-forge pyarrow pandas numpy"
    echo "pip install -r requirements-macos.txt"
    echo ""

    read -p "Veux-tu que je vérifie si Homebrew est installé pour Option 1 ou 2? (y/n) " -n 1 -r
    echo ""

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if command -v brew &> /dev/null; then
            echo "✅ Homebrew est installé"
            echo ""
            read -p "Installer Python 3.11 via Homebrew? (y/n) " -n 1 -r
            echo ""
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                echo "📦 Installation de Python 3.11..."
                brew install python@3.11
                echo ""
                echo "✅ Python 3.11 installé!"
                echo ""
                echo "Maintenant, exécute:"
                echo "  python3.11 -m venv venv"
                echo "  source venv/bin/activate"
                echo "  pip install -r requirements-macos.txt"
            fi
        else
            echo "❌ Homebrew n'est pas installé"
            echo ""
            echo "Installer Homebrew avec:"
            echo '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
        fi
    fi

    exit 0
fi

# Python version acceptable
echo "✅ Version Python compatible ($PYTHON_VERSION)"
echo ""

# Vérifier cmake
if ! command -v cmake &> /dev/null; then
    echo "⚠️  cmake n'est pas installé (nécessaire pour certains packages)"
    echo ""
    echo "Installer avec: brew install cmake"
    echo ""
fi

# Vérifier Xcode Command Line Tools
if ! xcode-select -p &> /dev/null; then
    echo "⚠️  Xcode Command Line Tools non installés"
    echo ""
    echo "Installer avec: xcode-select --install"
    echo ""
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Diagnostic terminé"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
