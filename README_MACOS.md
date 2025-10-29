# 🍎 Installation sur macOS - AWS Security Audit Tool

## Guide Complet pour macOS

Ce guide vous aidera à installer et lancer l'application sur macOS, en évitant les erreurs de compilation courantes.

## 🚨 Problèmes Courants sur macOS

### Problème 1: Erreurs de compilation numpy/pandas
L'erreur avec numpy est un problème courant sur macOS lié à:
- Versions anciennes de numpy/pandas qui ne compilent pas avec les nouveaux outils Xcode
- Incompatibilités entre les versions de Python et les bibliothèques C

### Problème 2: Python 3.14+ et pyarrow
**Symptôme**: `error: command 'cmake' failed: No such file or directory`

Si vous utilisez **Python 3.14**, pyarrow n'a pas encore de wheels précompilés. Vous avez 3 options:

1. **RECOMMANDÉ**: Utiliser Python 3.11 ou 3.12 (voir section ci-dessous)
2. Installer cmake: `brew install cmake apache-arrow`
3. Utiliser conda qui a des builds préconstruits

## 🔍 Diagnostic Rapide

Avant de commencer, lance le script de diagnostic:

```bash
./diagnose-macos.sh
```

Ce script va:
- ✅ Détecter votre version de Python
- ✅ Identifier les problèmes potentiels
- ✅ Proposer les solutions adaptées à votre configuration

## ✅ Solution Recommandée (Méthode Rapide)

### Prérequis

1. **Python 3.9 à 3.13** (recommandé: **3.11** ou **3.12**)
   ```bash
   python3 --version
   ```

   ⚠️ **IMPORTANT**: Python 3.14+ peut causer des problèmes car certains packages (pyarrow) n'ont pas encore de wheels précompilés. Si vous avez Python 3.14, suivez les instructions spéciales ci-dessous.

2. **Homebrew** (optionnel mais recommandé)
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

### Installation en 1 Commande

```bash
./run-macos.sh
```

Ce script va automatiquement:
- ✅ Vérifier votre version de Python
- ✅ Créer un environnement virtuel
- ✅ Installer les bonnes versions des dépendances
- ✅ Lancer l'application

## 🐍 Cas Spécial: Python 3.14+

Si vous avez Python 3.14, vous **devez** utiliser une version plus ancienne de Python pour éviter les problèmes de compilation.

### Solution 1: Installer Python 3.11 via Homebrew (Recommandé)

```bash
# Installer Python 3.11
brew install python@3.11

# Créer l'environnement virtuel avec Python 3.11
python3.11 -m venv venv

# Activer l'environnement
source venv/bin/activate

# Vérifier la version (devrait montrer 3.11.x)
python --version

# Installer les dépendances
pip install --upgrade pip setuptools wheel
pip install -r requirements-macos.txt

# Lancer l'application
streamlit run app.py
```

### Solution 2: Installer cmake pour compiler pyarrow

Si vous voulez absolument utiliser Python 3.14:

```bash
# Installer les outils de compilation
brew install cmake apache-arrow

# Créer l'environnement
python3 -m venv venv
source venv/bin/activate

# Installer (peut prendre du temps, compilation en cours)
pip install --upgrade pip setuptools wheel
pip install -r requirements-macos.txt

# Lancer
streamlit run app.py
```

### Solution 3: Utiliser pyenv pour gérer les versions Python

```bash
# Installer pyenv
brew install pyenv

# Installer Python 3.11
pyenv install 3.11.7

# Utiliser cette version pour le projet
pyenv local 3.11.7

# Créer l'environnement
python -m venv venv
source venv/bin/activate

# Installer
pip install -r requirements-macos.txt
```

## 📝 Installation Manuelle (Si le script échoue)

### Méthode 1: Environnement Virtuel (Recommandé)

```bash
# 1. Créer un environnement virtuel
python3 -m venv venv

# 2. Activer l'environnement
source venv/bin/activate

# 3. Mettre à jour pip et les outils
pip install --upgrade pip setuptools wheel

# 4. Installer numpy et pandas avec wheels précompilés
pip install --only-binary :all: numpy pandas

# 5. Installer le reste des dépendances
pip install -r requirements-macos.txt

# 6. Lancer l'application
streamlit run app.py
```

### Méthode 2: Avec Homebrew

Si vous avez des erreurs de compilation, utilisez Homebrew:

```bash
# Installer les dépendances système
brew install python@3.11
brew install numpy

# Créer l'environnement virtuel avec la version Homebrew
python3.11 -m venv venv
source venv/bin/activate

# Installer les dépendances Python
pip install -r requirements-macos.txt

# Lancer l'application
streamlit run app.py
```

### Méthode 3: Avec Conda (Alternative)

Si vous préférez Anaconda/Miniconda:

```bash
# Créer un environnement conda
conda create -n aws-audit python=3.11 numpy pandas

# Activer l'environnement
conda activate aws-audit

# Installer les autres dépendances
pip install -r requirements-macos.txt

# Lancer l'application
streamlit run app.py
```

## 🐛 Dépannage Avancé

### Erreur: "numpy compilation failed"

**Cause**: Les Xcode Command Line Tools ne sont pas installés ou sont obsolètes.

**Solution**:
```bash
# Installer/Mettre à jour Xcode Command Line Tools
xcode-select --install

# Si déjà installé, réinitialiser
sudo rm -rf /Library/Developer/CommandLineTools
xcode-select --install

# Accepter la licence
sudo xcodebuild -license accept
```

### Erreur: "clang: error: unsupported option"

**Cause**: Conflit entre plusieurs versions de compilateurs.

**Solution**:
```bash
# Nettoyer le cache pip
pip cache purge

# Réinstaller avec les wheels précompilés uniquement
pip install --only-binary :all: --force-reinstall numpy pandas
```

### Erreur: "ModuleNotFoundError: No module named 'numpy'"

**Cause**: L'environnement virtuel n'est pas activé ou numpy n'est pas installé.

**Solution**:
```bash
# Vérifier que l'environnement est activé
which python  # Doit montrer le chemin vers venv/bin/python

# Réactiver si nécessaire
source venv/bin/activate

# Réinstaller numpy
pip install --upgrade numpy
```

### Erreur: Architecture ARM64 vs x86_64 (Mac M1/M2/M3)

**Pour Apple Silicon (M1/M2/M3)**:

```bash
# Utiliser l'architecture native ARM64
arch -arm64 python3 -m venv venv
source venv/bin/activate

# Installer avec wheels ARM64
pip install --upgrade pip
pip install --only-binary :all: numpy pandas
pip install -r requirements-macos.txt
```

**Pour Intel x86_64**:

```bash
# Configuration standard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-macos.txt
```

## 🎯 Vérification de l'Installation

Après l'installation, vérifiez que tout fonctionne:

```bash
# Test 1: Import des modules
python3 -c "import numpy, pandas, streamlit; print('✅ Tous les modules importés')"

# Test 2: Vérification de la base de données
python3 -c "from data.aws_services_questions import ALL_QUESTIONS; print(f'✅ {len(ALL_QUESTIONS)} questions chargées')"

# Test 3: Lancement de l'application
streamlit run app.py
```

## 📊 Versions Testées sur macOS

| macOS Version | Python | Status |
|--------------|--------|--------|
| Ventura 13.x | 3.11   | ✅     |
| Sonoma 14.x  | 3.11   | ✅     |
| Sequoia 15.x | 3.11   | ✅     |

## 🔧 Comparaison des Fichiers Requirements

- **`requirements.txt`**: Version mise à jour, compatible Linux et nouvelles versions
- **`requirements-macos.txt`**: Version optimisée pour macOS avec wheels précompilés

## 🚀 Lancement Rapide

Une fois installé:

```bash
# Méthode 1: Utiliser le script
./run-macos.sh

# Méthode 2: Manuel
source venv/bin/activate
streamlit run app.py
```

L'application s'ouvrira automatiquement dans votre navigateur sur `http://localhost:8501`

## 💡 Conseils de Performance pour macOS

1. **Utiliser un environnement virtuel**: Évite les conflits avec les packages système
2. **Installer via Homebrew**: Plus stable pour les packages scientifiques
3. **Mettre à jour régulièrement**: `pip install --upgrade pip setuptools wheel`
4. **Vider le cache si problème**: `pip cache purge`

## 📞 Support Supplémentaire

Si vous rencontrez toujours des problèmes après avoir suivi ce guide:

1. Vérifiez votre version de macOS: `sw_vers`
2. Vérifiez votre version de Python: `python3 --version`
3. Vérifiez les Xcode tools: `xcode-select -p`
4. Créez une issue GitHub avec les détails de votre erreur

## ✅ Checklist d'Installation

- [ ] Python 3.9+ installé
- [ ] Xcode Command Line Tools installés
- [ ] Environnement virtuel créé
- [ ] Dépendances installées sans erreur
- [ ] Application démarre sur localhost:8501
- [ ] 100 questions chargées avec succès

---

**Note**: Ce guide est spécifique aux problèmes de compilation sur macOS. Pour Linux, utilisez le `README_INSTALLATION.md` standard.
