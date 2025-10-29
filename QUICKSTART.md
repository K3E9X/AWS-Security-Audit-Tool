# 🚀 Quick Start - AWS Security Audit Tool

## Installation Express

### 🐧 Linux
```bash
./run.sh
```

### 🍎 macOS
```bash
./run-macos.sh
```

**⚠️ Erreur avec Python 3.14 ?** Consulte [FIX_PYTHON_314.md](FIX_PYTHON_314.md)

### 🪟 Windows
```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## ⚠️ Problèmes Courants

### macOS: Erreur de compilation numpy/pyarrow
**Symptôme**: `error: metadata-generation-failed` ou `cmake failed` ou `typedef redefinition`

**Solution rapide**:
- Python 3.14: Voir [FIX_PYTHON_314.md](FIX_PYTHON_314.md) ⚡
- Autres versions: Utiliser `./run-macos.sh` ou consulter [README_MACOS.md](README_MACOS.md)

### Linux: Module not found
**Symptôme**: `ModuleNotFoundError: No module named 'streamlit'`

**Solution**: Installer les dépendances avec `pip install -r requirements.txt`

### Tous systèmes: Port déjà utilisé
**Symptôme**: `Address already in use`

**Solution**:
```bash
streamlit run app.py --server.port=8502
```

## 📚 Documentation Complète

- **[README_INSTALLATION.md](README_INSTALLATION.md)** - Guide complet d'installation et tests
- **[README_MACOS.md](README_MACOS.md)** - Guide spécifique macOS avec dépannage
- **[README.md](README.md)** - Documentation du projet (si existant)

## ✅ Vérification Rapide

Après installation, testez:

```bash
python -c "from data.aws_services_questions import ALL_QUESTIONS; print(f'✅ {len(ALL_QUESTIONS)} questions')"
```

Résultat attendu: `✅ 100 questions`

## 🌐 Accès à l'Application

Une fois lancée, ouvrez votre navigateur à:
```
http://localhost:8501
```

## 🛑 Arrêter l'Application

Appuyez sur `Ctrl+C` dans le terminal
