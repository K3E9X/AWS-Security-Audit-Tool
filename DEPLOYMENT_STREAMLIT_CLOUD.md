# 🚀 Déploiement sur Streamlit Cloud

## Guide Complet de Déploiement

Ce guide explique comment déployer l'AWS Security Audit Tool sur Streamlit Cloud.

## ⚠️ Problème Courant: Site ne Charge Pas

Si votre site ne se lance pas sur Streamlit Cloud, c'est probablement dû à:

1. **Versions de packages incompatibles** - Streamlit Cloud a des versions spécifiques
2. **Fichiers de configuration manquants** - `.streamlit/config.toml`
3. **Requirements incorrects** - Besoin de versions exactes

## ✅ Solution: Configuration Correcte

### Étape 1: Vérifier les Fichiers Requis

Assurez-vous que ces fichiers existent à la racine du projet:

```
Machine71/
├── app.py                      # ✅ Application principale
├── requirements.txt            # ✅ Dépendances (versions EXACTES)
├── packages.txt                # ✅ Dépendances système (optionnel)
├── .streamlit/
│   ├── config.toml            # ✅ Configuration Streamlit
│   └── secrets.toml           # ✅ Template secrets
├── data/
│   └── aws_services_questions.py
└── utils/
    ├── session.py
    ├── export.py
    └── diagram.py
```

### Étape 2: Utiliser le Bon requirements.txt

**IMPORTANT**: Streamlit Cloud nécessite des versions EXACTES, pas `>=`

Le `requirements.txt` actuel utilise maintenant des versions exactes compatibles:

```txt
streamlit==1.32.2
plotly==5.20.0
pandas==2.2.0
numpy==1.26.4
pydantic==2.6.3
python-dotenv==1.0.1
markdown==3.5.2
reportlab==4.1.0
Pillow==10.2.0
streamlit-drawable-canvas==0.9.3
streamlit-agraph==0.0.45
```

### Étape 3: Configuration Streamlit Cloud

#### A. Paramètres de l'App

Dans Streamlit Cloud:

1. **Repository**: `K3E9X/Machine71`
2. **Branch**: `main` (ou votre branche de production)
3. **Main file path**: `app.py`
4. **Python version**: **3.11** (RECOMMANDÉ) ou 3.10

⚠️ **NE PAS utiliser Python 3.14** sur Streamlit Cloud - utiliser 3.11 ou 3.12

#### B. Paramètres Avancés (Advanced settings)

- **Python version**: `3.11`
- Pas de secrets nécessaires pour cette app (sauf si vous ajoutez des API keys)

### Étape 4: Vérifier les Logs

Si l'app ne charge toujours pas:

1. Aller sur Streamlit Cloud
2. Cliquer sur votre app
3. Cliquer sur "Manage app" → "Logs"
4. Chercher les erreurs dans les logs

#### Erreurs Courantes et Solutions

| Erreur | Cause | Solution |
|--------|-------|----------|
| `ModuleNotFoundError` | Package manquant | Vérifier requirements.txt |
| `Version conflict` | Versions incompatibles | Utiliser versions exactes |
| `Import error` | Structure fichiers | Vérifier data/ et utils/ existent |
| `Timeout` | Build trop long | Réduire dépendances ou utiliser packages.txt |

### Étape 5: Forcer un Rebuild

Si rien ne fonctionne:

1. Streamlit Cloud → Votre app
2. "Manage app" → "Reboot app"
3. Ou "⋮" menu → "Delete app" puis redéployer

## 🔧 Dépannage Spécifique

### Problème: "App is starting..."  mais ne charge jamais

**Solution**:
```bash
# 1. Localement, tester que l'app fonctionne
streamlit run app.py

# 2. Vérifier requirements.txt utilise versions exactes (==)
cat requirements.txt

# 3. S'assurer que .streamlit/config.toml existe
ls -la .streamlit/

# 4. Commit et push les changements
git add requirements.txt .streamlit/
git commit -m "Fix: Streamlit Cloud deployment"
git push
```

### Problème: Erreur d'import de modules

**Vérifier la structure**:
```bash
# Ces dossiers/fichiers doivent exister:
ls -la data/__init__.py
ls -la utils/__init__.py
ls -la data/aws_services_questions.py
ls -la utils/session.py
ls -la utils/export.py
ls -la utils/diagram.py
```

Si un `__init__.py` manque:
```bash
touch data/__init__.py
touch utils/__init__.py
```

### Problème: Version Python

Streamlit Cloud supporte:
- ✅ Python 3.9
- ✅ Python 3.10
- ✅ Python 3.11 (RECOMMANDÉ)
- ✅ Python 3.12
- ❌ Python 3.14 (trop récent, pas supporté)

**Solution**: Dans Streamlit Cloud settings, choisir **Python 3.11**

## 📋 Checklist de Déploiement

Avant de déployer, vérifier:

- [ ] `app.py` est à la racine
- [ ] `requirements.txt` utilise versions exactes (==)
- [ ] `.streamlit/config.toml` existe
- [ ] `data/__init__.py` existe
- [ ] `utils/__init__.py` existe
- [ ] Tous les modules s'importent correctement en local
- [ ] Python 3.11 sélectionné sur Streamlit Cloud
- [ ] Branch correcte sélectionnée

## 🎯 Configuration Recommandée Streamlit Cloud

```
Repository: K3E9X/Machine71
Branch: main
Main file: app.py
Python version: 3.11
```

## 🔄 Processus de Mise à Jour

Quand vous faites des changements:

1. **Tester localement**:
   ```bash
   streamlit run app.py
   ```

2. **Commit et push**:
   ```bash
   git add .
   git commit -m "Update: description"
   git push
   ```

3. **Streamlit Cloud va auto-redéployer** (si auto-deploy activé)

   Ou manuellement: "Manage app" → "Reboot app"

## 📊 Monitoring

Une fois déployé avec succès:

- **URL**: https://aws-security-audit-tool.streamlit.app
- **Status**: Vérifier "Manage app" pour voir état
- **Logs**: Accessible via "Logs" pour debugging
- **Analytics**: Streamlit Cloud fournit stats d'utilisation

## 🆘 Besoin d'Aide?

Si problèmes persistent:

1. **Vérifier les logs Streamlit Cloud**
2. **Tester en local** avec `streamlit run app.py`
3. **Comparer avec** `requirements-cloud.txt` (versions testées)
4. **Créer une issue** sur GitHub avec les logs d'erreur

## ✅ Vérification Finale

Une fois déployé, tester:

1. ✅ Le site charge dans les 30 secondes
2. ✅ Le dashboard s'affiche correctement
3. ✅ La navigation fonctionne (sidebar)
4. ✅ Les 100 questions sont accessibles
5. ✅ Les filtres fonctionnent
6. ✅ L'export fonctionne

## 📝 Notes Importantes

- **Première installation**: Peut prendre 2-5 minutes
- **Redémarrage**: ~30 secondes
- **Inactivité**: App s'endort après 7 jours sans visite (Streamlit Cloud gratuit)
- **Limites**: 1GB RAM sur plan gratuit

---

## 🔗 Ressources

- [Streamlit Cloud Docs](https://docs.streamlit.io/streamlit-community-cloud)
- [Deployment Guide](https://docs.streamlit.io/streamlit-community-cloud/deploy-your-app)
- [Troubleshooting](https://docs.streamlit.io/knowledge-base/deploy)
