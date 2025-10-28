# Démarrage avec Docker

## Méthode 1 : Docker Compose (RECOMMANDÉ)

### Démarrer l'API

```bash
docker-compose up
```

L'API sera accessible sur : **http://localhost:8000**

Documentation interactive : **http://localhost:8000/docs**

### Arrêter l'API

```bash
# Arrêter sans supprimer
docker-compose stop

# Arrêter et supprimer les conteneurs
docker-compose down
```

### Rebuild après modifications

```bash
docker-compose up --build
```

## Méthode 2 : Docker classique

### Build de l'image

```bash
docker build -t aws-security-audit-api .
```

### Lancer le conteneur

```bash
docker run -d \
  --name aws-audit-api \
  -p 8000:8000 \
  -v ${PWD}:/app \
  aws-security-audit-api
```

### Voir les logs

```bash
docker logs -f aws-audit-api
```

### Arrêter le conteneur

```bash
docker stop aws-audit-api
docker rm aws-audit-api
```

## Méthode 3 : Développement avec port mapping

Si vous voulez entrer dans le conteneur et lancer manuellement :

### Windows PowerShell

```powershell
docker run -it -p 8000:8000 -v ${PWD}:/app -w /app python:3.11-slim bash
```

### Puis dans le conteneur

```bash
pip install -r requirements.txt
python main.py
```

## Tester l'API

### Depuis votre navigateur Windows

- Page d'accueil : http://localhost:8000
- Documentation : http://localhost:8000/docs
- Health check : http://localhost:8000/health

### Depuis PowerShell Windows

```powershell
# Test simple
curl http://localhost:8000/health

# Avec formatting JSON (si vous avez Python sur Windows)
curl http://localhost:8000/health | python -m json.tool
```

### Depuis le conteneur

```bash
curl http://localhost:8000/health
python example_usage.py
```

## Ports utilisés

- **8000** : API REST

Si le port 8000 est déjà utilisé sur Windows, modifiez dans `docker-compose.yml` :

```yaml
ports:
  - "8080:8000"  # Utilisera le port 8080 sur Windows
```

Puis accédez à http://localhost:8080

## Troubleshooting

### Le port 8000 est déjà utilisé

```bash
# Voir ce qui utilise le port 8000
netstat -ano | findstr :8000

# Ou utiliser un autre port
docker run -p 8080:8000 ...
```

### Permission denied

Sur Windows, assurez-vous que Docker Desktop est lancé et que les volumes partagés sont configurés.

### Cannot connect to Docker daemon

Lancez Docker Desktop depuis Windows.
