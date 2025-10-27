#!/bin/bash

# Script pour démarrer l'API AWS Security Audit

echo "🚀 Démarrage de l'API AWS Security Audit..."

# Tuer les processus existants
pkill -f "python main.py" 2>/dev/null
pkill -f "uvicorn" 2>/dev/null
sleep 2

# Démarrer le serveur
python main.py &
SERVER_PID=$!

echo "✅ Serveur démarré avec PID: $SERVER_PID"
sleep 3

# Vérifier que le serveur répond
if curl -s http://127.0.0.1:8000/health > /dev/null 2>&1; then
    echo "✅ API accessible sur http://127.0.0.1:8000"
    echo ""
    echo "📚 Documentation interactive: http://127.0.0.1:8000/docs"
    echo ""
    echo "Pour tester depuis ce terminal:"
    echo "  curl http://127.0.0.1:8000/health"
    echo "  curl http://127.0.0.1:8000/questions?limit=5"
    echo ""
    echo "Pour arrêter le serveur: kill $SERVER_PID"
else
    echo "❌ Erreur: Le serveur ne répond pas"
    cat /tmp/api_server.log 2>/dev/null || echo "Pas de logs disponibles"
fi
