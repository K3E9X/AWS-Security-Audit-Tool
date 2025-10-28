"""
Gestion des sessions d'audit
Sauvegarde et chargement de l'état d'audit
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any


class AuditSession:
    def __init__(self):
        self.session_dir = Path("sessions")
        self.session_dir.mkdir(exist_ok=True)
        self.answers: Dict[str, Dict[str, Any]] = {}
        self.metadata = {
            "created_at": datetime.now().isoformat(),
            "last_modified": datetime.now().isoformat()
        }

    @property
    def total(self) -> int:
        """Nombre total de questions"""
        from data.aws_services_questions import ALL_QUESTIONS
        return len(ALL_QUESTIONS)

    @property
    def answered(self) -> int:
        """Nombre de questions répondues"""
        return len(self.answers)

    @property
    def progress(self) -> int:
        """Pourcentage de progression"""
        if self.total == 0:
            return 0
        return int((self.answered / self.total) * 100)

    def save_answer(self, question_id: str, status: str, risk_level: str, notes: str):
        """Sauvegarder une réponse"""
        self.answers[question_id] = {
            "status": status,
            "risk_level": risk_level,
            "notes": notes,
            "timestamp": datetime.now().isoformat()
        }
        self.metadata["last_modified"] = datetime.now().isoformat()

    def get_answer(self, question_id: str) -> Dict[str, Any]:
        """Récupérer une réponse"""
        return self.answers.get(question_id, {})

    def save(self, filename: str = None):
        """Sauvegarder la session"""
        if filename is None:
            filename = f"audit_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        session_file = self.session_dir / filename

        data = {
            "metadata": self.metadata,
            "answers": self.answers
        }

        with open(session_file, 'w') as f:
            json.dump(data, f, indent=2)

        return session_file

    def load(self, filename: str = None):
        """Charger une session"""
        if filename is None:
            # Charger la session la plus récente
            session_files = list(self.session_dir.glob("audit_session_*.json"))
            if not session_files:
                return

            session_file = max(session_files, key=lambda p: p.stat().st_mtime)
        else:
            session_file = self.session_dir / filename

        if not session_file.exists():
            return

        with open(session_file, 'r') as f:
            data = json.load(f)

        self.metadata = data.get("metadata", {})
        self.answers = data.get("answers", {})

    def get_findings_by_risk(self, risk_level: str):
        """Récupérer les findings par niveau de risque"""
        return {
            qid: answer for qid, answer in self.answers.items()
            if answer.get("risk_level") == risk_level
            and answer.get("status") == "Non-Compliant"
        }

    def get_statistics(self):
        """Statistiques de l'audit"""
        stats = {
            "total": self.total,
            "answered": self.answered,
            "progress": self.progress,
            "compliant": 0,
            "non_compliant": 0,
            "na": 0,
            "to_review": 0,
            "by_risk": {
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0
            }
        }

        for answer in self.answers.values():
            status = answer.get("status", "")
            if status == "Compliant":
                stats["compliant"] += 1
            elif status == "Non-Compliant":
                stats["non_compliant"] += 1
                risk = answer.get("risk_level", "Medium")
                stats["by_risk"][risk] += 1
            elif status == "N/A":
                stats["na"] += 1
            elif status == "To Review":
                stats["to_review"] += 1

        return stats
