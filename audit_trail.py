"""
Audit Trail — Logs all user actions with timestamps.
"""
import json
import os
from datetime import datetime
from typing import List, Dict


class AuditTrail:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.log_file = os.path.join(data_dir, "audit-log.json")
        self.entries = []
        self.load()

    def load(self):
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, "r") as f:
                    self.entries = json.load(f)
            except:
                self.entries = []

    def save(self):
        os.makedirs(self.data_dir, exist_ok=True)
        with open(self.log_file, "w") as f:
            json.dump(self.entries, f, indent=2)

    def log(self, action: str, entity_type: str, entity_id: str, details: str = "", user: str = "analyst"):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "entityType": entity_type,
            "entityId": entity_id,
            "details": details,
            "user": user,
        }
        self.entries.insert(0, entry)
        # Keep last 5000 entries
        if len(self.entries) > 5000:
            self.entries = self.entries[:5000]
        self.save()

    def get_recent(self, count: int = 50) -> List[Dict]:
        return self.entries[:count]

    def get_for_entity(self, entity_id: str) -> List[Dict]:
        return [e for e in self.entries if e["entityId"] == entity_id]

    def get_actions_this_month(self) -> List[Dict]:
        now = datetime.now()
        prefix = now.strftime("%Y-%m")
        return [e for e in self.entries if e["timestamp"].startswith(prefix)]

    def get_actions_by_type(self) -> Dict[str, int]:
        counts = {}
        for e in self.entries:
            a = e["action"]
            counts[a] = counts.get(a, 0) + 1
        return counts

    def export_csv(self, filepath: str):
        import csv
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Timestamp", "Action", "Entity Type", "Entity ID", "Details", "User"])
            for e in self.entries:
                w.writerow([e["timestamp"], e["action"], e["entityType"], e["entityId"], e["details"], e["user"]])
