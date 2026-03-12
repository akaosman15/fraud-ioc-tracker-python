import json
import os
import shutil
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional
import platform

APP_NAME = "FraudIOCTracker"
VERSION = "3.1.0"


def get_local_data_dir():
    if platform.system() == "Windows":
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
    elif platform.system() == "Darwin":
        base = os.path.join(os.path.expanduser("~"), "Library", "Application Support")
    else:
        base = os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, APP_NAME, "data")


def get_settings_path():
    d = get_local_data_dir()
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "settings.json")


# ── Settings ──
class Settings:
    def __init__(self):
        self.ipinfo_key = ""
        self.abuseipdb_key = ""
        self.shared_data_path = ""
        self.load()

    def load(self):
        p = get_settings_path()
        if os.path.exists(p):
            try:
                with open(p, "r") as f:
                    d = json.load(f)
                self.ipinfo_key = d.get("ipinfo_key", "")
                self.abuseipdb_key = d.get("abuseipdb_key", "")
                self.shared_data_path = d.get("shared_data_path", "")
            except:
                pass

    def save(self):
        p = get_settings_path()
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            json.dump({
                "ipinfo_key": self.ipinfo_key,
                "abuseipdb_key": self.abuseipdb_key,
                "shared_data_path": self.shared_data_path,
            }, f, indent=2)

    def get_data_dir(self):
        if self.shared_data_path and os.path.isdir(self.shared_data_path):
            return self.shared_data_path
        return get_local_data_dir()

    def get_data_file(self):
        return os.path.join(self.get_data_dir(), "ioc-data.json")


# ── Data Store ──
class DataStore:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.iocs = []
        self.actors = []

    def load(self):
        p = self.settings.get_data_file()
        if os.path.exists(p):
            try:
                with open(p, "r") as f:
                    d = json.load(f)
                self.iocs = d.get("iocs", [])
                self.actors = d.get("actors", [])
                return True
            except Exception as e:
                print(f"Load error: {e}")
        return False

    def save(self):
        p = self.settings.get_data_file()
        backup_dir = os.path.join(self.settings.get_data_dir(), "backups")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        os.makedirs(backup_dir, exist_ok=True)

        # Backup
        if os.path.exists(p):
            backups = sorted([f for f in os.listdir(backup_dir) if f.endswith(".json")], reverse=True)
            while len(backups) >= 10:
                os.remove(os.path.join(backup_dir, backups.pop()))
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            shutil.copy2(p, os.path.join(backup_dir, f"backup-{stamp}.json"))

        with open(p, "w") as f:
            json.dump({
                "_meta": {"tool": "Fraud IOC Tracker", "version": VERSION, "savedAt": datetime.now().isoformat()},
                "iocs": self.iocs,
                "actors": self.actors,
            }, f, indent=2)

    def export_to_file(self, filepath):
        with open(filepath, "w") as f:
            json.dump({
                "_meta": {"tool": "Fraud IOC Tracker", "version": VERSION, "exportedAt": datetime.now().isoformat()},
                "iocs": self.iocs,
                "actors": self.actors,
            }, f, indent=2)

    def import_from_file(self, filepath, merge=False):
        with open(filepath, "r") as f:
            d = json.load(f)
        new_iocs = d.get("iocs", d if isinstance(d, list) else [])
        new_actors = d.get("actors", [])

        if merge:
            existing_ioc_ids = {i["id"] for i in self.iocs}
            existing_ta_ids = {a["id"] for a in self.actors}
            added_iocs = [i for i in new_iocs if i.get("id") and i["id"] not in existing_ioc_ids]
            added_actors = [a for a in new_actors if a.get("id") and a["id"] not in existing_ta_ids]
            self.iocs.extend(added_iocs)
            self.actors.extend(added_actors)
            return len(added_iocs), len(added_actors)
        else:
            self.iocs = [i for i in new_iocs if i.get("id") and i.get("type") and i.get("value")]
            self.actors = new_actors
            return len(self.iocs), len(self.actors)

    def add_ioc(self, ioc: dict):
        self.iocs.insert(0, ioc)
        self.save()

    def add_actor(self, actor: dict):
        self.actors.insert(0, actor)
        self.save()

    def update_ioc(self, ioc_id, key, value):
        for i in self.iocs:
            if i["id"] == ioc_id:
                i[key] = value
                self.save()
                return

    def get_ioc(self, ioc_id):
        for i in self.iocs:
            if i["id"] == ioc_id:
                return i
        return None

    def get_actor(self, actor_id):
        for a in self.actors:
            if a["id"] == actor_id:
                return a
        return None

    def get_linked_iocs(self, actor_id):
        return [i for i in self.iocs if i.get("linkedTA") == actor_id]

    def get_correlated(self, ioc):
        return [i for i in self.iocs if i["id"] in ioc.get("correlations", [])]

    def get_same_subscription(self, ioc):
        sub = ioc.get("subscriptionId")
        if not sub:
            return []
        return [i for i in self.iocs if i["id"] != ioc["id"] and i.get("subscriptionId") == sub]
