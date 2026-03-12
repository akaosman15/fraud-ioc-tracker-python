"""
CSV Ingest Module — Smart column mapping for BigQuery exports,
AutoThreat reports, and Upstream detector data.
"""
import csv
import io
import os
import json
from datetime import datetime
from typing import List, Dict, Optional, Tuple


# Known column name patterns → IOC type mapping
COLUMN_HINTS = {
    "AM_USER": ["email", "e-mail", "user_email", "emailaddress", "email_address", "contact_email", "useremail", "aftermarket_user", "am_user"],
    "DEALER_ID": ["dealer_id", "dealerid", "dealer", "dealer_number", "dealer_code"],
    "IP": ["ip", "ip_address", "ipaddress", "login_ip", "source_ip", "client_ip", "remote_ip", "ip_addr", "ipaddr"],
    "VIN": ["vin", "vehicle_vin", "vin_number", "vehicleid", "vehicle_id"],
    "SUB_ID": ["hostid", "host_id", "subscription_id", "sub_id", "subscriptionid", "motorcraft_id", "account_id", "accountid", "license_id"],
    "TOOL": ["tool", "tool_name", "toolname", "software", "device_type"],
    "MAC": ["mac", "mac_address", "macaddress", "mac_addr", "hardware_address"],
    "COUNTRY": ["country", "country_code", "region", "geo", "location", "country_name"],
    "USERNAME": ["username", "user_name", "dealer_name", "dealername", "name", "user", "account_name"],
    "TIMESTAMP": ["timestamp", "login_time", "login_timestamp", "created_at", "date", "time", "datetime", "event_time", "session_start"],
    "DEVICE": ["device_id", "deviceid", "vcm_serial", "vcm", "device", "serial", "serial_number", "hardware_id"],
}

# IOC types that become actual IOC records
IOC_MAPPABLE = {"AM_USER", "DEALER_ID", "IP", "VIN", "SUB_ID", "TOOL", "MAC"}

# Internal IP prefixes to ignore during CSV ingest
INTERNAL_IP_PREFIXES = ("10.", "19.", "100.", "172.")

def is_internal_ip(value: str) -> bool:
    """Check if an IP address is internal/private and should be skipped."""
    return any(value.startswith(prefix) for prefix in INTERNAL_IP_PREFIXES)


def guess_column_type(col_name: str) -> str:
    """Guess the IOC type from a column name."""
    normalized = col_name.strip().lower().replace(" ", "_").replace("-", "_")
    for ioc_type, patterns in COLUMN_HINTS.items():
        for pattern in patterns:
            if normalized == pattern or normalized.startswith(pattern) or normalized.endswith(pattern):
                return ioc_type
    return "SKIP"


def read_csv_headers(filepath: str) -> Tuple[List[str], List[List[str]]]:
    """Read CSV and return (headers, preview_rows)."""
    with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
        # Detect delimiter
        sample = f.read(4096)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",\t|;")
        except csv.Error:
            dialect = csv.excel

        reader = csv.reader(f, dialect)
        headers = next(reader, [])
        preview = []
        for i, row in enumerate(reader):
            if i >= 5:
                break
            preview.append(row)
    return headers, preview


def read_csv_all(filepath: str) -> Tuple[List[str], List[List[str]]]:
    """Read entire CSV."""
    with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
        sample = f.read(4096)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",\t|;")
        except csv.Error:
            dialect = csv.excel
        reader = csv.reader(f, dialect)
        headers = next(reader, [])
        rows = list(reader)
    return headers, rows


def ingest_csv(filepath: str, column_mapping: Dict[int, str], source_label: str = "BigQuery") -> Dict:
    """
    Ingest a CSV file using the provided column mapping.

    column_mapping: {col_index: ioc_type_or_meta}
        e.g. {0: "SUB_ID", 1: "EMAIL", 2: "IP", 3: "TIMESTAMP", 4: "USERNAME"}

    Returns: {
        "iocs": [list of new IOC dicts],
        "links": [(ioc_id_1, ioc_id_2, reason), ...],
        "stats": {"rows": N, "iocs_created": N, "links_found": N}
    }
    """
    headers, rows = read_csv_all(filepath)
    now = datetime.now().strftime("%Y-%m-%d")

    # Collect all values per type across all rows
    # Also track which values appear in the same row (for linking)
    ioc_values = {}  # {(type, value): ioc_dict}
    row_groups = []  # list of [(type, value), ...] per row

    for row in rows:
        row_items = []
        row_meta = {"timestamp": "", "username": "", "device": ""}

        for col_idx, ioc_type in column_mapping.items():
            if col_idx >= len(row):
                continue
            val = row[col_idx].strip()
            if not val:
                continue

            if ioc_type == "TIMESTAMP":
                row_meta["timestamp"] = val
            elif ioc_type == "USERNAME":
                row_meta["username"] = val
            elif ioc_type == "DEVICE":
                row_meta["device"] = val
            elif ioc_type in IOC_MAPPABLE:
                # Skip internal IPs
                if ioc_type == "IP" and is_internal_ip(val):
                    continue
                key = (ioc_type, val)
                row_items.append(key)

                if key not in ioc_values:
                    ioc_values[key] = {
                        "id": f"IOC-{abs(hash(key)) % 99999999:08x}",
                        "type": ioc_type,
                        "value": val,
                        "threatLevel": "MEDIUM",
                        "source": source_label,
                        "tags": [],
                        "correlations": [],
                        "notes": "",
                        "status": "active",
                        "firstSeen": row_meta["timestamp"][:10] if row_meta["timestamp"] else now,
                        "lastSeen": row_meta["timestamp"][:10] if row_meta["timestamp"] else now,
                        "hitCount": 0,
                        "action": "Investigate",
                        "blockCount": 0,
                        "ipMeta": None,
                        "linkedTA": None,
                        "subscriptionId": "",
                        "_usernames": set(),
                        "_devices": set(),
                    }
                else:
                    # Update lastSeen if newer
                    ts = row_meta["timestamp"][:10] if row_meta["timestamp"] else now
                    if ts > ioc_values[key]["lastSeen"]:
                        ioc_values[key]["lastSeen"] = ts

                # Track hit count (each row = 1 hit)
                ioc_values[key]["hitCount"] += 1

                # Collect metadata
                if row_meta["username"]:
                    ioc_values[key]["_usernames"].add(row_meta["username"])
                if row_meta["device"]:
                    ioc_values[key]["_devices"].add(row_meta["device"])

        if row_items:
            row_groups.append(row_items)

    # Build correlation links: IOCs that appear in the same row are linked
    links = set()
    for group in row_groups:
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                key_a = group[i]
                key_b = group[j]
                if key_a != key_b and key_a in ioc_values and key_b in ioc_values:
                    id_a = ioc_values[key_a]["id"]
                    id_b = ioc_values[key_b]["id"]
                    if id_a < id_b:
                        links.add((id_a, id_b, f"Same row in {source_label} data"))
                    else:
                        links.add((id_b, id_a, f"Same row in {source_label} data"))

    # Finalize IOCs
    final_iocs = []
    for key, ioc in ioc_values.items():
        # Convert sets to notes
        notes_parts = []
        if ioc["_usernames"]:
            names = ", ".join(sorted(ioc["_usernames"]))
            notes_parts.append(f"Usernames: {names}")
        if ioc["_devices"]:
            devices = ", ".join(sorted(ioc["_devices"]))
            notes_parts.append(f"Devices: {devices}")
        if notes_parts:
            ioc["notes"] = " | ".join(notes_parts)

        # Set subscription ID for SUB_ID type
        if ioc["type"] == "SUB_ID":
            ioc["subscriptionId"] = ioc["value"]

        # Clean up temp fields
        del ioc["_usernames"]
        del ioc["_devices"]
        final_iocs.append(ioc)

    # Apply correlation links to IOC objects
    for id_a, id_b, reason in links:
        for ioc in final_iocs:
            if ioc["id"] == id_a and id_b not in ioc["correlations"]:
                ioc["correlations"].append(id_b)
            if ioc["id"] == id_b and id_a not in ioc["correlations"]:
                ioc["correlations"].append(id_a)

    return {
        "iocs": final_iocs,
        "links": list(links),
        "stats": {
            "rows": len(rows),
            "iocs_created": len(final_iocs),
            "links_found": len(links),
        },
    }


def auto_correlate(iocs: List[Dict]) -> List[Tuple[str, str, str]]:
    """
    Find correlations across ALL existing IOCs based on shared attributes.
    Returns new links: [(ioc_id_1, ioc_id_2, reason), ...]
    """
    new_links = []

    # Index by subscription ID
    sub_index = {}
    for ioc in iocs:
        sub = ioc.get("subscriptionId") or (ioc["value"] if ioc["type"] == "SUB_ID" else "")
        if sub:
            sub_index.setdefault(sub, []).append(ioc["id"])

    # Index by IP (for IP-type IOCs, but also check ipMeta)
    ip_index = {}
    for ioc in iocs:
        if ioc["type"] == "IP":
            ip_index.setdefault(ioc["value"], []).append(ioc["id"])

    # Index by linked threat actor
    ta_index = {}
    for ioc in iocs:
        ta = ioc.get("linkedTA")
        if ta:
            ta_index.setdefault(ta, []).append(ioc["id"])

    # Index by email domain
    domain_index = {}
    for ioc in iocs:
        if ioc["type"] == "EMAIL" and "@" in ioc["value"]:
            domain = ioc["value"].split("@")[1].lower()
            # Skip common providers
            if domain not in ("gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com"):
                domain_index.setdefault(domain, []).append(ioc["id"])

    # Generate links from shared attributes
    for label, index in [
        ("Shared HostID/Subscription", sub_index),
        ("Shared IP address", ip_index),
        ("Same Threat Actor", ta_index),
        ("Same email domain", domain_index),
    ]:
        for key, ids in index.items():
            if len(ids) < 2:
                continue
            for i in range(len(ids)):
                for j in range(i + 1, len(ids)):
                    a, b = (ids[i], ids[j]) if ids[i] < ids[j] else (ids[j], ids[i])
                    # Check if already linked
                    ioc_a = next((x for x in iocs if x["id"] == a), None)
                    if ioc_a and b not in ioc_a.get("correlations", []):
                        new_links.append((a, b, f"{label}: {key}"))

    return new_links


def apply_correlations(iocs: List[Dict], links: List[Tuple[str, str, str]]):
    """Apply correlation links to IOC objects in-place."""
    ioc_map = {i["id"]: i for i in iocs}
    applied = 0
    for id_a, id_b, reason in links:
        a = ioc_map.get(id_a)
        b = ioc_map.get(id_b)
        if a and b:
            if id_b not in a.get("correlations", []):
                a.setdefault("correlations", []).append(id_b)
                applied += 1
            if id_a not in b.get("correlations", []):
                b.setdefault("correlations", []).append(id_a)
                applied += 1
    return applied


# ── Saved mappings ──
def load_saved_mappings(settings_dir: str) -> Dict:
    """Load saved column mappings from disk."""
    path = os.path.join(settings_dir, "csv_mappings.json")
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except:
            pass
    return {}


def save_mapping(settings_dir: str, name: str, mapping: Dict):
    """Save a column mapping for reuse."""
    path = os.path.join(settings_dir, "csv_mappings.json")
    existing = load_saved_mappings(settings_dir)
    existing[name] = mapping
    os.makedirs(settings_dir, exist_ok=True)
    with open(path, "w") as f:
        json.dump(existing, f, indent=2)
