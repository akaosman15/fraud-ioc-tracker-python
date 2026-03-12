import requests
from typing import Optional


def enrich_ipinfo(ip: str, api_key: str) -> dict:
    if not api_key:
        return {"success": False, "error": "No IPinfo API key. Go to Settings."}
    try:
        r = requests.get(f"https://ipinfo.io/{ip}?token={api_key}", timeout=10)
        if r.status_code != 200:
            return {"success": False, "error": f"HTTP {r.status_code}"}
        d = r.json()
        result = {
            "provider": d.get("org", ""),
            "asn": (d.get("org", "").split(" ")[0] if d.get("org") else ""),
            "country": d.get("country", ""),
            "hosting": False,
            "ipType": "",
        }
        if d.get("hosting"):
            result["hosting"] = True
        privacy = d.get("privacy", {})
        if privacy.get("vpn"):
            result["ipType"] = "VPN"
        elif privacy.get("proxy"):
            result["ipType"] = "Proxy"
        elif privacy.get("tor"):
            result["ipType"] = "Tor Exit"
        elif privacy.get("hosting"):
            result["ipType"] = "Hosting"
        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


def enrich_abuseipdb(ip: str, api_key: str) -> dict:
    if not api_key:
        return {"success": False, "error": "No AbuseIPDB API key. Go to Settings."}
    try:
        r = requests.get(
            f"https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=10,
        )
        if r.status_code != 200:
            return {"success": False, "error": f"HTTP {r.status_code}"}
        d = r.json().get("data", r.json())
        result = {
            "abuseScore": d.get("abuseConfidenceScore", 0),
            "country": d.get("countryCode", ""),
            "provider": d.get("isp", ""),
            "asn": (d.get("isp", "").split(" ")[0] if d.get("isp") else ""),
            "ipType": "",
        }
        usage = d.get("usageType", "")
        if "Data Center" in usage:
            result["ipType"] = "Datacenter"
        elif "ISP" in usage:
            result["ipType"] = "Residential"
        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}
