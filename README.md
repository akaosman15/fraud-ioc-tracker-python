# ⚡ Fraud IOC Tracker (Python)

**Desktop threat intelligence tool for tracking fraud-related Indicators of Compromise.**

Built with Python + PyQt6. Single executable, no browser or Node.js needed.

![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

- **6 IOC Types**: Email, IP Address, VIN, Country, Tool Name, Subscription ID
- **Threat Actor Profiles**: Linked to IOCs, with AutoThreat/Upstream source reports and recommended tools to acquire
- **IP Enrichment**: One-click lookup via IPinfo and AbuseIPDB
- **Team Sync**: Point to a shared OneDrive/SharePoint folder — data syncs across machines
- **Auto-Save**: Local JSON with rolling backups
- **Export / Import / Merge**: Portable JSON files

## Quick Start

### Run from Source

```bash
pip install -r requirements.txt
python app.py
```

### Build Executable

**Windows:**
```bash
build-windows.bat
```

**Mac:**
```bash
chmod +x build-mac.sh
./build-mac.sh
```

Output: `dist/Fraud IOC Tracker.exe` (Windows) or `dist/Fraud IOC Tracker` (Mac)

## Project Structure

```
fraud-ioc-tracker-py/
├── app.py              # Main application (PyQt6 GUI)
├── data_store.py       # Data models, JSON storage, backup
├── enrichment.py       # IPinfo + AbuseIPDB integration
├── requirements.txt    # Dependencies
├── build-windows.bat   # Windows build script
└── build-mac.sh        # Mac build script
```

## License

MIT
