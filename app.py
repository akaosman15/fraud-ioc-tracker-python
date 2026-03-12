import sys, os, uuid
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QTableWidget, QTableWidgetItem, QHeaderView, QPushButton, QLineEdit,
    QComboBox, QLabel, QTextEdit, QDialog, QFileDialog,
    QTabWidget, QFrame, QScrollArea, QMessageBox, QAbstractItemView,
    QGroupBox, QCheckBox, QDoubleSpinBox,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont, QPalette

from data_store import Settings, DataStore, VERSION
from enrichment import enrich_ipinfo, enrich_abuseipdb
from csv_ingest import (read_csv_headers, guess_column_type, ingest_csv,
    auto_correlate, apply_correlations, save_mapping, load_saved_mappings, IOC_MAPPABLE)

# ── Constants ──
THREAT_LEVELS = {
    "CRITICAL": ("#ff1744", "#3d0a0a"), "HIGH": ("#ff9100", "#3d2a00"),
    "MEDIUM": ("#ffea00", "#3d3a00"), "LOW": ("#69f0ae", "#0a3d1f"),
}
IOC_TYPES = {
    "AM_USER": ("👤 Aftermarket User", "#82b1ff"),
    "DEALER_ID": ("🏢 Dealer ID", "#80cbc4"),
    "IP": ("⬡ IP Address", "#b388ff"),
    "VIN": ("⛟ VIN", "#ff80ab"),
    "SUB_ID": ("🔑 Subscription ID", "#ce93d8"),
    "TOOL": ("⚙ Tool", "#ffd180"),
    "MAC": ("📡 MAC Address", "#a5d6a7"),
}
IP_TYPES = ["Residential", "Datacenter", "Proxy", "VPN", "Tor Exit", "Mobile", "Hosting", "CDN"]
ACTIONS = ["Suspended", "Monitor", "Investigate", "Escalate", "Quarantine", "Compromised List", "Purchase Tool"]
SOURCES = ["AutoThreat", "Upstream Detector", "Manual"]

DARK_STYLE = """
QMainWindow, QWidget { background-color: #0d0f13; color: #e8eaed; }
QTabWidget::pane { border: 1px solid #2a2d35; background: #0d0f13; }
QTabBar::tab { background: #12141a; color: #6b7280; padding: 10px 20px; border: none; border-bottom: 2px solid transparent; font-weight: 600; font-size: 13px; }
QTabBar::tab:selected { color: #ff1744; border-bottom: 2px solid #ff1744; }
QTabBar::tab:hover { color: #9ca3af; }
QTableWidget { background-color: #0d0f13; gridline-color: #14161c; border: none; selection-background-color: rgba(255,23,68,0.08); }
QTableWidget::item { padding: 8px; border-bottom: 1px solid #14161c; }
QHeaderView::section { background-color: #0d0f13; color: #6b7280; border: none; border-bottom: 1px solid #1e2028; padding: 8px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
QLineEdit, QComboBox, QTextEdit { background-color: #12141a; border: 1px solid #2a2d35; border-radius: 6px; padding: 6px 10px; color: #e8eaed; font-size: 13px; }
QLineEdit:focus, QTextEdit:focus { border-color: #ff1744; }
QComboBox { padding-right: 20px; }
QComboBox::drop-down { border: none; }
QComboBox QAbstractItemView { background-color: #1a1d23; color: #e8eaed; selection-background-color: #2a2d35; border: 1px solid #2a2d35; }
QPushButton { border-radius: 6px; padding: 7px 16px; font-size: 12px; font-weight: 600; }
QPushButton#btnRed { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #ff1744,stop:1 #d50000); color: white; border: none; }
QPushButton#btnDark { background-color: #2a2d35; color: #9ca3af; border: 1px solid #2a2d35; }
QPushButton#btnGreen { background-color: #2a2d35; color: #69f0ae; border: 1px solid rgba(105,240,174,0.3); }
QPushButton#btnBlue { background-color: #2a2d35; color: #82b1ff; border: 1px solid rgba(130,177,255,0.3); }
QPushButton#btnOutline { background: transparent; color: #ff1744; border: 1px solid #ff1744; }
QLabel { color: #e8eaed; }
QScrollArea { border: none; background: transparent; }
QGroupBox { border: 1px solid #2a2d35; border-radius: 8px; margin-top: 10px; padding-top: 16px; background: #12141a; }
QGroupBox::title { color: #b388ff; font-size: 11px; font-weight: 700; text-transform: uppercase; subcontrol-origin: margin; left: 14px; padding: 0 6px; }
QDialog { background-color: #1a1d23; color: #e8eaed; }
QScrollBar:vertical { background: #12141a; width: 8px; }
QScrollBar::handle:vertical { background: #2a2d35; border-radius: 4px; min-height: 20px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QDoubleSpinBox { background-color: #12141a; border: 1px solid #2a2d35; border-radius: 6px; padding: 6px; color: #e8eaed; font-size: 13px; }
"""

MONO = QFont("Consolas", 11)
MONO.setStyleHint(QFont.StyleHint.Monospace)

def gen_id(prefix="IOC"):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"

# ══════════════════════════════════════
#  STAT CARD
# ══════════════════════════════════════
class StatCard(QFrame):
    def __init__(self, label, value="0", color="#82b1ff"):
        super().__init__()
        self.setStyleSheet("background:#12141a;border:1px solid #1e2028;border-radius:8px;padding:10px;")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(2)
        lbl = QLabel(label)
        lbl.setStyleSheet("color:#6b7280;font-size:9px;text-transform:uppercase;letter-spacing:1px;font-weight:700;border:none;")
        self.val_label = QLabel(str(value))
        self.val_label.setStyleSheet(f"color:{color};font-size:20px;font-weight:800;font-family:'Consolas',monospace;border:none;")
        layout.addWidget(lbl)
        layout.addWidget(self.val_label)

    def set_value(self, v, color=None):
        self.val_label.setText(str(v))
        if color:
            self.val_label.setStyleSheet(f"color:{color};font-size:20px;font-weight:800;font-family:'Consolas',monospace;border:none;")


def _field(label, widget):
    c = QWidget()
    l = QVBoxLayout(c)
    l.setContentsMargins(0, 0, 0, 0)
    l.setSpacing(4)
    lb = QLabel(label)
    lb.setStyleSheet("color:#9ca3af;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px;")
    l.addWidget(lb)
    l.addWidget(widget)
    return c


# ══════════════════════════════════════
#  ADD IOC DIALOG
# ══════════════════════════════════════
class AddIOCDialog(QDialog):
    def __init__(self, parent, actors, existing_iocs):
        super().__init__(parent)
        self.setWindowTitle("Add Indicator of Compromise")
        self.setMinimumWidth(560)
        self.setStyleSheet("QDialog{background:#1a1d23;}")
        self.actors = actors
        self.existing_iocs = existing_iocs
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # Custom ID
        self.custom_id_edit = QLineEdit()
        self.custom_id_edit.setPlaceholderText("Auto-generated if blank. Enter AutoThreat/Upstream ID here.")
        layout.addWidget(_field("IOC ID (optional — for AutoThreat/Upstream IDs)", self.custom_id_edit))

        # Type + Threat
        row1 = QHBoxLayout()
        self.type_combo = QComboBox()
        for k, (label, _) in IOC_TYPES.items():
            self.type_combo.addItem(label, k)
        self.type_combo.currentIndexChanged.connect(self._on_type_change)
        self.threat_combo = QComboBox()
        for k in THREAT_LEVELS:
            self.threat_combo.addItem(k)
        self.threat_combo.setCurrentText("HIGH")
        row1.addWidget(_field("IOC Type", self.type_combo))
        row1.addWidget(_field("Threat Level", self.threat_combo))
        layout.addLayout(row1)

        # Value
        self.value_edit = QLineEdit()
        self.value_edit.setPlaceholderText("Enter value...")
        layout.addWidget(_field("Value", self.value_edit))

        # Country (for AM_USER and DEALER_ID)
        self.country_edit = QLineEdit()
        self.country_edit.setPlaceholderText("e.g. US, NG, RO...")
        self.country_field = _field("Country", self.country_edit)
        layout.addWidget(self.country_field)
        self.country_field.hide()

        # Source
        src_row = QHBoxLayout()
        self.source_combo = QComboBox()
        self.source_combo.addItems(SOURCES)
        self.source_combo.currentIndexChanged.connect(self._on_source_change)
        src_row.addWidget(_field("Source", self.source_combo))
        self.source_detail_edit = QLineEdit()
        self.source_detail_edit.setPlaceholderText("Detector name or query used...")
        self.source_detail_field = _field("Source Detail", self.source_detail_edit)
        src_row.addWidget(self.source_detail_field)
        self.source_detail_field.hide()
        layout.addLayout(src_row)

        # Action
        self.action_combo = QComboBox()
        self.action_combo.addItems(ACTIONS)
        self.action_combo.setCurrentText("Investigate")
        layout.addWidget(_field("Action", self.action_combo))

        # IP fields
        self.ip_group = QGroupBox("IP Intelligence")
        ip_layout = QVBoxLayout(self.ip_group)
        ip_mode_row = QHBoxLayout()
        self.ip_manual_radio = QPushButton("Manual Entry")
        self.ip_manual_radio.setObjectName("btnDark")
        self.ip_manual_radio.setCheckable(True)
        self.ip_manual_radio.setChecked(True)
        self.ip_manual_radio.clicked.connect(lambda: self._set_ip_mode("manual"))
        self.ip_enrich_radio = QPushButton("Auto-Enrich (enter IP)")
        self.ip_enrich_radio.setObjectName("btnBlue")
        self.ip_enrich_radio.setCheckable(True)
        self.ip_enrich_radio.clicked.connect(lambda: self._set_ip_mode("enrich"))
        ip_mode_row.addWidget(self.ip_manual_radio)
        ip_mode_row.addWidget(self.ip_enrich_radio)
        ip_mode_row.addStretch()
        ip_layout.addLayout(ip_mode_row)

        # Manual IP fields
        self.ip_manual_widget = QWidget()
        iml = QGridLayout(self.ip_manual_widget)
        iml.setContentsMargins(0, 8, 0, 0)
        self.ip_type_combo = QComboBox()
        self.ip_type_combo.addItem("— Select —", "")
        for t in IP_TYPES:
            self.ip_type_combo.addItem(t, t)
        self.provider_edit = QLineEdit()
        self.provider_edit.setPlaceholderText("e.g. NordVPN, DigitalOcean...")
        self.asn_edit = QLineEdit()
        self.asn_edit.setPlaceholderText("e.g. AS14061")
        self.ip_country_edit = QLineEdit()
        self.ip_country_edit.setPlaceholderText("e.g. US, DE")
        self.hosting_check = QCheckBox("Hosting / Datacenter")
        self.hosting_check.setStyleSheet("color:#e8eaed;")
        iml.addWidget(QLabel("Classification"), 0, 0)
        iml.addWidget(self.ip_type_combo, 0, 1)
        iml.addWidget(QLabel("Provider"), 0, 2)
        iml.addWidget(self.provider_edit, 0, 3)
        iml.addWidget(QLabel("ASN"), 1, 0)
        iml.addWidget(self.asn_edit, 1, 1)
        iml.addWidget(QLabel("Country"), 1, 2)
        iml.addWidget(self.ip_country_edit, 1, 3)
        iml.addWidget(self.hosting_check, 2, 0, 1, 2)
        ip_layout.addWidget(self.ip_manual_widget)

        # Enrich widget
        self.ip_enrich_widget = QWidget()
        iel = QHBoxLayout(self.ip_enrich_widget)
        iel.setContentsMargins(0, 8, 0, 0)
        self.enrich_service = QComboBox()
        self.enrich_service.addItems(["IPinfo", "AbuseIPDB"])
        iel.addWidget(QLabel("Service:"))
        iel.addWidget(self.enrich_service)
        self.enrich_btn = QPushButton("Enrich Now")
        self.enrich_btn.setObjectName("btnBlue")
        self.enrich_btn.clicked.connect(self._do_enrich)
        iel.addWidget(self.enrich_btn)
        self.enrich_status = QLabel("")
        self.enrich_status.setStyleSheet("color:#6b7280;font-size:11px;")
        iel.addWidget(self.enrich_status)
        iel.addStretch()
        self.ip_enrich_widget.hide()
        ip_layout.addWidget(self.ip_enrich_widget)

        self.ip_group.hide()
        layout.addWidget(self.ip_group)

        # Tool fields
        self.tool_group = QGroupBox("Tool Details")
        tl = QHBoxLayout(self.tool_group)
        self.tool_cost = QDoubleSpinBox()
        self.tool_cost.setPrefix("$ ")
        self.tool_cost.setMaximum(999999)
        self.tool_cost.setDecimals(2)
        tl.addWidget(_field("Purchase Cost", self.tool_cost))
        tl.addStretch()
        self.tool_group.hide()
        layout.addWidget(self.tool_group)

        # Linking section
        link_group = QGroupBox("Link To")
        ll = QVBoxLayout(link_group)

        # Link to TA
        ta_row = QHBoxLayout()
        ta_row.addWidget(QLabel("Threat Actor:"))
        self.ta_combo = QComboBox()
        self.ta_combo.addItem("— None —", "")
        for a in actors:
            self.ta_combo.addItem(a["name"], a["id"])
        ta_row.addWidget(self.ta_combo)
        ll.addLayout(ta_row)

        # Link to existing IOCs
        ioc_row = QHBoxLayout()
        ioc_row.addWidget(QLabel("Existing IOC:"))
        self.link_ioc_combo = QComboBox()
        self.link_ioc_combo.addItem("— None —", "")
        for ioc in existing_iocs:
            t = IOC_TYPES.get(ioc["type"], ("?", "#999"))
            self.link_ioc_combo.addItem(f"{t[0]} {ioc['value'][:40]}", ioc["id"])
        self.link_ioc_combo.setMaxVisibleItems(15)
        ioc_row.addWidget(self.link_ioc_combo)
        ll.addLayout(ioc_row)

        # Manual link
        manual_row = QHBoxLayout()
        manual_row.addWidget(QLabel("Manual ref:"))
        self.manual_link_edit = QLineEdit()
        self.manual_link_edit.setPlaceholderText("Free text — case ID, ticket number, etc.")
        manual_row.addWidget(self.manual_link_edit)
        ll.addLayout(manual_row)

        layout.addWidget(link_group)

        # Tags + Notes
        self.tags_edit = QLineEdit()
        self.tags_edit.setPlaceholderText("phishing, BEC, credential-stuffing...")
        layout.addWidget(_field("Tags (comma-separated)", self.tags_edit))
        self.notes_edit = QTextEdit()
        self.notes_edit.setPlaceholderText("Context, observed behavior...")
        self.notes_edit.setMaximumHeight(70)
        layout.addWidget(_field("Analyst Notes", self.notes_edit))

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("btnDark")
        cancel_btn.clicked.connect(self.reject)
        add_btn = QPushButton("Add IOC")
        add_btn.setObjectName("btnRed")
        add_btn.clicked.connect(self.accept)
        btn_layout.addWidget(cancel_btn)
        btn_layout.addWidget(add_btn)
        layout.addLayout(btn_layout)

        self._enriched_meta = None
        self._on_type_change()
        self._on_source_change()

    def _on_type_change(self):
        t = self.type_combo.currentData()
        self.ip_group.setVisible(t == "IP")
        self.tool_group.setVisible(t == "TOOL")
        self.country_field.setVisible(t in ("AM_USER", "DEALER_ID"))
        placeholders = {
            "AM_USER": "Email address or username...",
            "DEALER_ID": "Dealer ID number...",
            "IP": "IP address (e.g. 185.234.72.19)...",
            "VIN": "Vehicle Identification Number...",
            "SUB_ID": "HostID / Subscription ID...",
            "TOOL": "Tool name (e.g. FraudFox VM, Multilogin)...",
            "MAC": "MAC address (e.g. AA:BB:CC:DD:EE:FF)...",
        }
        self.value_edit.setPlaceholderText(placeholders.get(t, "Enter value..."))

    def _on_source_change(self):
        src = self.source_combo.currentText()
        show = src in ("Upstream Detector", "Manual")
        self.source_detail_field.setVisible(show)
        if src == "Upstream Detector":
            self.source_detail_edit.setPlaceholderText("Enter detector name...")
        elif src == "Manual":
            self.source_detail_edit.setPlaceholderText("Enter query or method used...")

    def _set_ip_mode(self, mode):
        self.ip_manual_radio.setChecked(mode == "manual")
        self.ip_enrich_radio.setChecked(mode == "enrich")
        self.ip_manual_widget.setVisible(mode == "manual")
        self.ip_enrich_widget.setVisible(mode == "enrich")

    def _do_enrich(self):
        ip = self.value_edit.text().strip()
        if not ip:
            self.enrich_status.setText("Enter an IP first")
            self.enrich_status.setStyleSheet("color:#ff1744;font-size:11px;")
            return
        self.enrich_status.setText("Querying...")
        self.enrich_status.setStyleSheet("color:#ff9100;font-size:11px;")
        QApplication.processEvents()

        settings = self.parent().settings if hasattr(self.parent(), 'settings') else Settings()
        service = self.enrich_service.currentText()
        if service == "IPinfo":
            res = enrich_ipinfo(ip, settings.ipinfo_key)
        else:
            res = enrich_abuseipdb(ip, settings.abuseipdb_key)

        if not res["success"]:
            self.enrich_status.setText(res["error"])
            self.enrich_status.setStyleSheet("color:#ff1744;font-size:11px;")
            return

        self._enriched_meta = {"ipType": "", "provider": "", "asn": "", "country": "", "hosting": False}
        d = res["data"]
        for k in ["provider", "asn", "country", "ipType"]:
            if d.get(k):
                self._enriched_meta[k] = d[k]
        if d.get("hosting"):
            self._enriched_meta["hosting"] = True
        if d.get("abuseScore") is not None:
            self._enriched_meta["abuseScore"] = d["abuseScore"]

        summary = f"✓ {self._enriched_meta.get('ipType', '?')} | {self._enriched_meta.get('provider', '?')} | {self._enriched_meta.get('country', '?')}"
        if self._enriched_meta.get("abuseScore") is not None:
            summary += f" | Abuse: {self._enriched_meta['abuseScore']}%"
        self.enrich_status.setText(summary)
        self.enrich_status.setStyleSheet("color:#69f0ae;font-size:11px;")

    def get_ioc(self):
        now = datetime.now().strftime("%Y-%m-%d")
        ioc_type = self.type_combo.currentData()

        # IP meta
        ip_meta = None
        if ioc_type == "IP":
            if self._enriched_meta:
                ip_meta = self._enriched_meta
            elif self.ip_type_combo.currentData():
                ip_meta = {
                    "ipType": self.ip_type_combo.currentData(),
                    "provider": self.provider_edit.text(),
                    "asn": self.asn_edit.text(),
                    "country": self.ip_country_edit.text(),
                    "hosting": self.hosting_check.isChecked(),
                }

        # Source with detail
        source = self.source_combo.currentText()
        source_detail = self.source_detail_edit.text().strip()
        if source_detail:
            source = f"{source}: {source_detail}"

        # Correlations from IOC link
        correlations = []
        linked_ioc = self.link_ioc_combo.currentData()
        if linked_ioc:
            correlations.append(linked_ioc)

        # Manual link reference
        manual_ref = self.manual_link_edit.text().strip()

        # Notes with manual ref appended
        notes = self.notes_edit.toPlainText()
        if manual_ref:
            notes = f"[Ref: {manual_ref}] {notes}" if notes else f"Ref: {manual_ref}"

        # Country for user/dealer
        country = ""
        if ioc_type in ("AM_USER", "DEALER_ID"):
            country = self.country_edit.text().strip()

        # Tool cost
        tool_cost = None
        if ioc_type == "TOOL" and self.tool_cost.value() > 0:
            tool_cost = self.tool_cost.value()

        return {
            "id": self.custom_id_edit.text().strip() or gen_id("IOC"),
            "type": ioc_type,
            "value": self.value_edit.text().strip(),
            "threatLevel": self.threat_combo.currentText(),
            "source": source,
            "tags": [t.strip() for t in self.tags_edit.text().split(",") if t.strip()],
            "correlations": correlations,
            "notes": notes,
            "status": "active",
            "firstSeen": now,
            "lastSeen": now,
            "hitCount": 0,
            "action": self.action_combo.currentText(),
            "blockCount": 0,
            "ipMeta": ip_meta,
            "linkedTA": self.ta_combo.currentData() or None,
            "country": country,
            "toolCost": tool_cost,
        }


# ══════════════════════════════════════
#  ADD THREAT ACTOR DIALOG
# ══════════════════════════════════════
class AddTADialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Add Threat Actor")
        self.setMinimumWidth(480)
        self.setStyleSheet("QDialog{background:#1a1d23;}")
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("e.g. TA-GhostReaper, FraudRing-047")
        layout.addWidget(_field("Threat Actor Name / Alias", self.name_edit))

        row = QHBoxLayout()
        self.risk_combo = QComboBox()
        for k in THREAT_LEVELS:
            self.risk_combo.addItem(k)
        self.risk_combo.setCurrentText("HIGH")
        self.source_combo = QComboBox()
        self.source_combo.addItems(["AutoThreat", "Upstream Detector", "Manual Intel", "OSINT"])
        row.addWidget(_field("Risk Level", self.risk_combo))
        row.addWidget(_field("Source Report", self.source_combo))
        layout.addLayout(row)

        self.ref_edit = QLineEdit()
        self.ref_edit.setPlaceholderText("e.g. AT-RPT-2026-0342")
        layout.addWidget(_field("Source Report Reference", self.ref_edit))

        self.tools_edit = QTextEdit()
        self.tools_edit.setPlaceholderText("Tools the TA uses that AutoThreat recommends for testing...")
        self.tools_edit.setMaximumHeight(70)
        layout.addWidget(_field("Recommended Tools to Acquire", self.tools_edit))

        self.notes_edit = QTextEdit()
        self.notes_edit.setPlaceholderText("Actor profile, TTPs, campaign details...")
        self.notes_edit.setMaximumHeight(70)
        layout.addWidget(_field("Notes", self.notes_edit))

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("btnDark")
        cancel_btn.clicked.connect(self.reject)
        add_btn = QPushButton("Add Threat Actor")
        add_btn.setObjectName("btnRed")
        add_btn.clicked.connect(self.accept)
        btn_layout.addWidget(cancel_btn)
        btn_layout.addWidget(add_btn)
        layout.addLayout(btn_layout)

    def get_actor(self):
        return {
            "id": gen_id("TA"), "name": self.name_edit.text().strip(),
            "risk": self.risk_combo.currentText(), "source": self.source_combo.currentText(),
            "reportRef": self.ref_edit.text().strip(),
            "recommendedTools": self.tools_edit.toPlainText().strip(),
            "notes": self.notes_edit.toPlainText().strip(),
            "createdAt": datetime.now().strftime("%Y-%m-%d"),
        }


# ══════════════════════════════════════
#  SETTINGS DIALOG
# ══════════════════════════════════════
class SettingsDialog(QDialog):
    def __init__(self, parent, settings):
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle("Settings")
        self.setMinimumWidth(500)
        self.setStyleSheet("QDialog{background:#1a1d23;}")
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        group = QGroupBox("Team Sync — Shared Data Folder")
        group.setStyleSheet("QGroupBox{border:1px solid rgba(130,177,255,0.2);} QGroupBox::title{color:#82b1ff;}")
        gl = QVBoxLayout(group)
        gl.addWidget(QLabel("Point to a OneDrive/SharePoint synced folder."))
        row = QHBoxLayout()
        self.shared_path = QLineEdit(settings.shared_data_path)
        self.shared_path.setPlaceholderText("Not set — using local storage")
        self.shared_path.setReadOnly(True)
        browse_btn = QPushButton("Browse")
        browse_btn.setObjectName("btnDark")
        browse_btn.clicked.connect(self._browse)
        clear_btn = QPushButton("Clear")
        clear_btn.setObjectName("btnDark")
        clear_btn.clicked.connect(lambda: self.shared_path.setText(""))
        row.addWidget(self.shared_path)
        row.addWidget(browse_btn)
        row.addWidget(clear_btn)
        gl.addLayout(row)
        layout.addWidget(group)

        self.ipinfo_edit = QLineEdit(settings.ipinfo_key)
        self.ipinfo_edit.setPlaceholderText("IPinfo API key")
        layout.addWidget(_field("IPinfo Key (free: 50k/month)", self.ipinfo_edit))
        self.abuse_edit = QLineEdit(settings.abuseipdb_key)
        self.abuse_edit.setPlaceholderText("AbuseIPDB API key")
        layout.addWidget(_field("AbuseIPDB Key (free: 1k/day)", self.abuse_edit))

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("btnDark")
        cancel_btn.clicked.connect(self.reject)
        save_btn = QPushButton("Save Settings")
        save_btn.setObjectName("btnRed")
        save_btn.clicked.connect(self.accept)
        btn_layout.addWidget(cancel_btn)
        btn_layout.addWidget(save_btn)
        layout.addLayout(btn_layout)

    def _browse(self):
        path = QFileDialog.getExistingDirectory(self, "Select Shared Folder")
        if path:
            self.shared_path.setText(path)

    def apply_settings(self):
        self.settings.ipinfo_key = self.ipinfo_edit.text().strip()
        self.settings.abuseipdb_key = self.abuse_edit.text().strip()
        self.settings.shared_data_path = self.shared_path.text().strip()
        self.settings.save()


# ══════════════════════════════════════
#  CSV IMPORT DIALOG
# ══════════════════════════════════════
# ══════════════════════════════════════
#  EDIT IOC DIALOG
# ══════════════════════════════════════
class EditIOCDialog(QDialog):
    def __init__(self, parent, ioc):
        super().__init__(parent)
        self.ioc = ioc
        self.setWindowTitle(f"Edit IOC — {ioc['id']}")
        self.setMinimumWidth(500)
        self.setStyleSheet("QDialog{background:#1a1d23;}")
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # Value
        self.value_edit = QLineEdit(ioc.get("value", ""))
        layout.addWidget(_field("Value", self.value_edit))

        # Threat + Action
        row = QHBoxLayout()
        self.threat_combo = QComboBox()
        for k in THREAT_LEVELS:
            self.threat_combo.addItem(k)
        self.threat_combo.setCurrentText(ioc.get("threatLevel", "MEDIUM"))
        self.action_combo = QComboBox()
        self.action_combo.addItems(ACTIONS)
        self.action_combo.setCurrentText(ioc.get("action", "Monitor"))
        row.addWidget(_field("Threat Level", self.threat_combo))
        row.addWidget(_field("Action", self.action_combo))
        layout.addLayout(row)

        # Source
        self.source_edit = QLineEdit(ioc.get("source", ""))
        layout.addWidget(_field("Source", self.source_edit))

        # Country (for AM_USER/DEALER_ID)
        if ioc.get("type") in ("AM_USER", "DEALER_ID"):
            self.country_edit = QLineEdit(ioc.get("country", ""))
            layout.addWidget(_field("Country", self.country_edit))
        else:
            self.country_edit = None

        # Tool cost
        if ioc.get("type") == "TOOL":
            self.tool_cost = QDoubleSpinBox()
            self.tool_cost.setPrefix("$ ")
            self.tool_cost.setMaximum(999999)
            self.tool_cost.setDecimals(2)
            self.tool_cost.setValue(ioc.get("toolCost", 0) or 0)
            layout.addWidget(_field("Purchase Cost", self.tool_cost))
        else:
            self.tool_cost = None

        # Tags
        self.tags_edit = QLineEdit(", ".join(ioc.get("tags", [])))
        layout.addWidget(_field("Tags (comma-separated)", self.tags_edit))

        # Notes
        self.notes_edit = QTextEdit()
        self.notes_edit.setPlainText(ioc.get("notes", ""))
        self.notes_edit.setMaximumHeight(100)
        layout.addWidget(_field("Analyst Notes", self.notes_edit))

        # Status
        row2 = QHBoxLayout()
        self.status_combo = QComboBox()
        self.status_combo.addItems(["active", "monitoring", "resolved"])
        self.status_combo.setCurrentText(ioc.get("status", "active"))
        row2.addWidget(_field("Status", self.status_combo))
        row2.addStretch()
        layout.addLayout(row2)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("btnDark")
        cancel_btn.clicked.connect(self.reject)
        save_btn = QPushButton("Save Changes")
        save_btn.setObjectName("btnRed")
        save_btn.clicked.connect(self.accept)
        btn_layout.addWidget(cancel_btn)
        btn_layout.addWidget(save_btn)
        layout.addLayout(btn_layout)

    def get_updated(self):
        result = {
            "value": self.value_edit.text().strip(),
            "threatLevel": self.threat_combo.currentText(),
            "action": self.action_combo.currentText(),
            "source": self.source_edit.text().strip(),
            "tags": [t.strip() for t in self.tags_edit.text().split(",") if t.strip()],
            "notes": self.notes_edit.toPlainText(),
            "status": self.status_combo.currentText(),
        }
        if self.country_edit is not None:
            result["country"] = self.country_edit.text().strip()
        if self.tool_cost is not None:
            result["toolCost"] = self.tool_cost.value() if self.tool_cost.value() > 0 else None
        return result


class CSVImportDialog(QDialog):
    def __init__(self, parent, filepath, settings_dir=""):
        super().__init__(parent)
        self.filepath = filepath
        self.settings_dir = settings_dir
        self.setWindowTitle("CSV Import — Column Mapping")
        self.setMinimumWidth(700)
        self.setMinimumHeight(500)
        self.setStyleSheet("QDialog{background:#1a1d23;}")
        self.headers, self.preview = read_csv_headers(filepath)
        self.combos = []

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        src_row = QHBoxLayout()
        src_row.addWidget(QLabel("Source:"))
        self.source_combo = QComboBox()
        self.source_combo.addItems(["BigQuery", "AutoThreat", "Upstream Detector", "FDRS", "Manual"])
        src_row.addWidget(self.source_combo)
        src_row.addStretch()
        self.saved = load_saved_mappings(settings_dir) if settings_dir else {}
        if self.saved:
            src_row.addWidget(QLabel("Load saved:"))
            self.saved_combo = QComboBox()
            self.saved_combo.addItem("— Select —")
            for name in self.saved:
                self.saved_combo.addItem(name)
            self.saved_combo.currentIndexChanged.connect(self._load_saved)
            src_row.addWidget(self.saved_combo)
        layout.addLayout(src_row)

        info = QLabel(f"File: {os.path.basename(filepath)} — {len(self.headers)} columns. Map each to a type or skip.")
        info.setStyleSheet("color:#9ca3af;font-size:12px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        w = QWidget()
        gl = QGridLayout(w)
        gl.setSpacing(6)
        for i, h in enumerate(["Column", "Sample", "Map To"]):
            l = QLabel(h)
            l.setStyleSheet("color:#6b7280;font-size:10px;font-weight:700;text-transform:uppercase;")
            gl.addWidget(l, 0, i)

        type_opts = [("— Skip —", "SKIP"), ("Aftermarket User", "AM_USER"), ("Dealer ID", "DEALER_ID"),
            ("HostID / Sub ID", "SUB_ID"), ("IP Address", "IP"), ("VIN", "VIN"),
            ("Tool", "TOOL"), ("MAC Address", "MAC"), ("Username", "USERNAME"),
            ("Timestamp", "TIMESTAMP"), ("Device ID", "DEVICE"), ("Country", "COUNTRY")]

        for ci, header in enumerate(self.headers):
            gl.addWidget(QLabel(header), ci+1, 0)
            samples = [r[ci] for r in self.preview if ci < len(r) and r[ci].strip()][:3]
            sl = QLabel(" | ".join(samples) if samples else "—")
            sl.setStyleSheet("color:#6b7280;font-size:11px;font-family:Consolas;")
            sl.setMaximumWidth(250)
            sl.setWordWrap(True)
            gl.addWidget(sl, ci+1, 1)
            combo = QComboBox()
            for label, value in type_opts:
                combo.addItem(label, value)
            guessed = guess_column_type(header)
            for idx in range(combo.count()):
                if combo.itemData(idx) == guessed:
                    combo.setCurrentIndex(idx)
                    break
            self.combos.append(combo)
            gl.addWidget(combo, ci+1, 2)

        scroll.setWidget(w)
        layout.addWidget(scroll)

        bot = QHBoxLayout()
        self.save_name = QLineEdit()
        self.save_name.setPlaceholderText("Save mapping as... (optional)")
        self.save_name.setFixedWidth(300)
        bot.addWidget(self.save_name)
        bot.addStretch()
        cb = QPushButton("Cancel")
        cb.setObjectName("btnDark")
        cb.clicked.connect(self.reject)
        ib = QPushButton("Import CSV")
        ib.setObjectName("btnRed")
        ib.clicked.connect(self.accept)
        bot.addWidget(cb)
        bot.addWidget(ib)
        layout.addLayout(bot)

    def _load_saved(self, idx):
        if idx <= 0:
            return
        m = self.saved.get(self.saved_combo.currentText(), {})
        for cs, it in m.items():
            ci = int(cs)
            if ci < len(self.combos):
                for i in range(self.combos[ci].count()):
                    if self.combos[ci].itemData(i) == it:
                        self.combos[ci].setCurrentIndex(i)
                        break

    def get_mapping(self):
        return {i: c.currentData() for i, c in enumerate(self.combos) if c.currentData() != "SKIP"}

    def get_source(self):
        return self.source_combo.currentText()

    def get_save_name(self):
        return self.save_name.text().strip()


# ══════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("⚡ Fraud IOC Tracker")
        self.setMinimumSize(1200, 750)
        self.resize(1440, 900)
        self.settings = Settings()
        self.store = DataStore(self.settings)
        self.store.load()
        self.save_timer = QTimer()
        self.save_timer.setSingleShot(True)
        self.save_timer.timeout.connect(self._do_save)
        self.sort_col = "lastSeen"
        self.sort_asc = False
        self.filtered_iocs = []
        self.selected_ioc_id = None

        central = QWidget()
        self.setCentralWidget(central)
        ml = QVBoxLayout(central)
        ml.setContentsMargins(0, 0, 0, 0)
        ml.setSpacing(0)

        # Header
        header = QFrame()
        header.setStyleSheet("background:#12141a;border-bottom:1px solid #1a1d23;")
        header.setFixedHeight(56)
        hl = QHBoxLayout(header)
        hl.setContentsMargins(20, 0, 20, 0)
        tc = QVBoxLayout()
        tl = QLabel("⚡ Fraud IOC Tracker")
        tl.setStyleSheet("font-size:16px;font-weight:700;")
        tc.addWidget(tl)
        stl = QLabel("IOC Correlation & Threat Actor Tracking")
        stl.setStyleSheet("font-size:11px;color:#6b7280;")
        tc.addWidget(stl)
        hl.addLayout(tc)
        hl.addStretch()
        self.autosave_lbl = QLabel("● Ready")
        self.autosave_lbl.setStyleSheet("color:#2e7d32;font-size:10px;")
        hl.addWidget(self.autosave_lbl)
        for text, name, handler in [
            ("⚙ Settings", "btnDark", self._open_settings),
            ("📄 Ingest CSV", "btnBlue", self._ingest_csv),
            ("🔗 Auto-Correlate", "btnDark", self._auto_correlate),
            ("⤵ Merge", "btnDark", self._merge),
            ("⤴ Import", "btnDark", self._import),
            ("⤓ Export", "btnGreen", self._export),
        ]:
            b = QPushButton(text)
            b.setObjectName(name)
            b.clicked.connect(handler)
            hl.addWidget(b)
        ml.addWidget(header)

        # Tabs
        self.tabs = QTabWidget()

        # ── IOC Tab ──
        ioc_w = QWidget()
        il = QVBoxLayout(ioc_w)
        il.setContentsMargins(0, 0, 0, 0)
        il.setSpacing(0)

        sf = QFrame()
        sf.setStyleSheet("border-bottom:1px solid #1a1d23;")
        sl = QHBoxLayout(sf)
        sl.setContentsMargins(20, 12, 20, 12)
        self.stat_total = StatCard("Total IOCs", "0", "#82b1ff")
        self.stat_critical = StatCard("Critical", "0", "#ff1744")
        self.stat_active = StatCard("Active", "0", "#ff9100")
        self.stat_hits = StatCard("Total Hits", "0", "#b388ff")
        self.stat_suspended = StatCard("Suspended", "0", "#ff1744")
        self.stat_vpn = StatCard("VPN/Proxy/Tor", "0", "#ffea00")
        for s in [self.stat_total, self.stat_critical, self.stat_active, self.stat_hits, self.stat_suspended, self.stat_vpn]:
            sl.addWidget(s)
        il.addWidget(sf)

        # Filters
        ff = QFrame()
        ff.setStyleSheet("border-bottom:1px solid #1a1d23;")
        fl = QHBoxLayout(ff)
        fl.setContentsMargins(20, 10, 20, 10)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search...")
        self.search_edit.setFixedWidth(240)
        self.search_edit.textChanged.connect(self._refresh_table)
        fl.addWidget(self.search_edit)
        self.f_type = QComboBox()
        self.f_type.addItem("All Types", "ALL")
        for k, (label, _) in IOC_TYPES.items():
            self.f_type.addItem(label, k)
        self.f_type.currentIndexChanged.connect(self._refresh_table)
        self.f_type.setFixedWidth(160)
        fl.addWidget(self.f_type)
        self.f_threat = QComboBox()
        self.f_threat.addItem("All Levels", "ALL")
        for k in THREAT_LEVELS:
            self.f_threat.addItem(k, k)
        self.f_threat.currentIndexChanged.connect(self._refresh_table)
        self.f_threat.setFixedWidth(110)
        fl.addWidget(self.f_threat)
        self.f_source = QComboBox()
        self.f_source.addItem("All Sources", "ALL")
        for s in SOURCES:
            self.f_source.addItem(s, s)
        self.f_source.currentIndexChanged.connect(self._refresh_table)
        self.f_source.setFixedWidth(140)
        fl.addWidget(self.f_source)
        fl.addStretch()
        self.count_lbl = QLabel()
        self.count_lbl.setStyleSheet("color:#6b7280;font-size:11px;")
        fl.addWidget(self.count_lbl)
        ab = QPushButton("+ Add IOC")
        ab.setObjectName("btnRed")
        ab.clicked.connect(self._add_ioc)
        fl.addWidget(ab)
        il.addWidget(ff)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(11)
        self.table.setHorizontalHeaderLabels(["ID", "Type", "Value", "Threat", "Source", "Hits", "Action", "Last Seen", "TA", "Links", "Cost"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.cellClicked.connect(self._on_row_click)
        self.table.horizontalHeader().sectionClicked.connect(self._on_header_click)
        for i, w in enumerate([70, 130, 0, 80, 110, 55, 130, 90, 35, 40, 65]):
            if w:
                self.table.setColumnWidth(i, w)
        il.addWidget(self.table)
        self.tabs.addTab(ioc_w, "IOC Dashboard")

        # ── Threat Actors Tab ──
        ta_w = QWidget()
        tal = QVBoxLayout(ta_w)
        tal.setContentsMargins(0, 0, 0, 0)
        tah = QFrame()
        tah.setStyleSheet("border-bottom:1px solid #1a1d23;")
        tahx = QHBoxLayout(tah)
        tahx.setContentsMargins(20, 12, 20, 12)
        tahx.addWidget(QLabel("Threat Actor Profiles"))
        tahx.addStretch()
        atb = QPushButton("+ Add Threat Actor")
        atb.setObjectName("btnRed")
        atb.clicked.connect(self._add_ta)
        tahx.addWidget(atb)
        tal.addWidget(tah)
        self.ta_scroll = QScrollArea()
        self.ta_scroll.setWidgetResizable(True)
        self.ta_container = QWidget()
        self.ta_list_layout = QVBoxLayout(self.ta_container)
        self.ta_list_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.ta_scroll.setWidget(self.ta_container)
        tal.addWidget(self.ta_scroll)
        self.tabs.addTab(ta_w, "Threat Actors")

        # Detail panel
        self.detail_panel = QScrollArea()
        self.detail_panel.setWidgetResizable(True)
        self.detail_panel.setFixedWidth(0)
        self.detail_panel.setStyleSheet("background:#1a1d23;border-left:1px solid #2a2d35;")
        self.detail_content = QWidget()
        self.detail_layout = QVBoxLayout(self.detail_content)
        self.detail_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.detail_panel.setWidget(self.detail_content)

        wrapper = QHBoxLayout()
        wrapper.setContentsMargins(0, 0, 0, 0)
        wrapper.setSpacing(0)
        wrapper.addWidget(self.tabs)
        wrapper.addWidget(self.detail_panel)
        c = QWidget()
        c.setLayout(wrapper)
        ml.addWidget(c)

        self._refresh_table()
        self._refresh_actors()

    # ── Table ──
    def _get_filtered(self):
        q = self.search_edit.text().lower()
        ft = self.f_type.currentData()
        fth = self.f_threat.currentData()
        fs = self.f_source.currentData()
        result = []
        for i in self.store.iocs:
            if ft != "ALL" and i.get("type") != ft:
                continue
            if fth != "ALL" and i.get("threatLevel") != fth:
                continue
            if fs != "ALL" and not i.get("source", "").startswith(fs):
                continue
            if q:
                searchable = " ".join([i.get("value", ""), i.get("id", ""), " ".join(i.get("tags", [])),
                    i.get("notes", ""), i.get("source", ""), i.get("country", ""),
                    (i.get("ipMeta") or {}).get("provider", "")]).lower()
                if q not in searchable:
                    continue
            result.append(i)
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        if self.sort_col == "threatLevel":
            result.sort(key=lambda x: order.index(x.get("threatLevel", "LOW")), reverse=not self.sort_asc)
        elif self.sort_col in ("hitCount", "blockCount"):
            result.sort(key=lambda x: x.get(self.sort_col, 0), reverse=not self.sort_asc)
        elif self.sort_col == "lastSeen":
            result.sort(key=lambda x: x.get("lastSeen", ""), reverse=not self.sort_asc)
        elif self.sort_col == "value":
            result.sort(key=lambda x: x.get("value", "").lower(), reverse=not self.sort_asc)
        return result

    def _refresh_table(self):
        self._update_stats()
        self.filtered_iocs = self._get_filtered()
        self.count_lbl.setText(f"{len(self.filtered_iocs)} results")
        self.table.setRowCount(len(self.filtered_iocs))
        act_colors = {"Suspended": "#ff1744", "Escalate": "#ff9100", "Investigate": "#82b1ff",
            "Quarantine": "#ea80fc", "Monitor": "#69f0ae", "Added to Compromised List": "#ff1744", "Purchase Tool": "#ffd180"}
        for row, ioc in enumerate(self.filtered_iocs):
            self.table.setRowHeight(row, 36)
            # ID
            it = QTableWidgetItem(ioc["id"][-8:])
            it.setFont(MONO)
            it.setForeground(QColor("#6b7280"))
            self.table.setItem(row, 0, it)
            # Type
            t = IOC_TYPES.get(ioc["type"], ("?", "#999"))
            ti = QTableWidgetItem(t[0])
            ti.setForeground(QColor(t[1]))
            self.table.setItem(row, 1, ti)
            # Value
            vi = QTableWidgetItem(ioc["value"])
            vi.setFont(MONO)
            self.table.setItem(row, 2, vi)
            # Threat
            tl_c = THREAT_LEVELS.get(ioc["threatLevel"], ("#999", "#222"))
            thi = QTableWidgetItem(ioc["threatLevel"])
            thi.setForeground(QColor(tl_c[0]))
            self.table.setItem(row, 3, thi)
            # Source
            src = ioc.get("source", "")
            src_short = src.split(":")[0] if ":" in src else src
            si = QTableWidgetItem(src_short)
            si.setForeground(QColor("#ff80ab" if "AutoThreat" in src else "#80d8ff" if "Upstream" in src else "#9ca3af"))
            self.table.setItem(row, 4, si)
            # Hits
            hc = ioc.get("hitCount", 0)
            hi = QTableWidgetItem(f"{hc:,}")
            hi.setFont(MONO)
            hi.setForeground(QColor("#ff9100" if hc > 1000 else "#ffea00" if hc > 100 else "#69f0ae"))
            hi.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.table.setItem(row, 5, hi)
            # Action
            act = ioc.get("action", "Monitor")
            ai = QTableWidgetItem(act[:20])
            ai.setForeground(QColor(act_colors.get(act, "#69f0ae")))
            self.table.setItem(row, 6, ai)
            # Last Seen
            li = QTableWidgetItem(ioc.get("lastSeen", ""))
            li.setForeground(QColor("#9ca3af"))
            self.table.setItem(row, 7, li)
            # TA
            tai = QTableWidgetItem("⚡" if ioc.get("linkedTA") else "—")
            tai.setForeground(QColor("#ff80ab" if ioc.get("linkedTA") else "#2a2d35"))
            tai.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 8, tai)
            # Links
            cc = len(ioc.get("correlations", []))
            ci = QTableWidgetItem(str(cc) if cc else "—")
            ci.setFont(MONO)
            ci.setForeground(QColor("#ff80ab" if cc else "#3a3d45"))
            ci.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 9, ci)
            # Cost
            cost = ioc.get("toolCost")
            coi = QTableWidgetItem(f"${cost:,.2f}" if cost else "—")
            coi.setForeground(QColor("#ffd180" if cost else "#2a2d35"))
            self.table.setItem(row, 10, coi)

    def _on_row_click(self, row, col):
        if row < len(self.filtered_iocs):
            self.selected_ioc_id = self.filtered_iocs[row]["id"]
            self._show_detail(self.filtered_iocs[row])

    def _on_header_click(self, col):
        m = {2: "value", 3: "threatLevel", 5: "hitCount", 7: "lastSeen"}
        if col in m:
            k = m[col]
            if self.sort_col == k:
                self.sort_asc = not self.sort_asc
            else:
                self.sort_col = k
                self.sort_asc = False
            self._refresh_table()

    def _update_stats(self):
        iocs = self.store.iocs
        self.stat_total.set_value(len(iocs))
        self.stat_critical.set_value(sum(1 for i in iocs if i.get("threatLevel") == "CRITICAL"))
        self.stat_active.set_value(sum(1 for i in iocs if i.get("status") == "active"))
        self.stat_hits.set_value(f"{sum(i.get('hitCount', 0) for i in iocs):,}")
        self.stat_suspended.set_value(sum(1 for i in iocs if i.get("action") == "Suspended"))
        self.stat_vpn.set_value(sum(1 for i in iocs if i.get("ipMeta") and i["ipMeta"].get("ipType") in ["VPN", "Proxy", "Tor Exit"]))

    # ── Detail Panel ──
    def _show_detail(self, ioc):
        self.detail_panel.setFixedWidth(480)
        while self.detail_layout.count():
            c = self.detail_layout.takeAt(0)
            if c.widget():
                c.widget().deleteLater()

        # Header
        hw = QWidget()
        hx = QHBoxLayout(hw)
        idl = QLabel(ioc["id"])
        idl.setFont(MONO)
        idl.setStyleSheet("color:#6b7280;font-size:13px;")
        idl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        tl = THREAT_LEVELS[ioc["threatLevel"]]
        thl = QLabel(ioc["threatLevel"])
        thl.setStyleSheet(f"color:{tl[0]};font-weight:700;font-size:12px;padding:2px 8px;background:{tl[1]};border-radius:4px;")
        hx.addWidget(idl)
        hx.addWidget(thl)
        hx.addStretch()
        edit_btn = QPushButton("✏ Edit")
        edit_btn.setObjectName("btnDark")
        edit_btn.clicked.connect(lambda: self._edit_ioc(ioc["id"]))
        hx.addWidget(edit_btn)
        del_btn = QPushButton("🗑 Delete")
        del_btn.setStyleSheet("color:#ff1744;background:transparent;border:1px solid #ff174450;border-radius:6px;padding:7px 12px;font-size:12px;font-weight:600;")
        del_btn.clicked.connect(lambda: self._delete_ioc(ioc["id"]))
        hx.addWidget(del_btn)
        cb = QPushButton("✕")
        cb.setObjectName("btnDark")
        cb.clicked.connect(self._close_detail)
        hx.addWidget(cb)
        self.detail_layout.addWidget(hw)

        # Type + Value (selectable)
        t = IOC_TYPES.get(ioc["type"], ("?", "#999"))
        self.detail_layout.addWidget(QLabel(f"<span style='color:{t[1]};font-weight:600'>{t[0]}</span>"))
        vl = QLabel(ioc["value"])
        vl.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        vl.setWordWrap(True)
        vl.setStyleSheet("margin:4px 0 8px 0;")
        vl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.detail_layout.addWidget(vl)

        # Country
        if ioc.get("country"):
            self.detail_layout.addWidget(QLabel(f"Country: {ioc['country']}"))

        # TA
        if ioc.get("linkedTA"):
            ta = self.store.get_actor(ioc["linkedTA"])
            if ta:
                self.detail_layout.addWidget(QLabel(f"<span style='color:#ff80ab'>⚡ Threat Actor: {ta['name']}</span>"))

        # Stats
        sw = QWidget()
        sg = QGridLayout(sw)
        sg.setContentsMargins(0, 8, 0, 8)
        for ci, (label, val) in enumerate([
            ("Hits", f"{ioc.get('hitCount', 0):,}"),
            ("Suspended", str(ioc.get("blockCount", 0))),
            ("First Seen", ioc.get("firstSeen", "")),
            ("Last Seen", ioc.get("lastSeen", "")),
        ]):
            sg.addWidget(StatCard(label, val, "#ff1744" if label == "Suspended" and ioc.get("blockCount", 0) > 0 else "#e8eaed"), 0, ci)
        self.detail_layout.addWidget(sw)

        # Tool cost
        if ioc.get("toolCost"):
            self.detail_layout.addWidget(QLabel(f"<span style='color:#ffd180;font-size:14px;font-weight:700'>💰 Purchase Cost: ${ioc['toolCost']:,.2f}</span>"))

        # IP enrichment
        if ioc["type"] == "IP":
            ew = QWidget()
            el = QHBoxLayout(ew)
            el.setContentsMargins(0, 4, 0, 4)
            for label, svc, color in [("▶ IPinfo", "ipinfo", "#82b1ff"), ("▶ AbuseIPDB", "abuseipdb", "#ff9100")]:
                b = QPushButton(label)
                b.setStyleSheet(f"color:{color};border:1px solid {color}40;background:transparent;padding:4px 10px;border-radius:4px;font-size:10px;font-weight:700;")
                b.clicked.connect(lambda _, s=svc: self._enrich(ioc["id"], s))
                el.addWidget(b)
            el.addStretch()
            self.detail_layout.addWidget(ew)

            meta = ioc.get("ipMeta")
            if meta:
                g = QGroupBox("IP Intelligence")
                gl = QGridLayout(g)
                fields = [("Classification", meta.get("ipType", "—")), ("Provider", meta.get("provider", "—")),
                    ("ASN", meta.get("asn", "—")), ("Country", meta.get("country", "—")),
                    ("Hosting", "Yes" if meta.get("hosting") else "No")]
                if meta.get("abuseScore") is not None:
                    fields.append(("Abuse Score", f"{meta['abuseScore']}%"))
                for idx, (label, val) in enumerate(fields):
                    r, c = divmod(idx, 2)
                    gl.addWidget(QLabel(f"<span style='color:#6b7280;font-size:10px;text-transform:uppercase'>{label}</span>"), r*2, c*2)
                    gl.addWidget(QLabel(f"<span style='color:#e8eaed;font-size:13px'>{val}</span>"), r*2+1, c*2)
                self.detail_layout.addWidget(g)

        # Source
        self.detail_layout.addWidget(QLabel(f"Source: {ioc.get('source', '—')}"))

        # Action
        aw = QWidget()
        al = QHBoxLayout(aw)
        al.setContentsMargins(0, 8, 0, 8)
        ac = QComboBox()
        ac.addItems(ACTIONS)
        ac.setCurrentText(ioc.get("action", "Monitor"))
        ac.currentTextChanged.connect(lambda v: self._upd(ioc["id"], "action", v))
        al.addWidget(QLabel("Action:"))
        al.addWidget(ac)
        sb = QPushButton(f"⛔ Suspend ({ioc.get('blockCount', 0)})")
        sb.setObjectName("btnOutline")
        sb.clicked.connect(lambda: self._suspend(ioc["id"]))
        al.addWidget(sb)
        al.addStretch()
        self.detail_layout.addWidget(aw)

        # Tags
        tags = ioc.get("tags", [])
        if tags:
            tl = QLabel("Tags: " + ", ".join(tags))
            tl.setStyleSheet("color:#9ca3af;font-size:12px;")
            tl.setWordWrap(True)
            self.detail_layout.addWidget(tl)

        # Notes
        if ioc.get("notes"):
            nl = QLabel(ioc["notes"])
            nl.setWordWrap(True)
            nl.setStyleSheet("color:#c0c4cc;font-size:13px;background:#12141a;padding:10px;border-radius:8px;border:1px solid #2a2d35;")
            nl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.detail_layout.addWidget(nl)

        # Correlated
        corr = self.store.get_correlated(ioc)
        if corr:
            self.detail_layout.addWidget(QLabel(f"<span style='color:#ff1744;font-weight:600'>⚡ Correlated IOCs ({len(corr)})</span>"))
            for c in corr:
                ct = IOC_TYPES.get(c["type"], ("?", "#999"))
                cl = QLabel(f"  {c['id']}  {ct[0]}  {c['value']}")
                cl.setStyleSheet("color:#c0c4cc;font-size:12px;background:#12141a;padding:6px 10px;border-radius:6px;border:1px solid #2a2d35;margin:2px 0;")
                cl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                cl.setCursor(Qt.CursorShape.IBeamCursor)
                self.detail_layout.addWidget(cl)

        self.detail_layout.addStretch()

    def _close_detail(self):
        self.detail_panel.setFixedWidth(0)
        self.selected_ioc_id = None

    def _upd(self, ioc_id, key, val):
        self.store.update_ioc(ioc_id, key, val)
        self._trigger_save()
        self._refresh_table()

    def _suspend(self, ioc_id):
        ioc = self.store.get_ioc(ioc_id)
        if ioc:
            ioc["blockCount"] = ioc.get("blockCount", 0) + 1
            ioc["action"] = "Suspended"
            self.store.save()
            self._refresh_table()
            self._show_detail(ioc)

    def _edit_ioc(self, ioc_id):
        ioc = self.store.get_ioc(ioc_id)
        if not ioc:
            return
        dlg = EditIOCDialog(self, ioc)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            updated = dlg.get_updated()
            for k, v in updated.items():
                ioc[k] = v
            self.store.save()
            self._refresh_table()
            self._show_detail(ioc)

    def _delete_ioc(self, ioc_id):
        reply = QMessageBox.question(self, "Delete IOC",
            f"Delete IOC {ioc_id}? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.store.iocs = [i for i in self.store.iocs if i["id"] != ioc_id]
            # Remove from correlations
            for i in self.store.iocs:
                if ioc_id in i.get("correlations", []):
                    i["correlations"].remove(ioc_id)
            self.store.save()
            self._close_detail()
            self._refresh_table()

    def _delete_ta(self, ta_id):
        reply = QMessageBox.question(self, "Delete Threat Actor",
            f"Delete this Threat Actor? IOCs linked to it will be unlinked.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.store.actors = [a for a in self.store.actors if a["id"] != ta_id]
            for i in self.store.iocs:
                if i.get("linkedTA") == ta_id:
                    i["linkedTA"] = None
            self.store.save()
            self._refresh_actors()
            self._close_detail()

    def _enrich(self, ioc_id, service):
        ioc = self.store.get_ioc(ioc_id)
        if not ioc:
            return
        res = enrich_ipinfo(ioc["value"], self.settings.ipinfo_key) if service == "ipinfo" else enrich_abuseipdb(ioc["value"], self.settings.abuseipdb_key)
        if not res["success"]:
            QMessageBox.warning(self, "Enrichment Failed", res["error"])
            return
        if not ioc.get("ipMeta"):
            ioc["ipMeta"] = {"ipType": "", "provider": "", "asn": "", "country": "", "hosting": False}
        d = res["data"]
        for k in ["provider", "asn", "country", "ipType"]:
            if d.get(k):
                ioc["ipMeta"][k] = d[k]
        if d.get("hosting"):
            ioc["ipMeta"]["hosting"] = True
        if d.get("abuseScore") is not None:
            ioc["ipMeta"]["abuseScore"] = d["abuseScore"]
        self.store.save()
        self._refresh_table()
        self._show_detail(ioc)

    # ── Threat Actors ──
    def _refresh_actors(self):
        while self.ta_list_layout.count():
            c = self.ta_list_layout.takeAt(0)
            if c.widget():
                c.widget().deleteLater()
        if not self.store.actors:
            l = QLabel("No threat actors yet.")
            l.setStyleSheet("color:#6b7280;padding:40px;")
            l.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.ta_list_layout.addWidget(l)
            return
        for actor in self.store.actors:
            card = QFrame()
            card.setStyleSheet("background:#12141a;border:1px solid #2a2d35;border-radius:10px;padding:14px;margin:4px 20px;")
            cl = QVBoxLayout(card)
            hdr = QHBoxLayout()
            hdr.addWidget(QLabel(f"<span style='font-size:15px;font-weight:700'>{actor['name']}</span>"))
            tl = THREAT_LEVELS.get(actor.get("risk", "HIGH"), ("#ff9100", "#3d2a00"))
            rl = QLabel(actor.get("risk", "HIGH"))
            rl.setStyleSheet(f"color:{tl[0]};font-weight:700;font-size:11px;padding:2px 8px;background:{tl[1]};border-radius:4px;")
            hdr.addWidget(rl)
            hdr.addStretch()
            linked = self.store.get_linked_iocs(actor["id"])
            hdr.addWidget(QLabel(f"<span style='color:#6b7280;font-size:11px'>{len(linked)} IOCs</span>"))
            del_ta_btn = QPushButton("🗑")
            del_ta_btn.setStyleSheet("color:#ff1744;background:transparent;border:none;font-size:14px;padding:2px 6px;")
            del_ta_btn.clicked.connect(lambda _, tid=actor["id"]: self._delete_ta(tid))
            hdr.addWidget(del_ta_btn)
            cl.addLayout(hdr)
            if actor.get("reportRef"):
                cl.addWidget(QLabel(f"<span style='color:#6b7280;font-size:11px'>Report: {actor['reportRef']}</span>"))
            if actor.get("recommendedTools"):
                tl = QLabel(f"⚙ Tools: {actor['recommendedTools']}")
                tl.setStyleSheet("color:#ffd180;font-size:11px;")
                tl.setWordWrap(True)
                cl.addWidget(tl)
            self.ta_list_layout.addWidget(card)

    # ── Dialogs ──
    def _add_ioc(self):
        dlg = AddIOCDialog(self, self.store.actors, self.store.iocs)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            ioc = dlg.get_ioc()
            if ioc["value"]:
                # Apply bidirectional correlation
                for corr_id in ioc.get("correlations", []):
                    other = self.store.get_ioc(corr_id)
                    if other and ioc["id"] not in other.get("correlations", []):
                        other.setdefault("correlations", []).append(ioc["id"])
                self.store.add_ioc(ioc)
                self._refresh_table()

    def _add_ta(self):
        dlg = AddTADialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            a = dlg.get_actor()
            if a["name"]:
                self.store.add_actor(a)
                self._refresh_actors()

    def _open_settings(self):
        dlg = SettingsDialog(self, self.settings)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            dlg.apply_settings()
            self.store = DataStore(self.settings)
            self.store.load()
            self._refresh_table()
            self._refresh_actors()

    def _export(self):
        p, _ = QFileDialog.getSaveFileName(self, "Export", f"ioc-export-{datetime.now().strftime('%Y-%m-%d')}.json", "JSON (*.json)")
        if p:
            self.store.export_to_file(p)
            QMessageBox.information(self, "Export", f"Exported {len(self.store.iocs)} IOCs")

    def _import(self):
        p, _ = QFileDialog.getOpenFileName(self, "Import", "", "JSON (*.json)")
        if p:
            ci, ca = self.store.import_from_file(p, merge=False)
            self.store.save()
            self._refresh_table()
            self._refresh_actors()
            self._close_detail()
            QMessageBox.information(self, "Import", f"Imported {ci} IOCs + {ca} TAs")

    def _merge(self):
        p, _ = QFileDialog.getOpenFileName(self, "Merge", "", "JSON (*.json)")
        if p:
            ci, ca = self.store.import_from_file(p, merge=True)
            self.store.save()
            self._refresh_table()
            self._refresh_actors()
            QMessageBox.information(self, "Merge", f"Merged {ci} new IOCs + {ca} new TAs")

    def _ingest_csv(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select CSV", "", "CSV (*.csv);;TSV (*.tsv);;All (*.*)")
        if not p:
            return
        sd = self.settings.get_data_dir() if hasattr(self.settings, 'get_data_dir') else ""
        dlg = CSVImportDialog(self, p, sd)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        mapping = dlg.get_mapping()
        if not mapping:
            QMessageBox.warning(self, "No Mapping", "Map at least one column.")
            return
        source = dlg.get_source()
        sn = dlg.get_save_name()
        if sn and sd:
            save_mapping(sd, sn, {str(k): v for k, v in mapping.items()})
        result = ingest_csv(p, mapping, source)
        existing = {(i["type"], i["value"]) for i in self.store.iocs}
        added = 0
        for ioc in result["iocs"]:
            key = (ioc["type"], ioc["value"])
            if key not in existing:
                self.store.iocs.append(ioc)
                existing.add(key)
                added += 1
            else:
                for ex in self.store.iocs:
                    if ex["type"] == ioc["type"] and ex["value"] == ioc["value"]:
                        ex["hitCount"] += ioc["hitCount"]
                        if ioc["lastSeen"] > ex.get("lastSeen", ""):
                            ex["lastSeen"] = ioc["lastSeen"]
                        for cid in ioc.get("correlations", []):
                            if cid not in ex.get("correlations", []):
                                ex.setdefault("correlations", []).append(cid)
                        break
        self.store.save()
        self._refresh_table()
        self._close_detail()
        s = result["stats"]
        QMessageBox.information(self, "CSV Ingest", f"Rows: {s['rows']}\nNew IOCs: {added}\nCorrelations: {s['links_found']}")

    def _auto_correlate(self):
        if not self.store.iocs:
            QMessageBox.information(self, "Auto-Correlate", "Add some IOCs first.")
            return
        links = auto_correlate(self.store.iocs)
        if not links:
            QMessageBox.information(self, "Auto-Correlate", "No new correlations found.")
            return
        applied = apply_correlations(self.store.iocs, links)
        self.store.save()
        self._refresh_table()
        reasons = {}
        for _, _, r in links:
            cat = r.split(":")[0].strip()
            reasons[cat] = reasons.get(cat, 0) + 1
        summary = "\n".join([f"  • {r}: {c}" for r, c in reasons.items()])
        QMessageBox.information(self, "Auto-Correlate", f"Found {len(links)} correlations:\n\n{summary}")

    # ── Auto-save ──
    def _trigger_save(self):
        self.autosave_lbl.setText("● Saving...")
        self.autosave_lbl.setStyleSheet("color:#ff9100;font-size:10px;")
        self.save_timer.start(800)

    def _do_save(self):
        self.store.save()
        self.autosave_lbl.setText("● Auto-saved")
        self.autosave_lbl.setStyleSheet("color:#2e7d32;font-size:10px;")


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(DARK_STYLE)
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#0d0f13"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#e8eaed"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#12141a"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#1a1d23"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#e8eaed"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#2a2d35"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#e8eaed"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#ff1744"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    app.setPalette(palette)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
