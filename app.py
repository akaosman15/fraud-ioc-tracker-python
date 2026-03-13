import sys, os, uuid, io, math
from datetime import datetime, timedelta
from collections import Counter
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QTableWidget, QTableWidgetItem, QHeaderView, QPushButton, QLineEdit,
    QComboBox, QLabel, QTextEdit, QDialog, QFileDialog,
    QTabWidget, QFrame, QScrollArea, QMessageBox, QAbstractItemView,
    QGroupBox, QCheckBox, QDoubleSpinBox, QSplitter,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont, QPalette, QPixmap, QPainter, QPen, QBrush

from data_store import Settings, DataStore, VERSION
from enrichment import enrich_ipinfo, enrich_abuseipdb
from csv_ingest import (read_csv_headers, guess_column_type, ingest_csv,
    auto_correlate, apply_correlations, save_mapping, load_saved_mappings, IOC_MAPPABLE)
from audit_trail import AuditTrail

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
QDoubleSpinBox { background-color: #12141a; border: 1px solid #2a2d35; border-radius: 6px; padding: 6px; color: #e8eaed; }
QSplitter::handle { background: #2a2d35; width: 2px; }
"""

MONO = QFont("Consolas", 11)
MONO.setStyleHint(QFont.StyleHint.Monospace)

def gen_id(prefix="IOC"):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"

def _field(label, widget):
    c = QWidget()
    l = QVBoxLayout(c); l.setContentsMargins(0,0,0,0); l.setSpacing(4)
    lb = QLabel(label); lb.setStyleSheet("color:#9ca3af;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px;")
    l.addWidget(lb); l.addWidget(widget); return c

def _selectable(text, style=""):
    l = QLabel(text); l.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    l.setCursor(Qt.CursorShape.IBeamCursor)
    if style: l.setStyleSheet(style)
    l.setWordWrap(True); return l

# ── Stat Card ──
class StatCard(QFrame):
    def __init__(self, label, value="0", color="#82b1ff"):
        super().__init__()
        self.setStyleSheet("background:#12141a;border:1px solid #1e2028;border-radius:8px;")
        layout = QVBoxLayout(self); layout.setContentsMargins(10,8,10,8); layout.setSpacing(2)
        lbl = QLabel(label); lbl.setStyleSheet("color:#6b7280;font-size:9px;text-transform:uppercase;letter-spacing:1px;font-weight:700;border:none;")
        self.vl = QLabel(str(value)); self.vl.setStyleSheet(f"color:{color};font-size:20px;font-weight:800;font-family:Consolas,monospace;border:none;")
        layout.addWidget(lbl); layout.addWidget(self.vl)
    def set_value(self, v, color=None):
        self.vl.setText(str(v))
        if color: self.vl.setStyleSheet(f"color:{color};font-size:20px;font-weight:800;font-family:Consolas,monospace;border:none;")

# ══════════════════════════════════════
#  FRAUD RING GRAPH WIDGET
# ══════════════════════════════════════
class FraudRingWidget(QWidget):
    def __init__(self, iocs, parent=None):
        super().__init__(parent)
        self.iocs = iocs
        self.setMinimumSize(600, 400)
        self.nodes = {}
        self.edges = []
        self._build_graph()

    def _build_graph(self):
        # Only include IOCs with correlations
        linked = [i for i in self.iocs if i.get("correlations")]
        linked_ids = set()
        for i in linked:
            linked_ids.add(i["id"])
            for c in i.get("correlations", []):
                linked_ids.add(c)
        nodes = [i for i in self.iocs if i["id"] in linked_ids]
        if not nodes:
            return

        # Layout in a circle
        cx, cy = 300, 200
        r = min(250, 30 * len(nodes))
        for idx, ioc in enumerate(nodes):
            angle = (2 * math.pi * idx) / len(nodes) - math.pi / 2
            x = cx + r * math.cos(angle)
            y = cy + r * math.sin(angle)
            self.nodes[ioc["id"]] = {"x": x, "y": y, "ioc": ioc}

        seen = set()
        for ioc in nodes:
            for cid in ioc.get("correlations", []):
                edge = tuple(sorted([ioc["id"], cid]))
                if edge not in seen and cid in self.nodes:
                    seen.add(edge)
                    self.edges.append((ioc["id"], cid))

    def paintEvent(self, event):
        if not self.nodes:
            p = QPainter(self); p.setPen(QColor("#6b7280"))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No correlations to visualize.\nAdd IOCs and run Auto-Correlate.")
            p.end(); return

        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Edges
        p.setPen(QPen(QColor("#2a2d35"), 1))
        for a, b in self.edges:
            na, nb = self.nodes[a], self.nodes[b]
            p.drawLine(int(na["x"]), int(na["y"]), int(nb["x"]), int(nb["y"]))

        # Nodes
        for nid, nd in self.nodes.items():
            ioc = nd["ioc"]
            t = IOC_TYPES.get(ioc["type"], ("?", "#999"))
            color = QColor(t[1])
            tl_color = QColor(THREAT_LEVELS.get(ioc.get("threatLevel", "MEDIUM"), ("#ffea00", "#3d3a00"))[0])
            sz = 12 + min(ioc.get("hitCount", 0) / 50, 12)
            p.setBrush(QBrush(color))
            p.setPen(QPen(tl_color, 2))
            p.drawEllipse(int(nd["x"] - sz/2), int(nd["y"] - sz/2), int(sz), int(sz))
            p.setPen(QColor("#e8eaed"))
            p.setFont(QFont("Inter", 8))
            label = ioc["value"][:20]
            p.drawText(int(nd["x"] - 50), int(nd["y"] + sz/2 + 12), 100, 16, Qt.AlignmentFlag.AlignCenter, label)
        p.end()


# ══════════════════════════════════════
#  ADD IOC DIALOG
# ══════════════════════════════════════
class AddIOCDialog(QDialog):
    def __init__(self, parent, actors, existing_iocs):
        super().__init__(parent)
        self.setWindowTitle("Add Indicator of Compromise")
        self.setMinimumWidth(560)
        self.setStyleSheet("QDialog{background:#1a1d23;}")
        layout = QVBoxLayout(self); layout.setSpacing(10)

        self.custom_id_edit = QLineEdit()
        self.custom_id_edit.setPlaceholderText("Auto-generated if blank. Enter AutoThreat/Upstream ID here.")
        layout.addWidget(_field("IOC ID (optional)", self.custom_id_edit))

        row1 = QHBoxLayout()
        self.type_combo = QComboBox()
        for k, (label, _) in IOC_TYPES.items(): self.type_combo.addItem(label, k)
        self.type_combo.currentIndexChanged.connect(self._on_type_change)
        self.threat_combo = QComboBox()
        for k in THREAT_LEVELS: self.threat_combo.addItem(k)
        self.threat_combo.setCurrentText("HIGH")
        row1.addWidget(_field("IOC Type", self.type_combo))
        row1.addWidget(_field("Threat Level", self.threat_combo))
        layout.addLayout(row1)

        self.value_edit = QLineEdit(); self.value_edit.setPlaceholderText("Enter value...")
        layout.addWidget(_field("Value", self.value_edit))

        self.country_edit = QLineEdit(); self.country_edit.setPlaceholderText("e.g. US, NG, RO...")
        self.country_w = _field("Country", self.country_edit); self.country_w.hide()
        layout.addWidget(self.country_w)

        src_row = QHBoxLayout()
        self.source_combo = QComboBox(); self.source_combo.addItems(SOURCES)
        self.source_combo.currentIndexChanged.connect(self._on_source_change)
        src_row.addWidget(_field("Source", self.source_combo))
        self.source_detail = QLineEdit(); self.source_detail.setPlaceholderText("Detail...")
        self.source_detail_w = _field("Source Detail", self.source_detail); self.source_detail_w.hide()
        src_row.addWidget(self.source_detail_w)
        layout.addLayout(src_row)

        self.action_combo = QComboBox(); self.action_combo.addItems(ACTIONS); self.action_combo.setCurrentText("Investigate")
        layout.addWidget(_field("Action", self.action_combo))

        # IP
        self.ip_group = QGroupBox("IP Intelligence")
        ipl = QVBoxLayout(self.ip_group)
        mr = QHBoxLayout()
        self.ip_manual_btn = QPushButton("Manual Entry"); self.ip_manual_btn.setObjectName("btnDark"); self.ip_manual_btn.setCheckable(True); self.ip_manual_btn.setChecked(True)
        self.ip_enrich_btn = QPushButton("Auto-Enrich"); self.ip_enrich_btn.setObjectName("btnBlue"); self.ip_enrich_btn.setCheckable(True)
        self.ip_manual_btn.clicked.connect(lambda: self._ip_mode("manual")); self.ip_enrich_btn.clicked.connect(lambda: self._ip_mode("enrich"))
        mr.addWidget(self.ip_manual_btn); mr.addWidget(self.ip_enrich_btn); mr.addStretch()
        ipl.addLayout(mr)
        self.ip_manual_w = QWidget(); iml = QGridLayout(self.ip_manual_w); iml.setContentsMargins(0,8,0,0)
        self.ip_type_combo = QComboBox(); self.ip_type_combo.addItem("— Select —", "")
        for t in IP_TYPES: self.ip_type_combo.addItem(t, t)
        self.provider_edit = QLineEdit(); self.provider_edit.setPlaceholderText("Provider...")
        self.asn_edit = QLineEdit(); self.asn_edit.setPlaceholderText("ASN...")
        self.ip_country_edit = QLineEdit(); self.ip_country_edit.setPlaceholderText("Country...")
        self.hosting_check = QCheckBox("Hosting"); self.hosting_check.setStyleSheet("color:#e8eaed;")
        iml.addWidget(QLabel("Type"),0,0); iml.addWidget(self.ip_type_combo,0,1)
        iml.addWidget(QLabel("Provider"),0,2); iml.addWidget(self.provider_edit,0,3)
        iml.addWidget(QLabel("ASN"),1,0); iml.addWidget(self.asn_edit,1,1)
        iml.addWidget(QLabel("Country"),1,2); iml.addWidget(self.ip_country_edit,1,3)
        iml.addWidget(self.hosting_check,2,0,1,2)
        ipl.addWidget(self.ip_manual_w)
        self.ip_enrich_w = QWidget(); iel = QHBoxLayout(self.ip_enrich_w); iel.setContentsMargins(0,8,0,0)
        self.enrich_svc = QComboBox(); self.enrich_svc.addItems(["IPinfo", "AbuseIPDB"])
        iel.addWidget(self.enrich_svc)
        eb = QPushButton("Enrich Now"); eb.setObjectName("btnBlue"); eb.clicked.connect(self._do_enrich)
        iel.addWidget(eb)
        self.enrich_lbl = QLabel(""); self.enrich_lbl.setStyleSheet("color:#6b7280;font-size:11px;"); iel.addWidget(self.enrich_lbl); iel.addStretch()
        self.ip_enrich_w.hide(); ipl.addWidget(self.ip_enrich_w)
        self.ip_group.hide(); layout.addWidget(self.ip_group)

        # Tool
        self.tool_group = QGroupBox("Tool Details")
        tgl = QHBoxLayout(self.tool_group)
        self.tool_cost = QDoubleSpinBox(); self.tool_cost.setPrefix("$ "); self.tool_cost.setMaximum(999999); self.tool_cost.setDecimals(2)
        tgl.addWidget(_field("Purchase Cost", self.tool_cost)); tgl.addStretch()
        self.tool_group.hide(); layout.addWidget(self.tool_group)

        # Linking
        lg = QGroupBox("Link To"); ll = QVBoxLayout(lg)
        tr = QHBoxLayout(); tr.addWidget(QLabel("Threat Actor:"))
        self.ta_combo = QComboBox(); self.ta_combo.addItem("— None —", "")
        for a in actors: self.ta_combo.addItem(a["name"], a["id"])
        tr.addWidget(self.ta_combo); ll.addLayout(tr)
        ir = QHBoxLayout(); ir.addWidget(QLabel("Existing IOC:"))
        self.link_ioc = QComboBox(); self.link_ioc.addItem("— None —", "")
        for i in existing_iocs:
            t = IOC_TYPES.get(i["type"], ("?","#999"))
            self.link_ioc.addItem(f"{t[0]} {i['value'][:40]}", i["id"])
        self.link_ioc.setMaxVisibleItems(15); ir.addWidget(self.link_ioc); ll.addLayout(ir)
        mrl = QHBoxLayout(); mrl.addWidget(QLabel("Manual ref:"))
        self.manual_link = QLineEdit(); self.manual_link.setPlaceholderText("Case ID, ticket...")
        mrl.addWidget(self.manual_link); ll.addLayout(mrl)
        layout.addWidget(lg)

        self.tags_edit = QLineEdit(); self.tags_edit.setPlaceholderText("Tags (comma-separated)...")
        layout.addWidget(_field("Tags", self.tags_edit))
        self.notes_edit = QTextEdit(); self.notes_edit.setPlaceholderText("Notes..."); self.notes_edit.setMaximumHeight(70)
        layout.addWidget(_field("Notes", self.notes_edit))

        bl = QHBoxLayout(); bl.addStretch()
        cb = QPushButton("Cancel"); cb.setObjectName("btnDark"); cb.clicked.connect(self.reject); bl.addWidget(cb)
        ab = QPushButton("Add IOC"); ab.setObjectName("btnRed"); ab.clicked.connect(self.accept); bl.addWidget(ab)
        layout.addLayout(bl)
        self._enriched = None; self._on_type_change(); self._on_source_change()

    def _on_type_change(self):
        t = self.type_combo.currentData()
        self.ip_group.setVisible(t == "IP"); self.tool_group.setVisible(t == "TOOL")
        self.country_w.setVisible(t in ("AM_USER", "DEALER_ID"))
    def _on_source_change(self):
        s = self.source_combo.currentText(); self.source_detail_w.setVisible(s != "AutoThreat")
        self.source_detail.setPlaceholderText("Detector name..." if s == "Upstream Detector" else "Query used...")
    def _ip_mode(self, m):
        self.ip_manual_btn.setChecked(m=="manual"); self.ip_enrich_btn.setChecked(m=="enrich")
        self.ip_manual_w.setVisible(m=="manual"); self.ip_enrich_w.setVisible(m=="enrich")
    def _do_enrich(self):
        ip = self.value_edit.text().strip()
        if not ip: self.enrich_lbl.setText("Enter IP first"); return
        self.enrich_lbl.setText("Querying..."); QApplication.processEvents()
        settings = self.parent().settings if hasattr(self.parent(),'settings') else Settings()
        svc = self.enrich_svc.currentText()
        res = enrich_ipinfo(ip, settings.ipinfo_key) if svc == "IPinfo" else enrich_abuseipdb(ip, settings.abuseipdb_key)
        if not res["success"]: self.enrich_lbl.setText(res["error"]); return
        self._enriched = {"ipType":"","provider":"","asn":"","country":"","hosting":False}
        for k in ["provider","asn","country","ipType"]:
            if res["data"].get(k): self._enriched[k] = res["data"][k]
        if res["data"].get("hosting"): self._enriched["hosting"] = True
        if res["data"].get("abuseScore") is not None: self._enriched["abuseScore"] = res["data"]["abuseScore"]
        self.enrich_lbl.setText(f"✓ {self._enriched.get('ipType','')} | {self._enriched.get('provider','')} | {self._enriched.get('country','')}")
        self.enrich_lbl.setStyleSheet("color:#69f0ae;font-size:11px;")

    def get_ioc(self):
        now = datetime.now().strftime("%Y-%m-%d"); t = self.type_combo.currentData()
        ip_meta = None
        if t == "IP":
            if self._enriched: ip_meta = self._enriched
            elif self.ip_type_combo.currentData():
                ip_meta = {"ipType":self.ip_type_combo.currentData(),"provider":self.provider_edit.text(),"asn":self.asn_edit.text(),"country":self.ip_country_edit.text(),"hosting":self.hosting_check.isChecked()}
        src = self.source_combo.currentText(); sd = self.source_detail.text().strip()
        if sd: src = f"{src}: {sd}"
        corr = []; li = self.link_ioc.currentData()
        if li: corr.append(li)
        mr = self.manual_link.text().strip(); notes = self.notes_edit.toPlainText()
        if mr: notes = f"[Ref: {mr}] {notes}" if notes else f"Ref: {mr}"
        country = self.country_edit.text().strip() if t in ("AM_USER","DEALER_ID") else ""
        tc = self.tool_cost.value() if t == "TOOL" and self.tool_cost.value() > 0 else None
        return {"id": self.custom_id_edit.text().strip() or gen_id("IOC"), "type":t, "value":self.value_edit.text().strip(),
            "threatLevel":self.threat_combo.currentText(), "source":src, "tags":[x.strip() for x in self.tags_edit.text().split(",") if x.strip()],
            "correlations":corr, "notes":notes, "status":"active", "firstSeen":now, "lastSeen":now,
            "hitCount":0, "action":self.action_combo.currentText(), "blockCount":0, "ipMeta":ip_meta,
            "linkedTA":self.ta_combo.currentData() or None, "country":country, "toolCost":tc}


# ── Edit IOC Dialog ──
class EditIOCDialog(QDialog):
    def __init__(self, parent, ioc):
        super().__init__(parent); self.ioc = ioc
        self.setWindowTitle(f"Edit IOC — {ioc['id']}"); self.setMinimumWidth(500)
        self.setStyleSheet("QDialog{background:#1a1d23;}")
        layout = QVBoxLayout(self); layout.setSpacing(10)
        self.value_edit = QLineEdit(ioc.get("value","")); layout.addWidget(_field("Value", self.value_edit))
        row = QHBoxLayout()
        self.threat_combo = QComboBox()
        for k in THREAT_LEVELS: self.threat_combo.addItem(k)
        self.threat_combo.setCurrentText(ioc.get("threatLevel","MEDIUM"))
        self.action_combo = QComboBox(); self.action_combo.addItems(ACTIONS); self.action_combo.setCurrentText(ioc.get("action","Monitor"))
        row.addWidget(_field("Threat Level", self.threat_combo)); row.addWidget(_field("Action", self.action_combo))
        layout.addLayout(row)
        self.source_edit = QLineEdit(ioc.get("source","")); layout.addWidget(_field("Source", self.source_edit))
        self.country_edit = None
        if ioc.get("type") in ("AM_USER","DEALER_ID"):
            self.country_edit = QLineEdit(ioc.get("country","")); layout.addWidget(_field("Country", self.country_edit))
        self.tool_cost = None
        if ioc.get("type") == "TOOL":
            self.tool_cost = QDoubleSpinBox(); self.tool_cost.setPrefix("$ "); self.tool_cost.setMaximum(999999)
            self.tool_cost.setDecimals(2); self.tool_cost.setValue(ioc.get("toolCost",0) or 0)
            layout.addWidget(_field("Purchase Cost", self.tool_cost))
        self.tags_edit = QLineEdit(", ".join(ioc.get("tags",[]))); layout.addWidget(_field("Tags", self.tags_edit))
        self.notes_edit = QTextEdit(); self.notes_edit.setPlainText(ioc.get("notes","")); self.notes_edit.setMaximumHeight(100)
        layout.addWidget(_field("Notes", self.notes_edit))
        self.status_combo = QComboBox(); self.status_combo.addItems(["active","monitoring","resolved"])
        self.status_combo.setCurrentText(ioc.get("status","active")); layout.addWidget(_field("Status", self.status_combo))
        bl = QHBoxLayout(); bl.addStretch()
        cb = QPushButton("Cancel"); cb.setObjectName("btnDark"); cb.clicked.connect(self.reject); bl.addWidget(cb)
        sb = QPushButton("Save"); sb.setObjectName("btnRed"); sb.clicked.connect(self.accept); bl.addWidget(sb)
        layout.addLayout(bl)

    def get_updated(self):
        r = {"value":self.value_edit.text().strip(),"threatLevel":self.threat_combo.currentText(),
            "action":self.action_combo.currentText(),"source":self.source_edit.text().strip(),
            "tags":[x.strip() for x in self.tags_edit.text().split(",") if x.strip()],
            "notes":self.notes_edit.toPlainText(),"status":self.status_combo.currentText()}
        if self.country_edit: r["country"] = self.country_edit.text().strip()
        if self.tool_cost: r["toolCost"] = self.tool_cost.value() if self.tool_cost.value() > 0 else None
        return r


# ── Add TA Dialog ──
class AddTADialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent); self.setWindowTitle("Add Threat Actor"); self.setMinimumWidth(480)
        self.setStyleSheet("QDialog{background:#1a1d23;}")
        layout = QVBoxLayout(self); layout.setSpacing(10)
        self.name_edit = QLineEdit(); self.name_edit.setPlaceholderText("e.g. TA-GhostReaper")
        layout.addWidget(_field("Name / Alias", self.name_edit))
        row = QHBoxLayout()
        self.risk_combo = QComboBox()
        for k in THREAT_LEVELS: self.risk_combo.addItem(k)
        self.risk_combo.setCurrentText("HIGH")
        self.source_combo = QComboBox(); self.source_combo.addItems(["AutoThreat","Upstream Detector","Manual Intel","OSINT"])
        row.addWidget(_field("Risk", self.risk_combo)); row.addWidget(_field("Source", self.source_combo))
        layout.addLayout(row)
        self.ref_edit = QLineEdit(); self.ref_edit.setPlaceholderText("Report reference...")
        layout.addWidget(_field("Report Reference", self.ref_edit))
        self.tools_edit = QTextEdit(); self.tools_edit.setPlaceholderText("Tools to acquire..."); self.tools_edit.setMaximumHeight(70)
        layout.addWidget(_field("Recommended Tools", self.tools_edit))
        self.notes_edit = QTextEdit(); self.notes_edit.setPlaceholderText("Notes..."); self.notes_edit.setMaximumHeight(70)
        layout.addWidget(_field("Notes", self.notes_edit))
        bl = QHBoxLayout(); bl.addStretch()
        cb = QPushButton("Cancel"); cb.setObjectName("btnDark"); cb.clicked.connect(self.reject); bl.addWidget(cb)
        ab = QPushButton("Add"); ab.setObjectName("btnRed"); ab.clicked.connect(self.accept); bl.addWidget(ab)
        layout.addLayout(bl)
    def get_actor(self):
        return {"id":gen_id("TA"),"name":self.name_edit.text().strip(),"risk":self.risk_combo.currentText(),
            "source":self.source_combo.currentText(),"reportRef":self.ref_edit.text().strip(),
            "recommendedTools":self.tools_edit.toPlainText().strip(),"notes":self.notes_edit.toPlainText().strip(),
            "createdAt":datetime.now().strftime("%Y-%m-%d")}


# ── Settings Dialog ──
class SettingsDialog(QDialog):
    def __init__(self, parent, settings):
        super().__init__(parent); self.settings = settings
        self.setWindowTitle("Settings"); self.setMinimumWidth(500); self.setStyleSheet("QDialog{background:#1a1d23;}")
        layout = QVBoxLayout(self); layout.setSpacing(12)
        g = QGroupBox("Team Sync"); gl = QVBoxLayout(g)
        gl.addWidget(QLabel("Point to OneDrive/SharePoint synced folder."))
        r = QHBoxLayout(); self.shared_path = QLineEdit(settings.shared_data_path); self.shared_path.setReadOnly(True)
        bb = QPushButton("Browse"); bb.setObjectName("btnDark"); bb.clicked.connect(self._browse)
        clb = QPushButton("Clear"); clb.setObjectName("btnDark"); clb.clicked.connect(lambda: self.shared_path.setText(""))
        r.addWidget(self.shared_path); r.addWidget(bb); r.addWidget(clb); gl.addLayout(r); layout.addWidget(g)
        self.ipinfo_edit = QLineEdit(settings.ipinfo_key); layout.addWidget(_field("IPinfo Key", self.ipinfo_edit))
        self.abuse_edit = QLineEdit(settings.abuseipdb_key); layout.addWidget(_field("AbuseIPDB Key", self.abuse_edit))
        bl = QHBoxLayout(); bl.addStretch()
        cb = QPushButton("Cancel"); cb.setObjectName("btnDark"); cb.clicked.connect(self.reject); bl.addWidget(cb)
        sb = QPushButton("Save"); sb.setObjectName("btnRed"); sb.clicked.connect(self.accept); bl.addWidget(sb)
        layout.addLayout(bl)
    def _browse(self):
        p = QFileDialog.getExistingDirectory(self, "Select Folder")
        if p: self.shared_path.setText(p)
    def apply_settings(self):
        self.settings.ipinfo_key = self.ipinfo_edit.text().strip()
        self.settings.abuseipdb_key = self.abuse_edit.text().strip()
        self.settings.shared_data_path = self.shared_path.text().strip()
        self.settings.save()


# ── CSV Import Dialog ──
class CSVImportDialog(QDialog):
    def __init__(self, parent, filepath, settings_dir=""):
        super().__init__(parent); self.filepath = filepath; self.settings_dir = settings_dir
        self.setWindowTitle("CSV Import"); self.setMinimumWidth(700); self.setMinimumHeight(500)
        self.setStyleSheet("QDialog{background:#1a1d23;}")
        self.headers, self.preview = read_csv_headers(filepath); self.combos = []
        layout = QVBoxLayout(self); layout.setSpacing(12)
        sr = QHBoxLayout(); sr.addWidget(QLabel("Source:"))
        self.source_combo = QComboBox(); self.source_combo.addItems(["BigQuery","AutoThreat","Upstream Detector","FDRS","Manual"])
        sr.addWidget(self.source_combo); sr.addStretch()
        self.saved = load_saved_mappings(settings_dir) if settings_dir else {}
        if self.saved:
            sr.addWidget(QLabel("Load saved:"))
            self.saved_combo = QComboBox(); self.saved_combo.addItem("—")
            for n in self.saved: self.saved_combo.addItem(n)
            self.saved_combo.currentIndexChanged.connect(self._load_saved); sr.addWidget(self.saved_combo)
        layout.addLayout(sr)
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        w = QWidget(); gl = QGridLayout(w); gl.setSpacing(6)
        type_opts = [("— Skip —","SKIP"),("Aftermarket User","AM_USER"),("Dealer ID","DEALER_ID"),("HostID/Sub ID","SUB_ID"),
            ("IP Address","IP"),("VIN","VIN"),("Tool","TOOL"),("MAC Address","MAC"),("Username","USERNAME"),
            ("Timestamp","TIMESTAMP"),("Device ID","DEVICE"),("Country","COUNTRY")]
        for ci, h in enumerate(self.headers):
            gl.addWidget(QLabel(h), ci+1, 0)
            samples = [r[ci] for r in self.preview if ci < len(r) and r[ci].strip()][:3]
            sl = QLabel(" | ".join(samples) if samples else "—"); sl.setStyleSheet("color:#6b7280;font-size:11px;"); sl.setMaximumWidth(250)
            gl.addWidget(sl, ci+1, 1)
            combo = QComboBox()
            for label, value in type_opts: combo.addItem(label, value)
            g = guess_column_type(h)
            for idx in range(combo.count()):
                if combo.itemData(idx) == g: combo.setCurrentIndex(idx); break
            self.combos.append(combo); gl.addWidget(combo, ci+1, 2)
        scroll.setWidget(w); layout.addWidget(scroll)
        bot = QHBoxLayout()
        self.save_name = QLineEdit(); self.save_name.setPlaceholderText("Save mapping as..."); self.save_name.setFixedWidth(300)
        bot.addWidget(self.save_name); bot.addStretch()
        cb = QPushButton("Cancel"); cb.setObjectName("btnDark"); cb.clicked.connect(self.reject); bot.addWidget(cb)
        ib = QPushButton("Import"); ib.setObjectName("btnRed"); ib.clicked.connect(self.accept); bot.addWidget(ib)
        layout.addLayout(bot)
    def _load_saved(self, idx):
        if idx <= 0: return
        m = self.saved.get(self.saved_combo.currentText(), {})
        for cs, it in m.items():
            ci = int(cs)
            if ci < len(self.combos):
                for i in range(self.combos[ci].count()):
                    if self.combos[ci].itemData(i) == it: self.combos[ci].setCurrentIndex(i); break
    def get_mapping(self): return {i: c.currentData() for i, c in enumerate(self.combos) if c.currentData() != "SKIP"}
    def get_source(self): return self.source_combo.currentText()
    def get_save_name(self): return self.save_name.text().strip()


# ══════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("⚡ Fraud IOC Tracker")
        self.setMinimumSize(1200, 750); self.resize(1440, 900)
        self.settings = Settings()
        self.store = DataStore(self.settings); self.store.load()
        self.audit = AuditTrail(self.settings.get_data_dir())
        self.save_timer = QTimer(); self.save_timer.setSingleShot(True); self.save_timer.timeout.connect(self._do_save)
        self.sort_col = "lastSeen"; self.sort_asc = False; self.filtered_iocs = []; self.selected_ioc_id = None

        central = QWidget(); self.setCentralWidget(central)
        ml = QVBoxLayout(central); ml.setContentsMargins(0,0,0,0); ml.setSpacing(0)

        # Header
        header = QFrame(); header.setStyleSheet("background:#12141a;border-bottom:1px solid #1a1d23;"); header.setFixedHeight(56)
        hl = QHBoxLayout(header); hl.setContentsMargins(20,0,20,0)
        tc = QVBoxLayout()
        tc.addWidget(QLabel("⚡ Fraud IOC Tracker"))
        stl = QLabel("IOC Correlation & Threat Actor Tracking"); stl.setStyleSheet("font-size:11px;color:#6b7280;"); tc.addWidget(stl)
        hl.addLayout(tc); hl.addStretch()
        self.autosave_lbl = QLabel("● Ready"); self.autosave_lbl.setStyleSheet("color:#2e7d32;font-size:10px;"); hl.addWidget(self.autosave_lbl)
        for text, name, handler in [("⚙ Settings","btnDark",self._open_settings),("📄 Ingest CSV","btnBlue",self._ingest_csv),
            ("🔗 Auto-Correlate","btnDark",self._auto_correlate),("⤵ Merge","btnDark",self._merge),("⤴ Import","btnDark",self._import),("⤓ Export","btnGreen",self._export)]:
            b = QPushButton(text); b.setObjectName(name); b.clicked.connect(handler); hl.addWidget(b)
        ml.addWidget(header)

        # Content: tabs + detail panel in splitter
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.tabs = QTabWidget()

        # ── IOC Tab ──
        ioc_w = QWidget(); il = QVBoxLayout(ioc_w); il.setContentsMargins(0,0,0,0); il.setSpacing(0)
        sf = QFrame(); sf.setStyleSheet("border-bottom:1px solid #1a1d23;")
        sl = QHBoxLayout(sf); sl.setContentsMargins(20,12,20,12)
        self.stat_total = StatCard("Total IOCs","0","#82b1ff"); self.stat_critical = StatCard("Critical","0","#ff1744")
        self.stat_active = StatCard("Active","0","#ff9100"); self.stat_hits = StatCard("Total Hits","0","#b388ff")
        self.stat_suspended = StatCard("Suspended","0","#ff1744"); self.stat_vpn = StatCard("VPN/Proxy/Tor","0","#ffea00")
        for s in [self.stat_total,self.stat_critical,self.stat_active,self.stat_hits,self.stat_suspended,self.stat_vpn]: sl.addWidget(s)
        il.addWidget(sf)
        ff = QFrame(); ff.setStyleSheet("border-bottom:1px solid #1a1d23;")
        fl = QHBoxLayout(ff); fl.setContentsMargins(20,10,20,10)
        self.search_edit = QLineEdit(); self.search_edit.setPlaceholderText("Search..."); self.search_edit.setFixedWidth(240)
        self.search_edit.textChanged.connect(self._refresh_table); fl.addWidget(self.search_edit)
        self.f_type = QComboBox(); self.f_type.addItem("All Types","ALL")
        for k,(label,_) in IOC_TYPES.items(): self.f_type.addItem(label,k)
        self.f_type.currentIndexChanged.connect(self._refresh_table); self.f_type.setFixedWidth(160); fl.addWidget(self.f_type)
        self.f_threat = QComboBox(); self.f_threat.addItem("All Levels","ALL")
        for k in THREAT_LEVELS: self.f_threat.addItem(k,k)
        self.f_threat.currentIndexChanged.connect(self._refresh_table); self.f_threat.setFixedWidth(110); fl.addWidget(self.f_threat)
        self.f_source = QComboBox(); self.f_source.addItem("All Sources","ALL")
        for s in SOURCES: self.f_source.addItem(s,s)
        self.f_source.currentIndexChanged.connect(self._refresh_table); self.f_source.setFixedWidth(140); fl.addWidget(self.f_source)
        fl.addStretch()
        self.count_lbl = QLabel(); self.count_lbl.setStyleSheet("color:#6b7280;font-size:11px;"); fl.addWidget(self.count_lbl)
        ab = QPushButton("+ Add IOC"); ab.setObjectName("btnRed"); ab.clicked.connect(self._add_ioc); fl.addWidget(ab)
        il.addWidget(ff)
        self.table = QTableWidget(); self.table.setColumnCount(11)
        self.table.setHorizontalHeaderLabels(["ID","Type","Value","Threat","Source","Hits","Action","Last Seen","TA","Links","Cost"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.cellClicked.connect(self._on_row_click)
        self.table.horizontalHeader().sectionClicked.connect(self._on_header_click)
        for i,w in enumerate([70,130,0,80,110,55,130,90,35,40,65]):
            if w: self.table.setColumnWidth(i,w)
        il.addWidget(self.table)
        self.tabs.addTab(ioc_w, "IOC Dashboard")

        # ── Threat Actors Tab ──
        ta_w = QWidget(); tal = QVBoxLayout(ta_w); tal.setContentsMargins(0,0,0,0)
        tah = QFrame(); tah.setStyleSheet("border-bottom:1px solid #1a1d23;")
        tahx = QHBoxLayout(tah); tahx.setContentsMargins(20,12,20,12)
        tahx.addWidget(QLabel("Threat Actor Profiles")); tahx.addStretch()
        atb = QPushButton("+ Add Threat Actor"); atb.setObjectName("btnRed"); atb.clicked.connect(self._add_ta); tahx.addWidget(atb)
        tal.addWidget(tah)
        self.ta_scroll = QScrollArea(); self.ta_scroll.setWidgetResizable(True)
        self.ta_container = QWidget(); self.ta_list_layout = QVBoxLayout(self.ta_container)
        self.ta_list_layout.setAlignment(Qt.AlignmentFlag.AlignTop); self.ta_scroll.setWidget(self.ta_container)
        tal.addWidget(self.ta_scroll); self.tabs.addTab(ta_w, "Threat Actors")

        # ── Dashboard Tab ──
        dash_w = QWidget(); self.dash_layout = QVBoxLayout(dash_w); self.dash_layout.setContentsMargins(20,16,20,16)
        dash_scroll = QScrollArea(); dash_scroll.setWidgetResizable(True); dash_scroll.setWidget(dash_w)
        self.tabs.addTab(dash_scroll, "📊 Dashboard")

        # ── Fraud Ring Tab ──
        ring_w = QWidget(); ring_l = QVBoxLayout(ring_w); ring_l.setContentsMargins(20,16,20,16)
        ring_header = QHBoxLayout()
        ring_header.addWidget(QLabel("<span style='font-size:14px;font-weight:600'>Fraud Ring Visualization</span>"))
        ring_header.addStretch()
        refresh_ring = QPushButton("🔄 Refresh Graph"); refresh_ring.setObjectName("btnDark"); refresh_ring.clicked.connect(self._refresh_ring)
        ring_header.addWidget(refresh_ring)
        ring_l.addLayout(ring_header)
        self.ring_container = QVBoxLayout()
        ring_l.addLayout(self.ring_container); ring_l.addStretch()
        self.tabs.addTab(ring_w, "🕸 Fraud Rings")

        # ── Audit Trail Tab ──
        audit_w = QWidget(); audit_l = QVBoxLayout(audit_w); audit_l.setContentsMargins(0,0,0,0)
        audit_header = QFrame(); audit_header.setStyleSheet("border-bottom:1px solid #1a1d23;")
        ahx = QHBoxLayout(audit_header); ahx.setContentsMargins(20,12,20,12)
        ahx.addWidget(QLabel("Audit Trail")); ahx.addStretch()
        export_audit = QPushButton("⤓ Export Audit Log"); export_audit.setObjectName("btnGreen"); export_audit.clicked.connect(self._export_audit)
        ahx.addWidget(export_audit); audit_l.addWidget(audit_header)
        self.audit_table = QTableWidget(); self.audit_table.setColumnCount(5)
        self.audit_table.setHorizontalHeaderLabels(["Timestamp","Action","Type","Entity","Details"])
        self.audit_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.audit_table.verticalHeader().setVisible(False); self.audit_table.setShowGrid(False)
        self.audit_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        for i,w in enumerate([160,120,90,140,0]):
            if w: self.audit_table.setColumnWidth(i,w)
        audit_l.addWidget(self.audit_table); self.tabs.addTab(audit_w, "📋 Audit Trail")

        self.splitter.addWidget(self.tabs)

        # Detail panel
        self.detail_panel = QScrollArea(); self.detail_panel.setWidgetResizable(True)
        self.detail_panel.setStyleSheet("background:#1a1d23;border-left:1px solid #2a2d35;")
        self.detail_content = QWidget()
        self.detail_layout = QVBoxLayout(self.detail_content)
        self.detail_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.detail_panel.setWidget(self.detail_content)
        self.detail_panel.setVisible(False)
        self.splitter.addWidget(self.detail_panel)
        self.splitter.setSizes([1000, 0])

        ml.addWidget(self.splitter)
        self._refresh_table(); self._refresh_actors(); self._refresh_dashboard(); self._refresh_audit()

    # ── Table ──
    def _get_filtered(self):
        q = self.search_edit.text().lower(); ft = self.f_type.currentData(); fth = self.f_threat.currentData(); fs = self.f_source.currentData()
        result = []
        for i in self.store.iocs:
            if ft != "ALL" and i.get("type") != ft: continue
            if fth != "ALL" and i.get("threatLevel") != fth: continue
            if fs != "ALL" and not i.get("source","").startswith(fs): continue
            if q:
                s = " ".join([i.get("value",""),i.get("id","")," ".join(i.get("tags",[])),i.get("notes",""),i.get("source",""),i.get("country",""),(i.get("ipMeta") or {}).get("provider","")]).lower()
                if q not in s: continue
            result.append(i)
        order = ["CRITICAL","HIGH","MEDIUM","LOW"]
        if self.sort_col == "threatLevel": result.sort(key=lambda x: order.index(x.get("threatLevel","LOW")), reverse=not self.sort_asc)
        elif self.sort_col in ("hitCount","blockCount"): result.sort(key=lambda x: x.get(self.sort_col,0), reverse=not self.sort_asc)
        elif self.sort_col == "lastSeen": result.sort(key=lambda x: x.get("lastSeen",""), reverse=not self.sort_asc)
        elif self.sort_col == "value": result.sort(key=lambda x: x.get("value","").lower(), reverse=not self.sort_asc)
        return result

    def _refresh_table(self):
        self._update_stats()
        self.filtered_iocs = self._get_filtered()
        self.count_lbl.setText(f"{len(self.filtered_iocs)} results")
        ac = {"Suspended":"#ff1744","Escalate":"#ff9100","Investigate":"#82b1ff","Quarantine":"#ea80fc","Monitor":"#69f0ae","Compromised List":"#ff1744","Purchase Tool":"#ffd180"}
        self.table.setRowCount(len(self.filtered_iocs))
        for row, ioc in enumerate(self.filtered_iocs):
            self.table.setRowHeight(row, 36)
            it = QTableWidgetItem(ioc["id"][-8:]); it.setFont(MONO); it.setForeground(QColor("#6b7280")); self.table.setItem(row,0,it)
            t = IOC_TYPES.get(ioc["type"],("?","#999")); ti = QTableWidgetItem(t[0]); ti.setForeground(QColor(t[1])); self.table.setItem(row,1,ti)
            vi = QTableWidgetItem(ioc["value"]); vi.setFont(MONO); self.table.setItem(row,2,vi)
            tl = THREAT_LEVELS.get(ioc["threatLevel"],("#999","#222")); thi = QTableWidgetItem(ioc["threatLevel"]); thi.setForeground(QColor(tl[0])); self.table.setItem(row,3,thi)
            src = ioc.get("source","").split(":")[0]; si = QTableWidgetItem(src); si.setForeground(QColor("#ff80ab" if "AutoThreat" in src else "#80d8ff" if "Upstream" in src else "#9ca3af")); self.table.setItem(row,4,si)
            hc = ioc.get("hitCount",0); hi = QTableWidgetItem(f"{hc:,}"); hi.setFont(MONO); hi.setForeground(QColor("#ff9100" if hc>1000 else "#ffea00" if hc>100 else "#69f0ae")); hi.setTextAlignment(Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter); self.table.setItem(row,5,hi)
            act = ioc.get("action","Monitor"); ai = QTableWidgetItem(act[:20]); ai.setForeground(QColor(ac.get(act,"#69f0ae"))); self.table.setItem(row,6,ai)
            li = QTableWidgetItem(ioc.get("lastSeen","")); li.setForeground(QColor("#9ca3af")); self.table.setItem(row,7,li)
            tai = QTableWidgetItem("⚡" if ioc.get("linkedTA") else "—"); tai.setForeground(QColor("#ff80ab" if ioc.get("linkedTA") else "#2a2d35")); tai.setTextAlignment(Qt.AlignmentFlag.AlignCenter); self.table.setItem(row,8,tai)
            cc = len(ioc.get("correlations",[])); ci = QTableWidgetItem(str(cc) if cc else "—"); ci.setFont(MONO); ci.setForeground(QColor("#ff80ab" if cc else "#3a3d45")); ci.setTextAlignment(Qt.AlignmentFlag.AlignCenter); self.table.setItem(row,9,ci)
            cost = ioc.get("toolCost"); coi = QTableWidgetItem(f"${cost:,.2f}" if cost else "—"); coi.setForeground(QColor("#ffd180" if cost else "#2a2d35")); self.table.setItem(row,10,coi)

    def _on_row_click(self, row, col):
        if row < len(self.filtered_iocs): self.selected_ioc_id = self.filtered_iocs[row]["id"]; self._show_detail(self.filtered_iocs[row])
    def _on_header_click(self, col):
        m = {2:"value",3:"threatLevel",5:"hitCount",7:"lastSeen"}
        if col in m:
            k = m[col]
            if self.sort_col == k: self.sort_asc = not self.sort_asc
            else: self.sort_col = k; self.sort_asc = False
            self._refresh_table()

    def _update_stats(self):
        iocs = self.store.iocs
        self.stat_total.set_value(len(iocs)); self.stat_critical.set_value(sum(1 for i in iocs if i.get("threatLevel")=="CRITICAL"))
        self.stat_active.set_value(sum(1 for i in iocs if i.get("status")=="active"))
        self.stat_hits.set_value(f"{sum(i.get('hitCount',0) for i in iocs):,}")
        self.stat_suspended.set_value(sum(1 for i in iocs if i.get("action")=="Suspended"))
        self.stat_vpn.set_value(sum(1 for i in iocs if i.get("ipMeta") and i["ipMeta"].get("ipType") in ["VPN","Proxy","Tor Exit"]))

    # ── Detail Panel (fits without horizontal scroll) ──
    def _show_detail(self, ioc):
        self.detail_panel.setVisible(True)
        self.splitter.setSizes([900, 480])
        while self.detail_layout.count():
            c = self.detail_layout.takeAt(0)
            if c.widget(): c.widget().deleteLater()

        # Header
        hw = QWidget(); hx = QHBoxLayout(hw); hx.setContentsMargins(0,0,0,0)
        hx.addWidget(_selectable(ioc["id"], "color:#6b7280;font-size:13px;font-family:Consolas;"))
        tl = THREAT_LEVELS[ioc["threatLevel"]]
        thl = QLabel(ioc["threatLevel"]); thl.setStyleSheet(f"color:{tl[0]};font-weight:700;font-size:12px;padding:2px 8px;background:{tl[1]};border-radius:4px;")
        hx.addWidget(thl); hx.addStretch()
        eb = QPushButton("✏ Edit"); eb.setObjectName("btnDark"); eb.clicked.connect(lambda: self._edit_ioc(ioc["id"])); hx.addWidget(eb)
        db = QPushButton("🗑"); db.setStyleSheet("color:#ff1744;background:transparent;border:1px solid #ff174450;border-radius:6px;padding:5px 10px;font-size:12px;")
        db.clicked.connect(lambda: self._delete_ioc(ioc["id"])); hx.addWidget(db)
        xb = QPushButton("✕"); xb.setObjectName("btnDark"); xb.clicked.connect(self._close_detail); hx.addWidget(xb)
        self.detail_layout.addWidget(hw)

        t = IOC_TYPES.get(ioc["type"],("?","#999"))
        self.detail_layout.addWidget(QLabel(f"<span style='color:{t[1]};font-weight:600'>{t[0]}</span>"))
        self.detail_layout.addWidget(_selectable(ioc["value"], "font-size:16px;font-weight:700;font-family:Consolas;margin:4px 0 8px 0;"))

        if ioc.get("country"): self.detail_layout.addWidget(QLabel(f"Country: {ioc['country']}"))
        if ioc.get("linkedTA"):
            ta = self.store.get_actor(ioc["linkedTA"])
            if ta: self.detail_layout.addWidget(QLabel(f"<span style='color:#ff80ab'>⚡ Threat Actor: {ta['name']}</span>"))

        # Stats
        sw = QWidget(); sg = QGridLayout(sw); sg.setContentsMargins(0,8,0,8)
        for ci,(label,val) in enumerate([("Hits",f"{ioc.get('hitCount',0):,}"),("Suspended",str(ioc.get("blockCount",0))),("First",ioc.get("firstSeen","")),("Last",ioc.get("lastSeen",""))]):
            sg.addWidget(StatCard(label,val,"#ff1744" if label=="Suspended" and ioc.get("blockCount",0)>0 else "#e8eaed"),0,ci)
        self.detail_layout.addWidget(sw)

        if ioc.get("toolCost"): self.detail_layout.addWidget(QLabel(f"<span style='color:#ffd180;font-size:14px;font-weight:700'>💰 Cost: ${ioc['toolCost']:,.2f}</span>"))

        # IP enrichment
        if ioc["type"] == "IP":
            ew = QWidget(); el = QHBoxLayout(ew); el.setContentsMargins(0,4,0,4)
            for label,svc,color in [("▶ IPinfo","ipinfo","#82b1ff"),("▶ AbuseIPDB","abuseipdb","#ff9100")]:
                b = QPushButton(label); b.setStyleSheet(f"color:{color};border:1px solid {color}40;background:transparent;padding:4px 10px;border-radius:4px;font-size:10px;font-weight:700;")
                b.clicked.connect(lambda _,s=svc: self._enrich(ioc["id"],s)); el.addWidget(b)
            el.addStretch(); self.detail_layout.addWidget(ew)
            meta = ioc.get("ipMeta")
            if meta:
                g = QGroupBox("IP Intelligence"); gl = QGridLayout(g)
                fields = [("Type",meta.get("ipType","—")),("Provider",meta.get("provider","—")),("ASN",meta.get("asn","—")),("Country",meta.get("country","—")),("Hosting","Yes" if meta.get("hosting") else "No")]
                if meta.get("abuseScore") is not None: fields.append(("Abuse",f"{meta['abuseScore']}%"))
                for idx,(label,val) in enumerate(fields):
                    r,c = divmod(idx,2)
                    gl.addWidget(QLabel(f"<span style='color:#6b7280;font-size:10px'>{label}</span>"),r*2,c*2)
                    gl.addWidget(_selectable(str(val),"font-size:13px;"),r*2+1,c*2)
                self.detail_layout.addWidget(g)

        self.detail_layout.addWidget(QLabel(f"Source: {ioc.get('source','—')}"))

        # Action
        aw = QWidget(); al = QHBoxLayout(aw); al.setContentsMargins(0,8,0,8)
        ac = QComboBox(); ac.addItems(ACTIONS); ac.setCurrentText(ioc.get("action","Monitor"))
        ac.currentTextChanged.connect(lambda v: self._upd(ioc["id"],"action",v))
        al.addWidget(QLabel("Action:")); al.addWidget(ac); al.addStretch()
        self.detail_layout.addWidget(aw)

        if ioc.get("tags"):
            self.detail_layout.addWidget(_selectable("Tags: "+", ".join(ioc["tags"]), "color:#9ca3af;font-size:12px;"))
        if ioc.get("notes"):
            self.detail_layout.addWidget(_selectable(ioc["notes"], "color:#c0c4cc;font-size:13px;background:#12141a;padding:10px;border-radius:8px;border:1px solid #2a2d35;"))

        corr = self.store.get_correlated(ioc)
        if corr:
            self.detail_layout.addWidget(QLabel(f"<span style='color:#ff1744;font-weight:600'>⚡ Correlated IOCs ({len(corr)})</span>"))
            for c in corr:
                ct = IOC_TYPES.get(c["type"],("?","#999"))
                self.detail_layout.addWidget(_selectable(f"  {c['id']}  {ct[0]}  {c['value']}", "color:#c0c4cc;font-size:12px;background:#12141a;padding:6px 10px;border-radius:6px;border:1px solid #2a2d35;margin:2px 0;"))
        self.detail_layout.addStretch()

    def _close_detail(self):
        self.detail_panel.setVisible(False); self.splitter.setSizes([1400,0]); self.selected_ioc_id = None

    def _upd(self, ioc_id, key, val):
        self.store.update_ioc(ioc_id, key, val); self.audit.log("Updated", "IOC", ioc_id, f"{key}={val}")
        self._trigger_save(); self._refresh_table()

    def _edit_ioc(self, ioc_id):
        ioc = self.store.get_ioc(ioc_id)
        if not ioc: return
        dlg = EditIOCDialog(self, ioc)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            for k,v in dlg.get_updated().items(): ioc[k] = v
            self.store.save(); self.audit.log("Edited","IOC",ioc_id,f"Updated fields")
            self._refresh_table(); self._show_detail(ioc); self._refresh_audit()

    def _delete_ioc(self, ioc_id):
        if QMessageBox.question(self,"Delete IOC",f"Delete {ioc_id}?",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.store.iocs = [i for i in self.store.iocs if i["id"] != ioc_id]
            for i in self.store.iocs:
                if ioc_id in i.get("correlations",[]): i["correlations"].remove(ioc_id)
            self.store.save(); self.audit.log("Deleted","IOC",ioc_id,""); self._close_detail(); self._refresh_table(); self._refresh_audit()

    def _delete_ta(self, ta_id):
        if QMessageBox.question(self,"Delete TA","Delete this Threat Actor?",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.store.actors = [a for a in self.store.actors if a["id"] != ta_id]
            for i in self.store.iocs:
                if i.get("linkedTA") == ta_id: i["linkedTA"] = None
            self.store.save(); self.audit.log("Deleted","TA",ta_id,""); self._refresh_actors(); self._close_detail(); self._refresh_audit()

    def _enrich(self, ioc_id, service):
        ioc = self.store.get_ioc(ioc_id)
        if not ioc: return
        res = enrich_ipinfo(ioc["value"],self.settings.ipinfo_key) if service=="ipinfo" else enrich_abuseipdb(ioc["value"],self.settings.abuseipdb_key)
        if not res["success"]: QMessageBox.warning(self,"Error",res["error"]); return
        if not ioc.get("ipMeta"): ioc["ipMeta"] = {"ipType":"","provider":"","asn":"","country":"","hosting":False}
        for k in ["provider","asn","country","ipType"]:
            if res["data"].get(k): ioc["ipMeta"][k] = res["data"][k]
        if res["data"].get("hosting"): ioc["ipMeta"]["hosting"] = True
        if res["data"].get("abuseScore") is not None: ioc["ipMeta"]["abuseScore"] = res["data"]["abuseScore"]
        self.store.save(); self.audit.log("Enriched","IOC",ioc_id,service)
        self._refresh_table(); self._show_detail(ioc); self._refresh_audit()

    # ── Threat Actors ──
    def _refresh_actors(self):
        while self.ta_list_layout.count():
            c = self.ta_list_layout.takeAt(0)
            if c.widget(): c.widget().deleteLater()
        if not self.store.actors:
            l = QLabel("No threat actors yet."); l.setStyleSheet("color:#6b7280;padding:40px;"); l.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.ta_list_layout.addWidget(l); return
        for actor in self.store.actors:
            card = QFrame(); card.setStyleSheet("background:#12141a;border:1px solid #2a2d35;border-radius:10px;padding:14px;margin:4px 20px;")
            cl = QVBoxLayout(card); hdr = QHBoxLayout()
            hdr.addWidget(QLabel(f"<span style='font-size:15px;font-weight:700'>{actor['name']}</span>"))
            tl = THREAT_LEVELS.get(actor.get("risk","HIGH"),("#ff9100","#3d2a00"))
            rl = QLabel(actor.get("risk","HIGH")); rl.setStyleSheet(f"color:{tl[0]};font-weight:700;font-size:11px;padding:2px 8px;background:{tl[1]};border-radius:4px;")
            hdr.addWidget(rl); hdr.addStretch()
            linked = self.store.get_linked_iocs(actor["id"])
            hdr.addWidget(QLabel(f"<span style='color:#6b7280;font-size:11px'>{len(linked)} IOCs</span>"))
            dtb = QPushButton("🗑"); dtb.setStyleSheet("color:#ff1744;background:transparent;border:none;font-size:14px;")
            dtb.clicked.connect(lambda _,tid=actor["id"]: self._delete_ta(tid)); hdr.addWidget(dtb)
            cl.addLayout(hdr)
            if actor.get("reportRef"): cl.addWidget(QLabel(f"<span style='color:#6b7280;font-size:11px'>Report: {actor['reportRef']}</span>"))
            if actor.get("recommendedTools"):
                tl2 = QLabel(f"⚙ Tools: {actor['recommendedTools']}"); tl2.setStyleSheet("color:#ffd180;font-size:11px;"); tl2.setWordWrap(True); cl.addWidget(tl2)
            self.ta_list_layout.addWidget(card)

    # ── Dashboard ──
    def _refresh_dashboard(self):
        while self.dash_layout.count():
            c = self.dash_layout.takeAt(0)
            if c.widget(): c.widget().deleteLater()

        iocs = self.store.iocs
        self.dash_layout.addWidget(QLabel("<span style='font-size:18px;font-weight:700'>📊 Dashboard</span>"))

        # Metrics
        mg = QWidget(); mgl = QGridLayout(mg); mgl.setSpacing(12)
        metrics = [
            ("Total IOCs", len(iocs), "#82b1ff"),
            ("Critical", sum(1 for i in iocs if i.get("threatLevel")=="CRITICAL"), "#ff1744"),
            ("Suspended", sum(1 for i in iocs if i.get("action")=="Suspended"), "#ff9100"),
            ("Compromised List", sum(1 for i in iocs if i.get("action")=="Compromised List"), "#ff1744"),
            ("Threat Actors", len(self.store.actors), "#ce93d8"),
            ("Fraud Rings", sum(1 for i in iocs if len(i.get("correlations",[]))>=2), "#ff80ab"),
        ]
        for idx,(label,val,color) in enumerate(metrics):
            mgl.addWidget(StatCard(label, str(val), color), 0, idx)
        self.dash_layout.addWidget(mg)

        # IOC by type
        self.dash_layout.addWidget(QLabel("<span style='font-size:14px;font-weight:600;margin-top:16px'>IOCs by Type</span>"))
        type_counts = Counter(i.get("type","?") for i in iocs)
        for ioc_type, count in type_counts.most_common():
            t = IOC_TYPES.get(ioc_type, ("?","#999"))
            bar_w = int(min(count / max(len(iocs),1) * 400, 400))
            bl = QLabel(f"<span style='color:{t[1]}'>{t[0]}</span>  <span style='color:#e8eaed;font-weight:700'>{count}</span>")
            bl.setStyleSheet(f"background:linear-gradient(90deg, {t[1]}30 {bar_w}px, transparent {bar_w}px);padding:6px 12px;border-radius:4px;margin:2px 0;")
            self.dash_layout.addWidget(bl)

        # Threat level distribution
        self.dash_layout.addWidget(QLabel("<span style='font-size:14px;font-weight:600;margin-top:16px'>Threat Level Distribution</span>"))
        for level in ["CRITICAL","HIGH","MEDIUM","LOW"]:
            count = sum(1 for i in iocs if i.get("threatLevel")==level)
            tl = THREAT_LEVELS[level]
            bar_w = int(min(count / max(len(iocs),1) * 400, 400))
            bl = QLabel(f"<span style='color:{tl[0]}'>{level}</span>  <span style='color:#e8eaed;font-weight:700'>{count}</span>")
            bl.setStyleSheet(f"background:linear-gradient(90deg, {tl[0]}30 {bar_w}px, transparent {bar_w}px);padding:6px 12px;border-radius:4px;margin:2px 0;")
            self.dash_layout.addWidget(bl)

        # Actions
        self.dash_layout.addWidget(QLabel("<span style='font-size:14px;font-weight:600;margin-top:16px'>Actions Taken</span>"))
        act_counts = Counter(i.get("action","?") for i in iocs)
        act_colors = {"Suspended":"#ff1744","Monitor":"#69f0ae","Investigate":"#82b1ff","Escalate":"#ff9100","Quarantine":"#ea80fc","Compromised List":"#ff1744","Purchase Tool":"#ffd180"}
        for act, count in act_counts.most_common():
            color = act_colors.get(act, "#9ca3af")
            bar_w = int(min(count / max(len(iocs),1) * 400, 400))
            bl = QLabel(f"<span style='color:{color}'>{act}</span>  <span style='color:#e8eaed;font-weight:700'>{count}</span>")
            bl.setStyleSheet(f"background:linear-gradient(90deg, {color}30 {bar_w}px, transparent {bar_w}px);padding:6px 12px;border-radius:4px;margin:2px 0;")
            self.dash_layout.addWidget(bl)

        # Recent activity
        self.dash_layout.addWidget(QLabel("<span style='font-size:14px;font-weight:600;margin-top:16px'>Recent Activity</span>"))
        recent = self.audit.get_recent(10)
        if recent:
            for e in recent:
                ts = e["timestamp"][:19].replace("T"," ")
                al = QLabel(f"<span style='color:#6b7280'>{ts}</span>  <span style='color:#e8eaed'>{e['action']}</span> {e['entityType']} <span style='color:#82b1ff'>{e['entityId'][-8:]}</span> {e.get('details','')}")
                al.setStyleSheet("font-size:12px;padding:4px 0;")
                self.dash_layout.addWidget(al)
        else:
            self.dash_layout.addWidget(QLabel("<span style='color:#6b7280'>No activity recorded yet.</span>"))

        # Export button
        exp_btn = QPushButton("📄 Export Dashboard as PDF"); exp_btn.setObjectName("btnDark")
        exp_btn.clicked.connect(self._export_dashboard_pdf)
        self.dash_layout.addWidget(exp_btn)
        self.dash_layout.addStretch()

    def _export_dashboard_pdf(self):
        try:
            from PyQt6.QtGui import QTextDocument
            from PyQt6.QtPrintSupport import QPrinter
        except:
            QMessageBox.warning(self, "PDF Export", "PDF export requires PyQt6 print support."); return
        p, _ = QFileDialog.getSaveFileName(self, "Export Dashboard PDF", f"dashboard-{datetime.now().strftime('%Y-%m-%d')}.pdf", "PDF (*.pdf)")
        if not p: return
        iocs = self.store.iocs
        html = f"<h1>Fraud IOC Tracker — Dashboard Report</h1><p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>"
        html += f"<h2>Summary</h2><p>Total IOCs: {len(iocs)} | Critical: {sum(1 for i in iocs if i.get('threatLevel')=='CRITICAL')} | Suspended: {sum(1 for i in iocs if i.get('action')=='Suspended')} | Threat Actors: {len(self.store.actors)}</p>"
        html += "<h2>IOCs by Type</h2><table border='1' cellpadding='4'><tr><th>Type</th><th>Count</th></tr>"
        for t,c in Counter(i.get("type","?") for i in iocs).most_common():
            tn = IOC_TYPES.get(t,("?","#999"))[0]; html += f"<tr><td>{tn}</td><td>{c}</td></tr>"
        html += "</table>"
        html += "<h2>Recent Activity</h2><table border='1' cellpadding='4'><tr><th>Time</th><th>Action</th><th>Entity</th><th>Details</th></tr>"
        for e in self.audit.get_recent(20):
            html += f"<tr><td>{e['timestamp'][:19]}</td><td>{e['action']}</td><td>{e['entityId']}</td><td>{e.get('details','')}</td></tr>"
        html += "</table>"
        printer = QPrinter(QPrinter.PrinterMode.HighResolution); printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat); printer.setOutputFileName(p)
        doc = QTextDocument(); doc.setHtml(html); doc.print(printer)
        QMessageBox.information(self, "PDF Exported", f"Dashboard saved to {p}")

    # ── Fraud Ring Graph ──
    def _refresh_ring(self):
        while self.ring_container.count():
            c = self.ring_container.takeAt(0)
            if c.widget(): c.widget().deleteLater()
        graph = FraudRingWidget(self.store.iocs)
        graph.setMinimumHeight(500)
        self.ring_container.addWidget(graph)

    # ── Audit Trail ──
    def _refresh_audit(self):
        entries = self.audit.get_recent(200)
        self.audit_table.setRowCount(len(entries))
        for row, e in enumerate(entries):
            self.audit_table.setRowHeight(row, 32)
            ts = QTableWidgetItem(e["timestamp"][:19].replace("T"," ")); ts.setForeground(QColor("#6b7280")); self.audit_table.setItem(row,0,ts)
            ai = QTableWidgetItem(e["action"]); ai.setForeground(QColor("#e8eaed")); self.audit_table.setItem(row,1,ai)
            ti = QTableWidgetItem(e["entityType"]); ti.setForeground(QColor("#9ca3af")); self.audit_table.setItem(row,2,ti)
            ei = QTableWidgetItem(e["entityId"]); ei.setFont(MONO); ei.setForeground(QColor("#82b1ff")); self.audit_table.setItem(row,3,ei)
            di = QTableWidgetItem(e.get("details","")); di.setForeground(QColor("#6b7280")); self.audit_table.setItem(row,4,di)

    def _export_audit(self):
        p, _ = QFileDialog.getSaveFileName(self, "Export Audit Log", f"audit-log-{datetime.now().strftime('%Y-%m-%d')}.csv", "CSV (*.csv)")
        if p: self.audit.export_csv(p); QMessageBox.information(self, "Exported", f"Audit log saved to {p}")

    # ── Dialogs ──
    def _add_ioc(self):
        dlg = AddIOCDialog(self, self.store.actors, self.store.iocs)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            ioc = dlg.get_ioc()
            if ioc["value"]:
                for cid in ioc.get("correlations",[]):
                    other = self.store.get_ioc(cid)
                    if other and ioc["id"] not in other.get("correlations",[]): other.setdefault("correlations",[]).append(ioc["id"])
                self.store.add_ioc(ioc); self.audit.log("Added","IOC",ioc["id"],f"{ioc['type']}: {ioc['value'][:40]}")
                self._refresh_table(); self._refresh_dashboard(); self._refresh_audit()

    def _add_ta(self):
        dlg = AddTADialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            a = dlg.get_actor()
            if a["name"]: self.store.add_actor(a); self.audit.log("Added","TA",a["id"],a["name"]); self._refresh_actors(); self._refresh_dashboard(); self._refresh_audit()

    def _open_settings(self):
        dlg = SettingsDialog(self, self.settings)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            dlg.apply_settings(); self.store = DataStore(self.settings); self.store.load()
            self.audit = AuditTrail(self.settings.get_data_dir())
            self._refresh_table(); self._refresh_actors(); self._refresh_dashboard(); self._refresh_audit()

    def _export(self):
        p, _ = QFileDialog.getSaveFileName(self, "Export", f"ioc-export-{datetime.now().strftime('%Y-%m-%d')}.json", "JSON (*.json)")
        if p: self.store.export_to_file(p); self.audit.log("Exported","System","all",f"{len(self.store.iocs)} IOCs"); self._refresh_audit(); QMessageBox.information(self,"Export",f"Exported {len(self.store.iocs)} IOCs")

    def _import(self):
        p, _ = QFileDialog.getOpenFileName(self, "Import", "", "JSON (*.json)")
        if p:
            ci,ca = self.store.import_from_file(p,merge=False); self.store.save()
            self.audit.log("Imported","System","all",f"{ci} IOCs, {ca} TAs")
            self._refresh_table(); self._refresh_actors(); self._close_detail(); self._refresh_dashboard(); self._refresh_audit()

    def _merge(self):
        p, _ = QFileDialog.getOpenFileName(self, "Merge", "", "JSON (*.json)")
        if p:
            ci,ca = self.store.import_from_file(p,merge=True); self.store.save()
            self.audit.log("Merged","System","all",f"{ci} IOCs, {ca} TAs")
            self._refresh_table(); self._refresh_actors(); self._refresh_dashboard(); self._refresh_audit()

    def _ingest_csv(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select CSV", "", "CSV (*.csv);;TSV (*.tsv);;All (*.*)")
        if not p: return
        sd = self.settings.get_data_dir() if hasattr(self.settings,'get_data_dir') else ""
        dlg = CSVImportDialog(self, p, sd)
        if dlg.exec() != QDialog.DialogCode.Accepted: return
        mapping = dlg.get_mapping()
        if not mapping: QMessageBox.warning(self,"No Mapping","Map at least one column."); return
        source = dlg.get_source(); sn = dlg.get_save_name()
        if sn and sd: save_mapping(sd, sn, {str(k):v for k,v in mapping.items()})
        result = ingest_csv(p, mapping, source)
        existing = {(i["type"],i["value"]) for i in self.store.iocs}; added = 0
        for ioc in result["iocs"]:
            key = (ioc["type"],ioc["value"])
            if key not in existing: self.store.iocs.append(ioc); existing.add(key); added += 1
            else:
                for ex in self.store.iocs:
                    if ex["type"]==ioc["type"] and ex["value"]==ioc["value"]:
                        ex["hitCount"] += ioc["hitCount"]
                        if ioc["lastSeen"] > ex.get("lastSeen",""): ex["lastSeen"] = ioc["lastSeen"]
                        for cid in ioc.get("correlations",[]):
                            if cid not in ex.get("correlations",[]): ex.setdefault("correlations",[]).append(cid)
                        break
        self.store.save(); self.audit.log("CSV Ingest","System","csv",f"{added} new IOCs from {os.path.basename(p)}")
        self._refresh_table(); self._close_detail(); self._refresh_dashboard(); self._refresh_audit()
        s = result["stats"]; QMessageBox.information(self,"CSV Ingest",f"Rows: {s['rows']}\nNew IOCs: {added}\nCorrelations: {s['links_found']}")

    def _auto_correlate(self):
        if not self.store.iocs: QMessageBox.information(self,"Auto-Correlate","Add IOCs first."); return
        links = auto_correlate(self.store.iocs)
        if not links: QMessageBox.information(self,"Auto-Correlate","No new correlations found."); return
        applied = apply_correlations(self.store.iocs, links); self.store.save()
        self.audit.log("Auto-Correlate","System","all",f"{len(links)} correlations found")
        self._refresh_table(); self._refresh_dashboard(); self._refresh_audit()
        reasons = {}
        for _,_,r in links: cat = r.split(":")[0].strip(); reasons[cat] = reasons.get(cat,0)+1
        summary = "\n".join([f"  • {r}: {c}" for r,c in reasons.items()])
        QMessageBox.information(self,"Auto-Correlate",f"Found {len(links)} correlations:\n\n{summary}")

    # ── Auto-save ──
    def _trigger_save(self):
        self.autosave_lbl.setText("● Saving..."); self.autosave_lbl.setStyleSheet("color:#ff9100;font-size:10px;"); self.save_timer.start(800)
    def _do_save(self):
        self.store.save(); self.autosave_lbl.setText("● Auto-saved"); self.autosave_lbl.setStyleSheet("color:#2e7d32;font-size:10px;")


def main():
    app = QApplication(sys.argv); app.setStyle("Fusion"); app.setStyleSheet(DARK_STYLE)
    p = QPalette()
    p.setColor(QPalette.ColorRole.Window, QColor("#0d0f13")); p.setColor(QPalette.ColorRole.WindowText, QColor("#e8eaed"))
    p.setColor(QPalette.ColorRole.Base, QColor("#12141a")); p.setColor(QPalette.ColorRole.AlternateBase, QColor("#1a1d23"))
    p.setColor(QPalette.ColorRole.Text, QColor("#e8eaed")); p.setColor(QPalette.ColorRole.Button, QColor("#2a2d35"))
    p.setColor(QPalette.ColorRole.ButtonText, QColor("#e8eaed")); p.setColor(QPalette.ColorRole.Highlight, QColor("#ff1744"))
    p.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff")); app.setPalette(p)
    w = MainWindow(); w.show(); sys.exit(app.exec())

if __name__ == "__main__":
    main()
