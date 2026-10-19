"""
╔══════════════════════════════════════════════════════════════════╗
║                 BASTION — Advanced Security Suite               ║
║            by King Sabatsu Kisuke  ·  Version 4.0 ELITE         ║
╠══════════════════════════════════════════════════════════════════╣
║  Tools (left sidebar navigation):                                ║
║    ◈ Dashboard — live threat intel + IDS feed                   ║
║    ⬡ Self-Adapting AI Firewall (decay, CIDR, TTL rules)         ║
║    ⌁ IDS — sliding-window signatures + severity escalation      ║
║    ⚔ Attack Sandbox — Red Team Simulator                        ║
║    ⌕ Port Scanner + Port Closer                                 ║
║    ⛨ Vulnerability Scanner (15 checks)                          ║
║    ⚿ Password Analyzer + Hash Cracker                           ║
║    ⌬ Encryption Vault — AES-256 text/file/video/batch           ║
║    ⊕ CVE Threat Intelligence Lookup (cached, cross-wired)       ║
║    ⌖ Network Device Mapper (cross-wired to Vuln + CVE)          ║
║    ◎ Geo Threat Tracker — rotating globe + IP geolocation       ║
║    ⚙ Settings — tunable thresholds, NVD API key                 ║
║    ▤ Activity Log — filter/search/export (TXT/CSV/JSON)         ║
╠══════════════════════════════════════════════════════════════════╣
║  WHAT'S NEW IN v4.0:                                             ║
║    • SQLite persistence — rules, scores, log, CVE cache, geo    ║
║      cache, and settings all survive restart (bastion.db)       ║
║    • Settings tab — tune AI thresholds & NVD API key live       ║
║    • Cross-wiring — jump from Vuln Scan / Net Mapper straight   ║
║      into a CVE lookup or vulnerability scan on a found host    ║
║    • Geo Threat Tracker — geolocates blocked/flagged IPs on a   ║
║      rotating wireframe globe (ip-api.com, no key required)     ║
║    • Sidebar navigation shell, glyph icon set (no emoji)        ║
╠══════════════════════════════════════════════════════════════════╣
║  HOW TO RUN:                                                    ║
║    pip install psutil requests cryptography                     ║
║    python bastion_v4.py                                         ║
╚══════════════════════════════════════════════════════════════════╝
  ⚠  LEGAL NOTICE: For educational & personal use only.
     Only test on systems and networks you OWN or have permission.
"""

# ═══════════════════════════════════════════════════════════════
#  STDLIB IMPORTS
# ═══════════════════════════════════════════════════════════════
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import socket
import hashlib
import re
import math
import json
import csv
import os
import io
import time
import random
import subprocess
import ipaddress
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict, deque

# ═══════════════════════════════════════════════════════════════
#  OPTIONAL IMPORTS
# ═══════════════════════════════════════════════════════════════
try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes, padding as sym_padding
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    import base64
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

# ═══════════════════════════════════════════════════════════════
#  DESIGN SYSTEM — Gold + Obsidian Luxury Theme
# ═══════════════════════════════════════════════════════════════
BG0      = "#000000"
BG1      = "#08090c"
BG2      = "#0e1117"
BG3      = "#141820"
GOLD     = "#c8972a"
GOLD_LT  = "#f0c050"
GOLD_DIM = "#5a4010"
CRIMSON  = "#8b0000"
RED      = "#d63031"
RED_LT   = "#ff6b6b"
GREEN    = "#00b894"
GREEN_LT = "#55efc4"
CYAN     = "#0097a7"
CYAN_LT  = "#00e5ff"
AMBER    = "#f39c12"
PURPLE   = "#9b59b6"
TEXT     = "#c8d6e5"
TEXT_DIM = "#4a5568"
WHITE    = "#f0f4f8"
BORDER   = "#1a2035"

F_TITLE  = ("Georgia",     18, "bold")
F_HEAD   = ("Georgia",     12, "bold")
F_MONO   = ("Courier New", 10)
F_MONO_S = ("Courier New",  9)
F_MONO_L = ("Courier New", 12, "bold")
F_TINY   = ("Courier New",  8)
F_BIG    = ("Courier New", 22, "bold")

COMMON_PASSWORDS = [
    "password","123456","123456789","qwerty","abc123","password1",
    "111111","letmein","monkey","dragon","master","sunshine",
    "princess","welcome","shadow","superman","michael","football",
    "charlie","aa123456","donald","password2","qwerty123","iloveyou",
    "admin","login","hello","whatever","pass","1234","12345",
    "test","sample","guest","root","toor","alpine","changeme",
    "default","secret","manager","mustang","access","baseball",
    "batman","trustno1","ranger","solo","starwars",
]

PORT_SERVICES = {
    20:"FTP-Data", 21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP",
    53:"DNS", 67:"DHCP", 80:"HTTP", 110:"POP3", 119:"NNTP",
    143:"IMAP", 161:"SNMP", 194:"IRC", 443:"HTTPS", 445:"SMB",
    1433:"MSSQL", 1521:"Oracle", 3306:"MySQL", 3389:"RDP",
    5432:"PostgreSQL", 5900:"VNC", 6379:"Redis", 8080:"HTTP-Alt",
    8443:"HTTPS-Alt", 9200:"Elasticsearch", 27017:"MongoDB",
    11211:"Memcached", 2181:"ZooKeeper", 9092:"Kafka", 5672:"RabbitMQ",
}


# ═══════════════════════════════════════════════════════════════
#  EVENT BUS  — decoupled pub/sub for engine ↔ UI communication
# ═══════════════════════════════════════════════════════════════
class EventBus:
    """Thread-safe publish/subscribe event bus."""
    def __init__(self):
        self._subscribers: dict[str, list] = defaultdict(list)
        self._lock = threading.Lock()

    def subscribe(self, event_type: str, callback):
        with self._lock:
            self._subscribers[event_type].append(callback)

    def publish(self, event_type: str, data=None):
        with self._lock:
            subs = list(self._subscribers.get(event_type, []))
        for cb in subs:
            try:
                cb(data)
            except Exception:
                pass

bus = EventBus()


# ═══════════════════════════════════════════════════════════════
#  DATABASE — SQLite persistence layer (v4.0)
# ═══════════════════════════════════════════════════════════════
class Database:
    """
    Thread-safe SQLite persistence for the whole suite.

    Tables:
      settings      — key/value store (thresholds, NVD API key, etc.)
      fw_rules      — firewall manual + AI rules
      fw_state      — blocked_ips / whitelisted / ip_scores / ip_profiles (JSON blob)
      activity_log  — mirrored activity log records
      cve_cache     — cached NVD lookups, keyed by query, with TTL
      geo_cache     — cached IP → lat/lon/city/country geolocation
    One connection guarded by a lock — fine for a desktop app's write volume.
    """
    def __init__(self, path="bastion.db"):
        # One-time migration: adopt a database created under the old name
        if path == "bastion.db" and not os.path.exists(path) \
                and os.path.exists("king_sabatsu.db"):
            try:
                os.rename("king_sabatsu.db", path)
            except OSError:
                path = "king_sabatsu.db"
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        with self._lock, self._conn as c:
            c.execute("""CREATE TABLE IF NOT EXISTS settings (
                            key TEXT PRIMARY KEY, value TEXT)""")
            c.execute("""CREATE TABLE IF NOT EXISTS fw_rules (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            rule_id TEXT, action TEXT, target TEXT, type TEXT,
                            reason TEXT, source TEXT, time TEXT, expires TEXT)""")
            c.execute("""CREATE TABLE IF NOT EXISTS fw_state (
                            key TEXT PRIMARY KEY, value TEXT)""")
            c.execute("""CREATE TABLE IF NOT EXISTS activity_log (
                            seq INTEGER PRIMARY KEY, time TEXT, source TEXT,
                            level TEXT, message TEXT)""")
            c.execute("""CREATE TABLE IF NOT EXISTS cve_cache (
                            query TEXT PRIMARY KEY, payload TEXT, fetched_at TEXT)""")
            c.execute("""CREATE TABLE IF NOT EXISTS geo_cache (
                            ip TEXT PRIMARY KEY, lat REAL, lon REAL,
                            city TEXT, country TEXT, fetched_at TEXT)""")

    # ── settings ─────────────────────────────────────────────────
    def get_setting(self, key, default=None):
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key, value):
        with self._lock, self._conn as c:
            c.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                      (key, str(value)))

    def all_settings(self):
        with self._lock:
            rows = self._conn.execute("SELECT key,value FROM settings").fetchall()
        return {r["key"]: r["value"] for r in rows}

    # ── firewall rules ──────────────────────────────────────────
    def save_fw_rule(self, rule):
        with self._lock, self._conn as c:
            c.execute("""INSERT INTO fw_rules
                (rule_id,action,target,type,reason,source,time,expires)
                VALUES (?,?,?,?,?,?,?,?)""",
                (str(rule.get("id")), rule.get("action"), rule.get("target"),
                 rule.get("type"), rule.get("reason"), rule.get("source","MANUAL"),
                 rule.get("time"), rule.get("expires")))

    def delete_fw_rule(self, rule_id):
        with self._lock, self._conn as c:
            c.execute("DELETE FROM fw_rules WHERE rule_id=?", (str(rule_id),))

    def load_fw_rules(self):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM fw_rules").fetchall()
        return [dict(r) for r in rows]

    def clear_fw_rules(self):
        with self._lock, self._conn as c:
            c.execute("DELETE FROM fw_rules")

    def save_fw_state(self, blocked_ips, whitelisted, ip_scores, ip_profiles):
        payload = {
            "blocked_ips": list(blocked_ips),
            "whitelisted": list(whitelisted),
            "ip_scores":   dict(ip_scores),
            "ip_profiles": {ip: {
                "attack_types": dict(p["attack_types"]),
                "ports_seen":   list(p["ports_seen"]),
                "first_seen":   p["first_seen"],
                "last_seen":    p["last_seen"],
                "total_events": p["total_events"],
            } for ip, p in ip_profiles.items()},
        }
        with self._lock, self._conn as c:
            c.execute("INSERT INTO fw_state(key,value) VALUES('snapshot',?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                      (json.dumps(payload),))

    def load_fw_state(self):
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM fw_state WHERE key='snapshot'").fetchone()
        if not row:
            return None
        try:
            return json.loads(row["value"])
        except Exception:
            return None

    # ── activity log ────────────────────────────────────────────
    def save_log_record(self, record):
        with self._lock, self._conn as c:
            c.execute("""INSERT OR REPLACE INTO activity_log
                (seq,time,source,level,message) VALUES (?,?,?,?,?)""",
                (record["seq"], record["time"], record["source"],
                 record["level"], record["message"]))

    def load_log_records(self, limit=2000):
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM activity_log ORDER BY seq DESC LIMIT ?",
                (limit,)).fetchall()
        return [dict(r) for r in rows]

    def clear_log(self):
        with self._lock, self._conn as c:
            c.execute("DELETE FROM activity_log")

    # ── CVE cache ────────────────────────────────────────────────
    def cve_cache_get(self, query, max_age_hours=24):
        with self._lock:
            row = self._conn.execute(
                "SELECT payload, fetched_at FROM cve_cache WHERE query=?",
                (query,)).fetchone()
        if not row:
            return None
        try:
            fetched = datetime.fromisoformat(row["fetched_at"])
        except Exception:
            return None
        if datetime.now() - fetched > timedelta(hours=max_age_hours):
            return None
        try:
            return json.loads(row["payload"])
        except Exception:
            return None

    def cve_cache_set(self, query, results):
        with self._lock, self._conn as c:
            c.execute("INSERT INTO cve_cache(query,payload,fetched_at) VALUES(?,?,?) "
                      "ON CONFLICT(query) DO UPDATE SET payload=excluded.payload, "
                      "fetched_at=excluded.fetched_at",
                      (query, json.dumps(results, default=str), datetime.now().isoformat()))

    # ── geo cache ────────────────────────────────────────────────
    def geo_cache_get(self, ip):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM geo_cache WHERE ip=?", (ip,)).fetchone()
        return dict(row) if row else None

    def geo_cache_set(self, ip, lat, lon, city, country):
        with self._lock, self._conn as c:
            c.execute("INSERT INTO geo_cache(ip,lat,lon,city,country,fetched_at) "
                      "VALUES(?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET "
                      "lat=excluded.lat, lon=excluded.lon, city=excluded.city, "
                      "country=excluded.country, fetched_at=excluded.fetched_at",
                      (ip, lat, lon, city, country, datetime.now().isoformat()))


# Singleton — created before engines so they can hydrate from it
db = Database()


# ═══════════════════════════════════════════════════════════════
#  ACTIVITY LOG — thread-safe singleton
# ═══════════════════════════════════════════════════════════════
class ActivityLog:
    """
    Central, thread-safe activity log.

    Improvements over v3.0:
    • Stores structured records (not just strings)
    • Deque with configurable cap (default 2000)
    • Publishes 'log.entry' events on the bus so the UI stays decoupled
    • Helpers for CSV and JSON export
    """
    LEVELS = ("DEBUG", "INFO", "WARN", "ERROR", "CRITICAL")

    def __init__(self, maxlen=2000):
        self._records: deque[dict] = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._seq = 0
        self._hydrate()

    def _hydrate(self):
        """Load recent records from SQLite so history survives restart."""
        try:
            rows = db.load_log_records(limit=2000)
        except Exception:
            rows = []
        with self._lock:
            for r in reversed(rows):  # oldest first, appendleft each so newest ends up at front
                self._records.appendleft(r)
                self._seq = max(self._seq, r.get("seq", 0))

    def write(self, source: str, message: str, level: str = "INFO"):
        level = level.upper()
        if level not in self.LEVELS:
            level = "INFO"
        with self._lock:
            self._seq += 1
            record = {
                "seq":     self._seq,
                "time":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source":  source.upper()[:12],
                "level":   level,
                "message": message,
            }
            self._records.appendleft(record)
        try:
            db.save_log_record(record)
        except Exception:
            pass
        bus.publish("log.entry", record)
        return record

    def get_all(self) -> list[dict]:
        with self._lock:
            return list(self._records)

    def filtered(self, level=None, source=None, search=None) -> list[dict]:
        with self._lock:
            records = list(self._records)
        if level and level != "ALL":
            records = [r for r in records if r["level"] == level]
        if source and source != "ALL":
            records = [r for r in records if r["source"] == source]
        if search:
            lo = search.lower()
            records = [r for r in records
                       if lo in r["message"].lower() or lo in r["source"].lower()]
        return records

    def clear(self):
        with self._lock:
            self._records.clear()
        try:
            db.clear_log()
        except Exception:
            pass

    def export_txt(self, path: str):
        records = self.get_all()
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# Bastion — Activity Log Export\n")
            f.write(f"# Generated: {datetime.now()}\n")
            f.write(f"# Records:   {len(records)}\n\n")
            for r in reversed(records):
                f.write(
                    f"[{r['time']}] [{r['level']:8}] {r['source']:12} {r['message']}\n"
                )

    def export_csv(self, path: str):
        records = self.get_all()
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["seq","time","level","source","message"])
            w.writeheader()
            w.writerows(reversed(records))

    def export_json(self, path: str):
        records = self.get_all()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(list(reversed(records)), f, indent=2)

    def sources(self) -> list[str]:
        with self._lock:
            return sorted({r["source"] for r in self._records})

# Singleton
log = ActivityLog()
# Convenience alias
def glog(source, message, level="INFO"):
    log.write(source, message, level)


# ═══════════════════════════════════════════════════════════════
#  AI FIREWALL ENGINE  (v3.1 upgrades)
# ═══════════════════════════════════════════════════════════════
class AIFirewallEngine:
    """
    Self-adapting firewall.

    v3.1 improvements:
    • Score decay — threat scores fade over time (IPs can recover)
    • Behavioral fingerprinting — track per-IP attack profile
    • Adaptive threshold — auto-tightens when attack volume is high
    • Rule expiry — auto-rules can expire after a configurable TTL
    • Country/subnet block stubs (CIDR matching)
    • Detailed rule hit history
    """

    SCORE_MAP = {
        "PORT_SCAN":    12,
        "BRUTE_FORCE":  28,
        "FLOOD":        18,
        "EXPLOIT":      45,
        "RECON":         8,
        "ANOMALY":      20,
        "DATA_EXFIL":   35,
    }

    def __init__(self):
        self.rules:       list[dict] = []
        self.auto_rules:  list[dict] = []
        self.blocked_ips: set[str]   = set()
        self.whitelisted: set[str]   = set()
        self.cidr_blocks: list       = []          # list of ipaddress.IPv4Network

        self.ip_scores:   dict[str, float]    = defaultdict(float)
        self.ip_profiles: dict[str, dict]     = defaultdict(self._empty_profile)
        self.port_hits:   dict[str, int]      = defaultdict(int)
        self.attack_log:  deque[dict]         = deque(maxlen=2000)

        # Score decay — run every 30 seconds
        self._decay_factor  = 0.92   # multiply score by this each cycle
        self._decay_interval = 30

        self.thresholds = {
            "port_scan_rate":   10,
            "brute_force_rate":  5,
            "flood_rate":       50,
            "auto_block_score": 75,
            "adaptive_min":     40,  # floor when adaptive tightens
        }
        self._load_settings_overrides()
        self.stats = {
            "total_seen": 0, "total_blocked": 0,
            "auto_blocked": 0, "rules_generated": 0,
        }
        self._rule_id   = 0
        self._lock      = threading.Lock()

        self._hydrate_from_db()
        self._start_decay_thread()
        self._start_persist_thread()

    def _hydrate_from_db(self):
        """Load persisted rules and threat state from SQLite (v4.0)."""
        try:
            for r in db.load_fw_rules():
                rule = {
                    "id": r["rule_id"], "action": r["action"], "target": r["target"],
                    "type": r["type"], "reason": r["reason"], "source": r["source"],
                    "time": r["time"], "expires": r["expires"], "hits": 0, "history": [],
                }
                if r["source"] == "AI":
                    self.auto_rules.append(rule)
                else:
                    self.rules.append(rule)
                    try:
                        self._rule_id = max(self._rule_id, int(r["rule_id"]))
                    except (TypeError, ValueError):
                        pass
        except Exception:
            pass
        try:
            state = db.load_fw_state()
            if state:
                self.blocked_ips.update(state.get("blocked_ips", []))
                self.whitelisted.update(state.get("whitelisted", []))
                for ip, score in state.get("ip_scores", {}).items():
                    self.ip_scores[ip] = score
                for ip, p in state.get("ip_profiles", {}).items():
                    prof = self._empty_profile()
                    prof["attack_types"].update(p.get("attack_types", {}))
                    prof["ports_seen"] = set(p.get("ports_seen", []))
                    prof["first_seen"] = p.get("first_seen")
                    prof["last_seen"]  = p.get("last_seen")
                    prof["total_events"] = p.get("total_events", 0)
                    self.ip_profiles[ip] = prof
        except Exception:
            pass

    def _start_persist_thread(self):
        """Periodically snapshot scores/profiles to SQLite (every 20s)."""
        def loop():
            while True:
                time.sleep(20)
                try:
                    with self._lock:
                        db.save_fw_state(self.blocked_ips, self.whitelisted,
                                         self.ip_scores, self.ip_profiles)
                except Exception:
                    pass
        threading.Thread(target=loop, daemon=True).start()

    # ── Internal helpers ────────────────────────────────────────
    @staticmethod
    def _empty_profile():
        return {
            "attack_types": defaultdict(int),
            "ports_seen":   set(),
            "first_seen":   None,
            "last_seen":    None,
            "total_events": 0,
        }

    def _load_settings_overrides(self):
        """Pull any persisted tuning values (from the Settings tab) at startup."""
        try:
            v = db.get_setting("fw_auto_block_score")
            if v is not None: self.thresholds["auto_block_score"] = float(v)
            v = db.get_setting("fw_adaptive_min")
            if v is not None: self.thresholds["adaptive_min"] = float(v)
            v = db.get_setting("fw_decay_factor")
            if v is not None: self._decay_factor = float(v)
        except Exception:
            pass

    def apply_settings(self, auto_block_score=None, adaptive_min=None, decay_factor=None):
        """Called live from the Settings tab to retune the engine without restart."""
        with self._lock:
            if auto_block_score is not None:
                self.thresholds["auto_block_score"] = float(auto_block_score)
                db.set_setting("fw_auto_block_score", auto_block_score)
            if adaptive_min is not None:
                self.thresholds["adaptive_min"] = float(adaptive_min)
                db.set_setting("fw_adaptive_min", adaptive_min)
            if decay_factor is not None:
                self._decay_factor = float(decay_factor)
                db.set_setting("fw_decay_factor", decay_factor)

    def _start_decay_thread(self):
        def decay_loop():
            while True:
                time.sleep(self._decay_interval)
                self._apply_decay()
        t = threading.Thread(target=decay_loop, daemon=True)
        t.start()

    def _apply_decay(self):
        with self._lock:
            for ip in list(self.ip_scores):
                self.ip_scores[ip] *= self._decay_factor
                if self.ip_scores[ip] < 1.0:
                    del self.ip_scores[ip]
            # Adaptive threshold: relax if total seen / min threat
            active_threats = sum(1 for s in self.ip_scores.values() if s >= 25)
            if active_threats > 20:
                self.thresholds["auto_block_score"] = max(
                    self.thresholds["adaptive_min"],
                    self.thresholds["auto_block_score"] - 5)
            elif active_threats < 5:
                self.thresholds["auto_block_score"] = min(
                    90,
                    self.thresholds["auto_block_score"] + 1)

    # ── Rule management ─────────────────────────────────────────
    def _next_rule_id(self):
        self._rule_id += 1
        return self._rule_id

    def add_manual_rule(self, action, target, rule_type, reason="Manual",
                        ttl_minutes=None):
        """Add a manual firewall rule. ttl_minutes=None means permanent."""
        expires = None
        if ttl_minutes:
            expires = (datetime.now() + timedelta(minutes=ttl_minutes)).isoformat()
        rule = {
            "id":      self._next_rule_id(),
            "action":  action.upper(),
            "target":  target,
            "type":    rule_type.upper(),
            "reason":  reason,
            "source":  "MANUAL",
            "time":    datetime.now().strftime("%H:%M:%S"),
            "expires": expires,
            "hits":    0,
            "history": [],
        }
        with self._lock:
            self.rules.append(rule)
        try:
            db.save_fw_rule(rule)
        except Exception:
            pass
        glog("FIREWALL", f"Rule added: {action} {rule_type} {target} — {reason}")
        return rule

    def remove_expired_rules(self):
        now = datetime.now()
        with self._lock:
            before = len(self.rules)
            self.rules = [
                r for r in self.rules
                if not r.get("expires") or
                   datetime.fromisoformat(r["expires"]) > now
            ]
            removed = before - len(self.rules)
        if removed:
            glog("FIREWALL", f"{removed} expired rule(s) removed", "INFO")

    def add_cidr_block(self, cidr: str, reason="Manual CIDR block"):
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
            self.cidr_blocks.append({"net": net, "reason": reason,
                                     "time": datetime.now().strftime("%H:%M:%S")})
            glog("FIREWALL", f"CIDR block added: {cidr} — {reason}")
            return True
        except ValueError as e:
            glog("FIREWALL", f"Invalid CIDR {cidr}: {e}", "ERROR")
            return False

    # ── Packet evaluation ────────────────────────────────────────
    def evaluate(self, src_ip: str, dst_port: int, proto: str) -> tuple[str, str]:
        """Evaluate a packet. Returns (action, reason)."""
        with self._lock:
            self.stats["total_seen"] += 1

        # Whitelist
        if src_ip in self.whitelisted:
            return "ALLOW", "Whitelisted"

        # Hard-blocked IPs
        if src_ip in self.blocked_ips:
            with self._lock:
                self.stats["total_blocked"] += 1
            return "BLOCK", "AI auto-block"

        # CIDR blocks
        try:
            addr = ipaddress.IPv4Address(src_ip)
            for entry in self.cidr_blocks:
                if addr in entry["net"]:
                    with self._lock:
                        self.stats["total_blocked"] += 1
                    return "BLOCK", f"CIDR block: {entry['net']} — {entry['reason']}"
        except ValueError:
            pass

        # Manual rules (check expiry inline)
        now = datetime.now()
        with self._lock:
            active_rules = [
                r for r in self.rules
                if not r.get("expires") or
                   datetime.fromisoformat(r["expires"]) > now
            ]
        for rule in active_rules:
            hit = False
            t = rule["type"]
            if t == "IP"    and rule["target"] == src_ip:         hit = True
            if t == "PORT"  and rule["target"] == str(dst_port):  hit = True
            if t == "PROTO" and rule["target"].upper() == proto.upper(): hit = True
            if hit:
                with self._lock:
                    rule["hits"] += 1
                    rule["history"].append(
                        {"time": now.strftime("%H:%M:%S"), "ip": src_ip, "port": dst_port})
                    if len(rule["history"]) > 50:
                        rule["history"] = rule["history"][-50:]
                if rule["action"] == "BLOCK":
                    with self._lock:
                        self.stats["total_blocked"] += 1
                    return "BLOCK", f"Rule #{rule['id']}: {rule['reason']}"
                return "ALLOW", f"Rule #{rule['id']}: {rule['reason']}"

        return "ALLOW", "Default ALLOW"

    # ── AI learning ──────────────────────────────────────────────
    def learn_from_attack(self, src_ip: str, attack_type: str,
                          severity: float) -> tuple[bool, dict | None]:
        """Update threat model; returns (newly_blocked, rule_or_None)."""
        delta = self.SCORE_MAP.get(attack_type, 10) * severity

        with self._lock:
            self.ip_scores[src_ip] += delta
            score = self.ip_scores[src_ip]

            # Update behavioral profile
            prof = self.ip_profiles[src_ip]
            prof["attack_types"][attack_type] += 1
            prof["total_events"] += 1
            prof["last_seen"] = datetime.now().isoformat()
            if not prof["first_seen"]:
                prof["first_seen"] = prof["last_seen"]

            entry = {
                "time":     datetime.now().strftime("%H:%M:%S"),
                "ip":       src_ip,
                "type":     attack_type,
                "severity": severity,
                "score":    round(score, 1),
            }
            self.attack_log.appendleft(entry)

            auto_block_threshold = self.thresholds["auto_block_score"]
            should_block = score >= auto_block_threshold and src_ip not in self.blocked_ips

        if should_block:
            with self._lock:
                self.blocked_ips.add(src_ip)
                self.stats["auto_blocked"] += 1
                self.stats["rules_generated"] += 1
                rule_id = f"AI-{self.stats['rules_generated']}"
                rule = {
                    "id":      rule_id,
                    "action":  "BLOCK",
                    "target":  src_ip,
                    "type":    "IP",
                    "reason":  f"AI auto-block | {attack_type} | score={score:.0f}",
                    "source":  "AI",
                    "time":    datetime.now().strftime("%H:%M:%S"),
                    "expires": None,
                    "hits":    0,
                    "history": [],
                }
                self.auto_rules.append(rule)
            try:
                db.save_fw_rule(rule)
            except Exception:
                pass
            glog("FIREWALL", f"AI AUTO-BLOCKED {src_ip} (score={score:.0f})", "WARN")
            bus.publish("firewall.auto_block", {"ip": src_ip, "score": score})
            return True, rule

        bus.publish("firewall.threat_update", {"ip": src_ip, "score": score, "type": attack_type})
        return False, None

    def get_threat_level(self, ip: str) -> tuple[str, str]:
        score = self.ip_scores.get(ip, 0)
        if score >= 75: return "CRITICAL", RED
        if score >= 50: return "HIGH",     AMBER
        if score >= 25: return "MEDIUM",   GOLD
        if score >  0:  return "LOW",      GREEN
        return "NONE", TEXT_DIM

    def get_profile_summary(self, ip: str) -> str:
        prof = self.ip_profiles.get(ip)
        if not prof:
            return "No profile data"
        types = ", ".join(f"{k}×{v}" for k,v in prof["attack_types"].items())
        return (f"Events: {prof['total_events']} | Types: {types or 'none'} | "
                f"First: {(prof['first_seen'] or 'unknown')[:19]} | "
                f"Last: {(prof['last_seen'] or 'unknown')[:19]}")

    def unblock_ip(self, ip: str):
        with self._lock:
            self.blocked_ips.discard(ip)
            self.ip_scores.pop(ip, None)
        removed_ids = [r["id"] for r in self.auto_rules if r["target"] == ip]
        self.auto_rules = [r for r in self.auto_rules if r["target"] != ip]
        try:
            for rid in removed_ids:
                db.delete_fw_rule(rid)
        except Exception:
            pass
        glog("FIREWALL", f"IP {ip} unblocked and score reset")

    def export_rules(self, path: str):
        data = {
            "exported": datetime.now().isoformat(),
            "manual_rules": self.rules,
            "auto_rules":   self.auto_rules,
            "blocked_ips":  list(self.blocked_ips),
            "whitelisted":  list(self.whitelisted),
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def import_rules(self, path: str) -> int:
        with open(path) as f:
            data = json.load(f)
        loaded = 0
        for r in data.get("manual_rules", []):
            self.rules.append(r)
            loaded += 1
        self.blocked_ips.update(data.get("blocked_ips", []))
        self.whitelisted.update(data.get("whitelisted", []))
        glog("FIREWALL", f"Imported {loaded} rules from {path}")
        return loaded


# ═══════════════════════════════════════════════════════════════
#  IDS ENGINE  (v3.1 upgrades)
# ═══════════════════════════════════════════════════════════════
class IDSEngine:
    """
    Intrusion Detection System.

    v3.1 improvements:
    • Sliding-window rate limiters (time-bucketed, not raw counters)
    • 5 new signatures: Telnet probe, FTP brute, SNMP walk,
      Memcached amplification, ZooKeeper probe
    • Severity escalation: repeated triggers → severity++
    • Per-IP session context (tracks state across packets)
    • Publishes alerts on bus
    """

    SIGNATURES = [
        {"name": "NULL Scan",            "pattern": "flags==0",            "severity": 2},
        {"name": "SYN Flood",            "pattern": "high_syn_rate",        "severity": 3},
        {"name": "Port Scan",            "pattern": "many_ports_one_src",   "severity": 2},
        {"name": "SSH Brute Force",      "pattern": "many_port22_fails",    "severity": 3},
        {"name": "SMB Exploit",          "pattern": "port445_anomaly",      "severity": 4},
        {"name": "DNS Tunneling",        "pattern": "large_dns_payload",    "severity": 3},
        {"name": "ICMP Flood",           "pattern": "high_icmp_rate",       "severity": 2},
        {"name": "HTTP Flood",           "pattern": "high_http_rate",       "severity": 2},
        {"name": "Malformed Packet",     "pattern": "bad_header",           "severity": 2},
        {"name": "Data Exfiltration",    "pattern": "large_outbound",       "severity": 4},
        # NEW in v3.1
        {"name": "Telnet Probe",         "pattern": "port23_access",        "severity": 3},
        {"name": "FTP Brute Force",      "pattern": "many_port21_fails",    "severity": 3},
        {"name": "SNMP Walk",            "pattern": "port161_sweep",        "severity": 2},
        {"name": "Memcached Amplif.",    "pattern": "port11211_udp",        "severity": 4},
        {"name": "ZooKeeper Probe",      "pattern": "port2181_access",      "severity": 3},
    ]

    # Sliding window config (seconds → max hits)
    WINDOWS = {
        "port_scan":   (60, 15),    # 15 unique ports in 60s
        "ssh_brute":   (60, 8),     # 8 attempts in 60s
        "ftp_brute":   (60, 8),
        "http_flood":  (30, 40),
        "icmp_flood":  (10, 20),
        "total_rate":  (60, 200),   # overall packets from one IP
    }

    def __init__(self):
        self.alerts:  deque[dict]               = deque(maxlen=1000)
        self._windows: dict[str, dict]          = defaultdict(lambda: defaultdict(deque))
        self._sessions: dict[str, dict]         = defaultdict(self._empty_session)
        self._escalation: dict[str, dict]       = defaultdict(lambda: defaultdict(int))
        self.stats = {"total_alerts": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        self._lock = threading.Lock()

    @staticmethod
    def _empty_session():
        return {"unique_ports": set(), "total": 0, "first": None}

    def _window_count(self, ip: str, key: str, window_secs: int) -> int:
        """Return hit count in rolling window, pruning old entries."""
        q = self._windows[ip][key]
        cutoff = time.monotonic() - window_secs
        while q and q[0] < cutoff:
            q.popleft()
        q.append(time.monotonic())
        return len(q)

    def analyze(self, src_ip: str, dst_port: int, proto: str,
                payload_size: int = 0) -> list[dict]:
        ts = datetime.now().strftime("%H:%M:%S")
        alerts = []

        with self._lock:
            sess = self._sessions[src_ip]
            sess["total"] += 1
            sess["unique_ports"].add(dst_port)
            if not sess["first"]:
                sess["first"] = ts

            unique_ports = len(sess["unique_ports"])

            # ── Port scan ──────────────────────────────────────
            port_rate = self._window_count(src_ip, "port_scan", 60)
            if unique_ports > 15 or port_rate > self.WINDOWS["port_scan"][1]:
                self._escalation[src_ip]["port_scan"] += 1
                sev = min(4, 2 + self._escalation[src_ip]["port_scan"] // 3)
                alerts.append(self._make_alert(
                    src_ip, "Port Scan",
                    f"{unique_ports} unique ports | {port_rate}/min", sev, ts))
                firewall.learn_from_attack(src_ip, "PORT_SCAN", sev / 2)

            # ── SSH brute force ────────────────────────────────
            if dst_port == 22:
                ssh_rate = self._window_count(src_ip, "ssh_brute", 60)
                if ssh_rate > self.WINDOWS["ssh_brute"][1]:
                    self._escalation[src_ip]["ssh_brute"] += 1
                    sev = min(4, 3 + self._escalation[src_ip]["ssh_brute"] // 5)
                    alerts.append(self._make_alert(
                        src_ip, "SSH Brute Force",
                        f"{ssh_rate} SSH attempts/min", sev, ts))
                    firewall.learn_from_attack(src_ip, "BRUTE_FORCE", sev / 2)

            # ── FTP brute force ────────────────────────────────
            if dst_port == 21:
                ftp_rate = self._window_count(src_ip, "ftp_brute", 60)
                if ftp_rate > self.WINDOWS["ftp_brute"][1]:
                    alerts.append(self._make_alert(
                        src_ip, "FTP Brute Force",
                        f"{ftp_rate} FTP attempts/min", 3, ts))
                    firewall.learn_from_attack(src_ip, "BRUTE_FORCE", 1.4)

            # ── SMB probe ─────────────────────────────────────
            if dst_port == 445:
                smb_rate = self._window_count(src_ip, "smb", 30)
                if smb_rate > 5:
                    alerts.append(self._make_alert(
                        src_ip, "SMB Exploit Probe",
                        f"Repeated SMB access × {smb_rate}", 4, ts))
                    firewall.learn_from_attack(src_ip, "EXPLOIT", 2.0)

            # ── Telnet probe ───────────────────────────────────
            if dst_port == 23:
                alerts.append(self._make_alert(
                    src_ip, "Telnet Probe",
                    "Plaintext protocol access attempt", 3, ts))
                firewall.learn_from_attack(src_ip, "RECON", 1.2)

            # ── SNMP walk ─────────────────────────────────────
            if dst_port == 161:
                snmp_rate = self._window_count(src_ip, "snmp", 30)
                if snmp_rate > 10:
                    alerts.append(self._make_alert(
                        src_ip, "SNMP Walk",
                        f"Possible SNMP enumeration × {snmp_rate}", 2, ts))
                    firewall.learn_from_attack(src_ip, "RECON", 0.8)

            # ── Memcached amplification ────────────────────────
            if dst_port == 11211:
                alerts.append(self._make_alert(
                    src_ip, "Memcached Amplif.",
                    "UDP amplification vector (port 11211)", 4, ts))
                firewall.learn_from_attack(src_ip, "FLOOD", 2.5)

            # ── ZooKeeper probe ───────────────────────────────
            if dst_port == 2181:
                alerts.append(self._make_alert(
                    src_ip, "ZooKeeper Probe",
                    "Unauthenticated ZooKeeper access attempt", 3, ts))
                firewall.learn_from_attack(src_ip, "EXPLOIT", 1.5)

            # ── Large payload / exfiltration ───────────────────
            if payload_size > 8192:
                alerts.append(self._make_alert(
                    src_ip, "Data Exfiltration",
                    f"Oversized payload: {payload_size} bytes", 4, ts))
                firewall.learn_from_attack(src_ip, "DATA_EXFIL", 2.0)

            # ── HTTP flood ────────────────────────────────────
            if dst_port in (80, 8080, 443, 8443):
                http_rate = self._window_count(src_ip, "http_flood", 30)
                if http_rate > self.WINDOWS["http_flood"][1]:
                    alerts.append(self._make_alert(
                        src_ip, "HTTP Flood",
                        f"{http_rate} HTTP requests in 30s", 3, ts))
                    firewall.learn_from_attack(src_ip, "FLOOD", 1.5)

            # ── Record and publish ─────────────────────────────
            for alert in alerts:
                self.alerts.appendleft(alert)
                self.stats["total_alerts"] += 1
                sev = alert["severity"]
                if sev >= 4:    self.stats["critical"] += 1
                elif sev == 3:  self.stats["high"] += 1
                elif sev == 2:  self.stats["medium"] += 1
                else:           self.stats["low"] += 1
                glog("IDS", f"{alert['name']} from {src_ip}: {alert['detail']}",
                     alert["level"])
                bus.publish("ids.alert", alert)

        return alerts

    def _make_alert(self, ip, name, detail, severity, ts) -> dict:
        sev_labels = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
        return {
            "time": ts, "ip": ip, "name": name,
            "detail": detail, "severity": severity,
            "level": sev_labels.get(severity, "MEDIUM"),
        }

    def clear_session(self, ip: str):
        with self._lock:
            self._sessions.pop(ip, None)
            self._windows.pop(ip, None)
            self._escalation.pop(ip, None)


# ═══════════════════════════════════════════════════════════════
#  SANDBOX ENGINE
# ═══════════════════════════════════════════════════════════════
class SandboxEngine:
    ATTACK_TYPES = [
        {"name": "SYN Port Scan",       "type": "PORT_SCAN",   "severity": 1.0},
        {"name": "SSH Brute Force",      "type": "BRUTE_FORCE", "severity": 1.5},
        {"name": "HTTP Flood",           "type": "FLOOD",       "severity": 1.2},
        {"name": "SMB Exploit Probe",    "type": "EXPLOIT",     "severity": 2.0},
        {"name": "DNS Amplification",    "type": "FLOOD",       "severity": 1.3},
        {"name": "ICMP Ping Sweep",      "type": "RECON",       "severity": 0.8},
        {"name": "FTP Brute Force",      "type": "BRUTE_FORCE", "severity": 1.4},
        {"name": "RDP Scan",             "type": "PORT_SCAN",   "severity": 1.1},
        {"name": "SQL Injection Probe",  "type": "EXPLOIT",     "severity": 2.0},
        {"name": "Zero-Day Simulation",  "type": "EXPLOIT",     "severity": 2.5},
        {"name": "Data Exfiltration",    "type": "DATA_EXFIL",  "severity": 2.0},
        {"name": "Memcached Amplif.",    "type": "FLOOD",       "severity": 2.5},
    ]
    FAKE_IPS = [
        "10.0.0.{}", "192.168.100.{}", "172.16.0.{}",
        "10.10.10.{}", "192.168.50.{}", "203.0.113.{}", "198.51.100.{}"
    ]

    def __init__(self):
        self.running  = False
        self.results  = deque(maxlen=500)

    def _rand_ip(self):
        return random.choice(self.FAKE_IPS).format(random.randint(1, 254))

    def run_attack(self, attack_type_idx, count=20, delay=0.1, callback=None):
        self.running = True
        attack = self.ATTACK_TYPES[attack_type_idx]

        def worker():
            blocked = allowed = 0
            for _ in range(count):
                if not self.running:
                    break
                ip   = self._rand_ip()
                port = random.choice([21, 22, 23, 80, 161, 443, 445, 2181, 3306, 3389, 11211])
                payload = random.randint(64, 16384)
                action, reason = firewall.evaluate(ip, port, "TCP")
                auto_blocked, new_rule = firewall.learn_from_attack(
                    ip, attack["type"], attack["severity"])
                alerts = ids.analyze(ip, port, "TCP", payload)
                result = {
                    "time":    datetime.now().strftime("%H:%M:%S"),
                    "attack":  attack["name"],
                    "src_ip":  ip,
                    "port":    port,
                    "action":  action,
                    "reason":  reason,
                    "alerts":  [a["name"] for a in alerts],
                    "auto":    auto_blocked,
                    "rule":    new_rule,
                }
                self.results.appendleft(result)
                if action == "BLOCK": blocked += 1
                else: allowed += 1
                if callback:
                    callback(result)
                time.sleep(delay)

            self.running = False
            if callback:
                callback({"done": True, "blocked": blocked,
                          "allowed": allowed, "total": count})
        threading.Thread(target=worker, daemon=True).start()

    def run_full_assault(self, callback=None):
        def worker():
            self.running = True
            for i in range(len(self.ATTACK_TYPES)):
                if not self.running:
                    break
                self.run_attack(i, count=12, delay=0.04, callback=callback)
                time.sleep(1.2)
        threading.Thread(target=worker, daemon=True).start()


# ═══════════════════════════════════════════════════════════════
#  VULNERABILITY SCANNER
# ═══════════════════════════════════════════════════════════════
class VulnScanner:
    CHECKS = [
        {"name": "Telnet Open",        "port": 23,    "risk": "CRITICAL",
         "desc": "Telnet transmits data in plaintext. Replace with SSH."},
        {"name": "FTP Open",           "port": 21,    "risk": "HIGH",
         "desc": "FTP has no encryption. Use SFTP/FTPS instead."},
        {"name": "Default HTTP",       "port": 80,    "risk": "MEDIUM",
         "desc": "Unencrypted web server. Redirect to HTTPS."},
        {"name": "MySQL Exposed",      "port": 3306,  "risk": "HIGH",
         "desc": "Database port accessible. Bind to localhost only."},
        {"name": "MongoDB Exposed",    "port": 27017, "risk": "CRITICAL",
         "desc": "MongoDB with no auth is a major data breach risk."},
        {"name": "Redis Exposed",      "port": 6379,  "risk": "CRITICAL",
         "desc": "Redis often has no auth. Expose only internally."},
        {"name": "RDP Open",           "port": 3389,  "risk": "HIGH",
         "desc": "RDP is frequently brute-forced. Use VPN + NLA."},
        {"name": "SMB Open",           "port": 445,   "risk": "CRITICAL",
         "desc": "SMB is target of WannaCry/NotPetya. Disable if unused."},
        {"name": "VNC Open",           "port": 5900,  "risk": "HIGH",
         "desc": "VNC is often weakly authenticated. Use SSH tunneling."},
        {"name": "Elasticsearch",      "port": 9200,  "risk": "CRITICAL",
         "desc": "Elasticsearch has no auth by default. Massive leak risk."},
        {"name": "SNMP Open",          "port": 161,   "risk": "MEDIUM",
         "desc": "SNMP v1/v2 use community strings — easily guessed."},
        {"name": "IRC Open",           "port": 194,   "risk": "LOW",
         "desc": "IRC used by botnets for C2 communication."},
        {"name": "Memcached Exposed",  "port": 11211, "risk": "CRITICAL",
         "desc": "Memcached has no auth & can be used for DDoS amplification."},
        {"name": "ZooKeeper Exposed",  "port": 2181,  "risk": "HIGH",
         "desc": "ZooKeeper exposes cluster config. Restrict to internal only."},
        {"name": "Kafka Exposed",      "port": 9092,  "risk": "HIGH",
         "desc": "Kafka brokers should not be internet-facing."},
    ]

    def scan(self, target="127.0.0.1", timeout=0.5, callback=None):
        results = []
        for check in self.CHECKS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                found = (s.connect_ex((target, check["port"])) == 0)
                s.close()
            except Exception:
                found = False
            entry = {**check, "found": found}
            results.append(entry)
            if callback:
                callback(entry)
        return results


# ═══════════════════════════════════════════════════════════════
#  GEO LOCATOR — resolves IPs to lat/lon via ip-api.com (v4.0)
# ═══════════════════════════════════════════════════════════════
class GeoLocator:
    """
    Resolves public IPs to (lat, lon, city, country) using ip-api.com's
    free batch endpoint (no key required, ~45 req/min limit). Private /
    reserved IPs are skipped since they have no meaningful geolocation.
    Results are cached indefinitely in SQLite — a given public IP's
    location basically never changes for our purposes.
    """
    BATCH_URL = "http://ip-api.com/batch"

    @staticmethod
    def is_public(ip: str) -> bool:
        try:
            addr = ipaddress.IPv4Address(ip)
            return not (addr.is_private or addr.is_loopback or
                       addr.is_link_local or addr.is_multicast or addr.is_reserved)
        except ValueError:
            return False

    def locate_many(self, ips: list[str]) -> list[dict]:
        """Returns list of dicts: ip, lat, lon, city, country, cached(bool)."""
        results = []
        to_fetch = []
        for ip in dict.fromkeys(ips):  # de-dupe, preserve order
            if not self.is_public(ip):
                continue
            cached = None
            try:
                cached = db.geo_cache_get(ip)
            except Exception:
                pass
            if cached and cached.get("lat") is not None:
                results.append({**cached, "cached": True})
            else:
                to_fetch.append(ip)

        if to_fetch and REQUESTS_OK:
            for i in range(0, len(to_fetch), 100):  # batch API caps at 100/request
                chunk = to_fetch[i:i+100]
                try:
                    resp = requests.post(self.BATCH_URL,
                        json=[{"query": ip} for ip in chunk], timeout=10)
                    if resp.status_code == 200:
                        for item in resp.json():
                            if item.get("status") == "success":
                                ip   = item["query"]
                                lat  = item.get("lat")
                                lon  = item.get("lon")
                                city = item.get("city", "")
                                country = item.get("country", "")
                                try:
                                    db.geo_cache_set(ip, lat, lon, city, country)
                                except Exception:
                                    pass
                                results.append({
                                    "ip": ip, "lat": lat, "lon": lon,
                                    "city": city, "country": country, "cached": False,
                                })
                except Exception as e:
                    glog("GEO", f"Geolocation batch error: {e}", "ERROR")
        return results


# ═══════════════════════════════════════════════════════════════
#  GEO GLOBE — animated wireframe rotating globe (Canvas, v4.0)
# ═══════════════════════════════════════════════════════════════
class GeoGlobe:
    """
    Pure-Tkinter rotating wireframe globe: a latitude/longitude graticule
    projected orthographically onto a Canvas and continuously rotated.
    No external map assets required. Threat pins are plotted as glowing
    dots at their lat/lon and rotate with the globe; pins on the far
    side are dimmed to fake depth.
    """
    def __init__(self, canvas: tk.Canvas, cx, cy, radius):
        self.canvas = canvas
        self.cx, self.cy, self.radius = cx, cy, radius
        self.angle = 0.0
        self.pins: list[dict] = []   # {"lat":, "lon":, "label":, "severity":}
        self._tilt = math.radians(18)

    def set_pins(self, pins):
        self.pins = pins

    def _project(self, lat_deg, lon_deg):
        """Orthographic projection of a lat/lon point, returns (x, y, visible, depth)."""
        lat = math.radians(lat_deg)
        lon = math.radians(lon_deg) + self.angle
        # 3D sphere coords
        x = math.cos(lat) * math.sin(lon)
        y = math.sin(lat)
        z = math.cos(lat) * math.cos(lon)
        # tilt around x-axis for a nicer viewing angle
        y2 = y * math.cos(self._tilt) - z * math.sin(self._tilt)
        z2 = y * math.sin(self._tilt) + z * math.cos(self._tilt)
        visible = z2 > -0.15
        sx = self.cx + x * self.radius
        sy = self.cy - y2 * self.radius
        return sx, sy, visible, z2

    def draw(self):
        c = self.canvas
        c.delete("globe")
        r = self.radius
        # Outer rim
        c.create_oval(self.cx-r, self.cy-r, self.cx+r, self.cy+r,
                       outline=GOLD_DIM, width=1, tags="globe")
        # Latitude rings (every 30°)
        for lat in range(-60, 61, 30):
            pts = []
            for lon in range(0, 361, 8):
                x, y, vis, z = self._project(lat, lon)
                pts.append((x, y, vis))
            self._draw_wire(pts, CYAN if lat == 0 else GOLD_DIM, 2 if lat == 0 else 1)
        # Longitude meridians (every 30°)
        for lon in range(0, 360, 30):
            pts = []
            for lat in range(-90, 91, 8):
                x, y, vis, z = self._project(lat, lon)
                pts.append((x, y, vis))
            self._draw_wire(pts, GOLD_DIM, 1)
        # Threat pins
        for pin in self.pins:
            x, y, vis, z = self._project(pin["lat"], pin["lon"])
            sev = pin.get("severity", "LOW")
            color = {"CRITICAL": RED, "HIGH": AMBER, "MEDIUM": GOLD, "LOW": GREEN}.get(sev, CYAN_LT)
            if not vis:
                color = TEXT_DIM
            rad = 4 if vis else 2
            c.create_oval(x-rad, y-rad, x+rad, y+rad,
                          fill=color, outline="", tags="globe")
            if vis:
                c.create_oval(x-rad-2, y-rad-2, x+rad+2, y+rad+2,
                              outline=color, width=1, tags="globe")

    def _draw_wire(self, pts, color, width):
        # Draw only the segments where both endpoints face the viewer
        for i in range(len(pts) - 1):
            x1, y1, v1 = pts[i]
            x2, y2, v2 = pts[i+1]
            if v1 and v2:
                self.canvas.create_line(x1, y1, x2, y2, fill=color, width=width, tags="globe")

    def spin(self, step=0.018):
        self.angle += step
        self.draw()


# ═══════════════════════════════════════════════════════════════
#  GLOBAL SINGLETONS
# ═══════════════════════════════════════════════════════════════
firewall   = AIFirewallEngine()
geolocator = GeoLocator()
ids      = IDSEngine()
sandbox  = SandboxEngine()
vuln     = VulnScanner()

# CVE settings — tunable live from the Settings tab
NVD_API_KEY     = db.get_setting("nvd_api_key", "")
try:
    CVE_CACHE_HOURS = int(db.get_setting("cve_cache_hours", "24"))
except (TypeError, ValueError):
    CVE_CACHE_HOURS = 24


# ═══════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ═══════════════════════════════════════════════════════════════
class BastionApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("BASTION  ◈  Advanced Security Suite v4.0  —  by King Sabatsu Kisuke")
        self.root.geometry("1360x860")
        self.root.configure(bg=BG0)
        self.root.resizable(True, True)
        self.root.minsize(1100, 700)
        self.scan_running = False

        self._build_ui()
        self._start_clock()
        self._wire_bus()
        self._start_live_updates()
        self._seed_default_rules()
        self._start_globe_spin()
        glog("SYSTEM", "Bastion v4.0 initialized — all systems online", "INFO")

    # ── Bus wiring ───────────────────────────────────────────────
    def _wire_bus(self):
        """Connect bus events to UI callbacks (all marshalled via root.after)."""
        bus.subscribe("log.entry",          lambda d: self.root.after(0, lambda e=d: self._log_append(e)))
        bus.subscribe("firewall.auto_block",lambda d: self.root.after(0, lambda e=d: self._fw_on_auto_block(e)))
        bus.subscribe("ids.alert",          lambda d: self.root.after(0, lambda e=d: self._ids_on_alert(e)))

    # ── UI construction ──────────────────────────────────────────
    def _build_ui(self):
        self._build_header()
        self._build_shell()

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=BG1, height=64)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)
        tk.Frame(self.root, bg=GOLD, height=2).pack(fill=tk.X)

        left = tk.Frame(hdr, bg=BG1)
        left.pack(side=tk.LEFT, padx=20)
        tk.Label(left, text="⬡  BASTION", bg=BG1,
                 fg=GOLD_LT, font=("Georgia", 18, "bold")).pack(side=tk.LEFT)
        tk.Label(left, text="  ◈  ELITE SECURITY SUITE v4.0", bg=BG1,
                 fg=GOLD_DIM, font=("Courier New", 9)).pack(side=tk.LEFT, pady=4)
        tk.Label(left, text="   by KING SABATSU KISUKE", bg=BG1,
                 fg=CRIMSON, font=("Georgia", 9, "italic")).pack(side=tk.LEFT, pady=4)

        right = tk.Frame(hdr, bg=BG1)
        right.pack(side=tk.RIGHT, padx=20)
        self.clock_var = tk.StringVar()
        tk.Label(right, textvariable=self.clock_var, bg=BG1,
                 fg=GOLD, font=F_MONO).pack(side=tk.RIGHT, padx=16)

        self.hdr_stats = {}
        for label, color in [("THREATS", RED), ("BLOCKED", AMBER), ("ALERTS", CYAN_LT)]:
            f = tk.Frame(right, bg=BG2, padx=10, pady=4)
            f.pack(side=tk.RIGHT, padx=4)
            tk.Label(f, text=label, bg=BG2, fg=TEXT_DIM, font=F_TINY).pack()
            var = tk.StringVar(value="0")
            tk.Label(f, textvariable=var, bg=BG2, fg=color, font=F_MONO_L).pack()
            self.hdr_stats[label] = var

    # ── Sidebar nav shell (v4.0 — replaces top notebook) ──────────
    def _build_shell(self):
        style = ttk.Style()
        style.theme_use("default")
        # Treeview styling shared across all tabs
        style.configure("Treeview",
            background=BG1, foreground=TEXT, fieldbackground=BG1,
            rowheight=24, borderwidth=0, font=F_MONO_S)
        style.configure("Treeview.Heading",
            background=BG2, foreground=GOLD, font=("Courier New",8,"bold"))
        style.map("Treeview", background=[("selected", BG3)], foreground=[("selected", GOLD_LT)])
        style.configure("TProgressbar", background=GOLD, troughcolor=BG2, borderwidth=0)

        body = tk.Frame(self.root, bg=BG0)
        body.pack(fill=tk.BOTH, expand=True)

        # ── Sidebar ──────────────────────────────────────────────
        sidebar = tk.Frame(body, bg=BG1, width=210)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)
        tk.Frame(body, bg=GOLD_DIM, width=1).pack(side=tk.LEFT, fill=tk.Y)

        nav_scroll = tk.Frame(sidebar, bg=BG1)
        nav_scroll.pack(fill=tk.BOTH, expand=True, pady=(10, 4))

        pages = [
            ("dashboard", "◈", "DASHBOARD",    self._build_dashboard),
            ("firewall",  "⬡", "AI FIREWALL",  self._build_firewall),
            ("ids",       "⌁", "IDS",          self._build_ids),
            ("sandbox",   "⚔", "SANDBOX",      self._build_sandbox),
            ("scanner",   "⌕", "PORT SCANNER", self._build_portscanner),
            ("vulnscan",  "⛨", "VULN SCAN",    self._build_vulnscan),
            ("password",  "⚿", "PASSWORD",     self._build_password),
            ("vault",     "⌬", "VAULT",        self._build_vault),
            ("cve",       "⊕", "CVE LOOKUP",   self._build_cve),
            ("netmapper", "⌖", "NET MAPPER",   self._build_netmapper),
            ("geo",       "◎", "GEO TRACKER",  self._build_geotracker),
            ("settings",  "⚙", "SETTINGS",     self._build_settings),
            ("log",       "▤", "ACTIVITY LOG", self._build_log),
        ]

        # ── Content area — stacked frames, one raised at a time ────
        content_outer = tk.Frame(body, bg=BG0)
        content_outer.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.page_title_var = tk.StringVar(value="DASHBOARD")
        title_bar = tk.Frame(content_outer, bg=BG0, height=40)
        title_bar.pack(fill=tk.X)
        title_bar.pack_propagate(False)
        tk.Label(title_bar, textvariable=self.page_title_var, bg=BG0,
                 fg=GOLD_LT, font=F_HEAD, padx=20).pack(side=tk.LEFT, anchor="w")
        self._title_underline = tk.Frame(title_bar, bg=GOLD_DIM, height=1)
        self._title_underline.pack(side=tk.BOTTOM, fill=tk.X)

        content = tk.Frame(content_outer, bg=BG0)
        content.pack(fill=tk.BOTH, expand=True)

        self.pages = {}
        self.nav_buttons = {}
        for key, glyph, label, builder in pages:
            frame = tk.Frame(content, bg=BG0)
            frame.place(x=0, y=0, relwidth=1, relheight=1)
            self.pages[key] = (frame, label)
            builder(frame)

            btn = tk.Frame(nav_scroll, bg=BG1, cursor="hand2")
            btn.pack(fill=tk.X, padx=0, pady=0)
            accent = tk.Frame(btn, bg=BG1, width=3)
            accent.pack(side=tk.LEFT, fill=tk.Y)
            inner = tk.Frame(btn, bg=BG1)
            inner.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10,4), pady=9)
            gl = tk.Label(inner, text=glyph, bg=BG1, fg=GOLD, font=("Courier New", 12, "bold"))
            gl.pack(side=tk.LEFT, padx=(0,10))
            lb = tk.Label(inner, text=label, bg=BG1, fg=TEXT_DIM,
                          font=("Courier New", 9, "bold"), anchor="w")
            lb.pack(side=tk.LEFT, fill=tk.X, expand=True)
            self.nav_buttons[key] = (btn, accent, inner, gl, lb)

            for w in (btn, accent, inner, gl, lb):
                w.bind("<Button-1>", lambda e, k=key: self._show_page(k))
                w.bind("<Enter>", lambda e, k=key: self._nav_hover(k, True))
                w.bind("<Leave>", lambda e, k=key: self._nav_hover(k, False))

        tk.Frame(sidebar, bg=GOLD_DIM, height=1).pack(fill=tk.X, side=tk.BOTTOM)
        tk.Label(sidebar, text="v4.0 ELITE", bg=BG1, fg=GOLD_DIM,
                 font=F_TINY).pack(side=tk.BOTTOM, pady=8)

        self._show_page("dashboard")

    def _nav_hover(self, key, entering):
        if key == getattr(self, "_active_page", None):
            return
        btn, accent, inner, gl, lb = self.nav_buttons[key]
        bg = BG2 if entering else BG1
        for w in (btn, accent, inner, gl, lb):
            w.config(bg=bg)

    def _show_page(self, key):
        self._active_page = key
        frame, label = self.pages[key]
        frame.tkraise()
        self.page_title_var.set(label)
        for k, (btn, accent, inner, gl, lb) in self.nav_buttons.items():
            active = (k == key)
            bg = BG2 if active else BG1
            for w in (btn, accent, inner, gl, lb):
                w.config(bg=bg)
            accent.config(bg=GOLD if active else bg)
            gl.config(fg=GOLD_LT if active else GOLD)
            lb.config(fg=GOLD_LT if active else TEXT_DIM)

    def _start_globe_spin(self):
        def tick():
            if hasattr(self, "geo_globe"):
                self.geo_globe.spin()
            self.root.after(60, tick)
        self.root.after(200, tick)

    # ════════════════════════════════════════
    #  DASHBOARD TAB
    # ════════════════════════════════════════
    def _build_dashboard(self, tab):
        tk.Label(tab, text="LIVE SECURITY DASHBOARD",
                 bg=BG0, fg=GOLD_LT, font=F_TITLE, pady=12).pack()
        tk.Frame(tab, bg=GOLD, height=1).pack(fill=tk.X, padx=20)

        cards = tk.Frame(tab, bg=BG0)
        cards.pack(fill=tk.X, padx=20, pady=14)
        self.dash_vars = {}
        card_data = [
            ("TOTAL SEEN",   "0", GOLD_LT, "total_seen"),
            ("BLOCKED",      "0", RED,     "total_blocked"),
            ("AUTO-BLOCKED", "0", AMBER,   "auto_blocked"),
            ("IDS ALERTS",   "0", CYAN_LT, "ids_alerts"),
            ("RULES ACTIVE", "0", GREEN,   "rules"),
            ("AI RULES",     "0", GOLD,    "ai_rules"),
        ]
        for label, val, color, key in card_data:
            card = tk.Frame(cards, bg=BG2, padx=16, pady=14)
            card.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=6)
            tk.Label(card, text=label, bg=BG2, fg=TEXT_DIM, font=F_TINY).pack()
            tk.Frame(card, bg=GOLD_DIM, height=1).pack(fill=tk.X, pady=4)
            var = tk.StringVar(value=val)
            tk.Label(card, textvariable=var, bg=BG2, fg=color,
                     font=("Courier New", 26, "bold")).pack()
            self.dash_vars[key] = var

        split = tk.Frame(tab, bg=BG0)
        split.pack(fill=tk.BOTH, expand=True, padx=20, pady=8)

        # Threat feed
        left = tk.Frame(split, bg=BG1)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        tk.Label(left, text="⌁  THREAT INTELLIGENCE FEED",
                 bg=BG1, fg=GOLD, font=F_TINY, pady=8).pack()
        tk.Frame(left, bg=GOLD_DIM, height=1).pack(fill=tk.X)
        self.threat_feed = scrolledtext.ScrolledText(
            left, bg=BG1, fg=TEXT, font=F_MONO_S,
            height=12, relief="flat", state="disabled")
        self.threat_feed.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        for tag, color in [("critical",RED),("high",AMBER),("medium",GOLD),("ok",GREEN),("dim",TEXT_DIM)]:
            self.threat_feed.tag_config(tag, foreground=color)

        # IDS alert feed
        right = tk.Frame(split, bg=BG1)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(8, 0))
        tk.Label(right, text="⛨  IDS ALERT STREAM",
                 bg=BG1, fg=CYAN_LT, font=F_TINY, pady=8).pack()
        tk.Frame(right, bg=CYAN, height=1).pack(fill=tk.X)
        self.ids_feed = scrolledtext.ScrolledText(
            right, bg=BG1, fg=TEXT, font=F_MONO_S,
            height=12, relief="flat", state="disabled")
        self.ids_feed.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        for tag, color in [("CRITICAL",RED),("HIGH",AMBER),("MEDIUM",GOLD),("LOW",GREEN),("dim",TEXT_DIM)]:
            self.ids_feed.tag_config(tag, foreground=color)

    # ════════════════════════════════════════
    #  AI FIREWALL TAB
    # ════════════════════════════════════════
    def _build_firewall(self, tab):
        top = tk.Frame(tab, bg=BG1, pady=10)
        top.pack(fill=tk.X, padx=12, pady=(12, 0))
        tk.Label(top, text="⬡  SELF-ADAPTING AI FIREWALL v4.0",
                 bg=BG1, fg=GOLD_LT, font=F_HEAD, padx=16).pack(side=tk.LEFT)
        self.fw_ai_var = tk.StringVar(value="AI: LEARNING")
        tk.Label(top, textvariable=self.fw_ai_var, bg=BG2,
                 fg=GREEN, font=F_MONO_S, padx=10, pady=4).pack(side=tk.RIGHT, padx=16)

        # ── Rule input row ──────────────────────────────────────
        inp = tk.Frame(tab, bg=BG2, pady=10)
        inp.pack(fill=tk.X, padx=12, pady=6)

        self.fw_entries = {}
        for col, (label, key, width, default) in enumerate([
            ("TARGET:", "fw_target", 22, ""),
            ("REASON:", "fw_reason", 26, "Manual block"),
            ("TTL (min):", "fw_ttl", 8, ""),
        ]):
            tk.Label(inp, text=label, bg=BG2, fg=TEXT_DIM,
                     font=F_TINY).grid(row=0, column=col*2, padx=(12,4), sticky="w")
            e = tk.Entry(inp, bg=BG3, fg=GOLD_LT, insertbackground=GOLD,
                         font=F_MONO, width=width, relief="flat", bd=4)
            e.insert(0, default)
            e.grid(row=0, column=col*2+1, padx=4)
            self.fw_entries[key] = e

        tk.Label(inp, text="TYPE:", bg=BG2, fg=TEXT_DIM,
                 font=F_TINY).grid(row=0, column=6, padx=(12,4))
        self.fw_type = ttk.Combobox(inp, values=["IP","PORT","PROTO","CIDR"],
                                    width=8, state="readonly", font=F_MONO)
        self.fw_type.set("IP")
        self.fw_type.grid(row=0, column=7, padx=4)

        btn_f = tk.Frame(inp, bg=BG2)
        btn_f.grid(row=0, column=8, padx=16)
        self._btn(btn_f, "⊘ BLOCK",    RED,   WHITE, self._fw_add_block).pack(side=tk.LEFT, padx=3)
        self._btn(btn_f, "✔ ALLOW",    GREEN, BG0,   self._fw_add_allow).pack(side=tk.LEFT, padx=3)
        self._btn(btn_f, "◇ UNBLOCK",  AMBER, BG0,   self._fw_unblock_ip).pack(side=tk.LEFT, padx=3)
        self._btn(btn_f, "⇩ SAVE",     GOLD,  BG0,   self._fw_save).pack(side=tk.LEFT, padx=3)
        self._btn(btn_f, "▸ LOAD",     BG3,   GOLD,  self._fw_load).pack(side=tk.LEFT, padx=3)

        # ── Split layout ─────────────────────────────────────────
        split = tk.Frame(tab, bg=BG0)
        split.pack(fill=tk.BOTH, expand=True, padx=12, pady=6)

        # Left: rules table
        left = tk.Frame(split, bg=BG1)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,6))
        tk.Label(left, text="ACTIVE RULES  (★=AI  ⏱=Expiring)",
                 bg=BG1, fg=GOLD, font=F_TINY, pady=6).pack()

        cols = ("ID","Action","Type","Target","Source","Reason","Hits","Expires","Time")
        self.fw_tree = ttk.Treeview(left, columns=cols, show="headings", height=13)
        widths = [50,70,60,140,70,160,45,90,75]
        for col, w in zip(cols, widths):
            self.fw_tree.heading(col, text=col)
            self.fw_tree.column(col, width=w, anchor="center" if w<100 else "w")
        self.fw_tree.tag_configure("block",    foreground=RED)
        self.fw_tree.tag_configure("allow",    foreground=GREEN)
        self.fw_tree.tag_configure("ai_block", foreground=AMBER)
        self.fw_tree.bind("<Double-1>", self._fw_show_profile)
        fsb = ttk.Scrollbar(left, orient="vertical", command=self.fw_tree.yview)
        self.fw_tree.configure(yscrollcommand=fsb.set)
        self.fw_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
        fsb.pack(side=tk.RIGHT, fill=tk.Y)

        bot = tk.Frame(left, bg=BG1, pady=4)
        bot.pack(fill=tk.X)
        self._btn(bot, "⌫ REMOVE SELECTED", CRIMSON, WHITE, self._fw_remove).pack(side=tk.LEFT, padx=8)
        self._btn(bot, "⏱ PURGE EXPIRED",   BG3, AMBER, self._fw_purge_expired).pack(side=tk.LEFT, padx=4)

        # Right: AI panel
        right = tk.Frame(split, bg=BG1, width=250)
        right.pack(side=tk.RIGHT, fill=tk.Y)
        right.pack_propagate(False)

        tk.Label(right, text="AI THREAT SCORES",
                 bg=BG1, fg=AMBER, font=F_TINY, pady=8).pack()
        tk.Frame(right, bg=AMBER, height=1).pack(fill=tk.X)
        self.fw_scores_text = scrolledtext.ScrolledText(
            right, bg=BG1, fg=TEXT, font=F_TINY, relief="flat", state="disabled")
        self.fw_scores_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.fw_scores_text.tag_config("CRITICAL", foreground=RED)
        self.fw_scores_text.tag_config("HIGH",     foreground=AMBER)
        self.fw_scores_text.tag_config("MEDIUM",   foreground=GOLD)

        thresh_f = tk.Frame(right, bg=BG2, pady=8)
        thresh_f.pack(fill=tk.X, padx=6, pady=4)
        tk.Label(thresh_f, text="AUTO-BLOCK THRESHOLD",
                 bg=BG2, fg=TEXT_DIM, font=F_TINY).pack()
        self.fw_threshold = tk.Scale(thresh_f, from_=10, to=100,
            orient=tk.HORIZONTAL, bg=BG2, fg=GOLD,
            troughcolor=BG3, activebackground=GOLD_LT,
            highlightthickness=0, font=F_TINY,
            command=self._fw_update_threshold)
        self.fw_threshold.set(75)
        self.fw_threshold.pack(fill=tk.X, padx=8)

        tk.Label(right, text="SCORE DECAY FACTOR",
                 bg=BG2, fg=TEXT_DIM, font=F_TINY).pack(padx=6)
        self.fw_decay = tk.Scale(right, from_=50, to=99,
            orient=tk.HORIZONTAL, bg=BG2, fg=CYAN,
            troughcolor=BG3, activebackground=CYAN_LT,
            highlightthickness=0, font=F_TINY,
            command=self._fw_update_decay)
        self.fw_decay.set(92)
        self.fw_decay.pack(fill=tk.X, padx=14, pady=(0, 8))

    def _fw_update_threshold(self, val):
        firewall.thresholds["auto_block_score"] = int(val)

    def _fw_update_decay(self, val):
        firewall._decay_factor = int(val) / 100.0

    def _fw_add_block(self): self._fw_add_from_ui("BLOCK")
    def _fw_add_allow(self): self._fw_add_from_ui("ALLOW")

    def _fw_add_from_ui(self, action):
        target = self.fw_entries["fw_target"].get().strip()
        reason = self.fw_entries["fw_reason"].get().strip() or "Manual"
        rtype  = self.fw_type.get()
        ttl_str = self.fw_entries["fw_ttl"].get().strip()
        ttl    = int(ttl_str) if ttl_str.isdigit() else None

        if not target:
            messagebox.showwarning("Input required", "Enter a target."); return

        if rtype == "CIDR":
            ok = firewall.add_cidr_block(target, reason)
            if ok:
                glog("FIREWALL", f"CIDR block added: {target}")
            return

        rule = firewall.add_manual_rule(action, target, rtype, reason, ttl)
        self._fw_insert_tree(rule)
        self.fw_entries["fw_target"].delete(0, tk.END)

    def _fw_insert_tree(self, rule):
        tag = "ai_block" if rule.get("source") == "AI" else \
              "block" if rule["action"] == "BLOCK" else "allow"
        expires = rule.get("expires", "")
        if expires:
            expires = expires[:16]
        self.fw_tree.insert("", "end", values=(
            rule["id"], rule["action"], rule["type"], rule["target"],
            rule.get("source","MANUAL"), rule["reason"],
            rule.get("hits", 0), expires or "∞", rule["time"]
        ), tags=(tag,))

    def _fw_on_auto_block(self, data):
        rule = {
            "id": f"AI-{firewall.stats['rules_generated']}", "action": "BLOCK",
            "target": data["ip"], "type": "IP",
            "reason": f"AI auto-block score={data['score']:.0f}",
            "source": "AI", "time": datetime.now().strftime("%H:%M:%S"),
            "expires": None, "hits": 0,
        }
        self._fw_insert_tree(rule)
        self.fw_ai_var.set(f"AI: BLOCKED {data['ip'][:12]}")

    def _fw_remove(self):
        for item in self.fw_tree.selection():
            vals = self.fw_tree.item(item)["values"]
            firewall.rules = [r for r in firewall.rules if str(r["id"]) != str(vals[0])]
            self.fw_tree.delete(item)

    def _fw_purge_expired(self):
        firewall.remove_expired_rules()
        # Rebuild tree
        self.fw_tree.delete(*self.fw_tree.get_children())
        for rule in firewall.rules:
            self._fw_insert_tree(rule)

    def _fw_unblock_ip(self):
        target = self.fw_entries["fw_target"].get().strip()
        if not target:
            messagebox.showwarning("Input required", "Enter an IP to unblock."); return
        firewall.unblock_ip(target)
        messagebox.showinfo("Unblocked", f"{target} has been unblocked and its score reset.")

    def _fw_show_profile(self, event):
        sel = self.fw_tree.selection()
        if not sel: return
        vals = self.fw_tree.item(sel[0])["values"]
        ip = str(vals[3])
        level, _ = firewall.get_threat_level(ip)
        score = firewall.ip_scores.get(ip, 0)
        profile = firewall.get_profile_summary(ip)
        messagebox.showinfo(
            f"Threat Profile — {ip}",
            f"IP:      {ip}\n"
            f"Level:   {level}\n"
            f"Score:   {score:.1f}\n"
            f"Profile: {profile}"
        )

    def _fw_save(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON","*.json"),("All","*.*")],
            initialfile="king_firewall_rules.json")
        if not path: return
        try:
            firewall.export_rules(path)
            messagebox.showinfo("Saved", f"Rules saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _fw_load(self):
        path = filedialog.askopenfilename(
            filetypes=[("JSON","*.json"),("All","*.*")])
        if not path: return
        try:
            count = firewall.import_rules(path)
            self.fw_tree.delete(*self.fw_tree.get_children())
            for rule in firewall.rules:
                self._fw_insert_tree(rule)
            messagebox.showinfo("Loaded", f"Loaded {count} rules from:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _seed_default_rules(self):
        """Seed baseline rules only on first-ever run; otherwise repopulate
        the tree from whatever was hydrated from SQLite (v4.0)."""
        if firewall.rules or firewall.auto_rules:
            for rule in firewall.rules + firewall.auto_rules:
                self._fw_insert_tree(rule)
            return
        defaults = [
            ("BLOCK", "23",        "PORT",  "Telnet — plaintext protocol"),
            ("BLOCK", "445",       "PORT",  "SMB — WannaCry attack vector"),
            ("BLOCK", "ICMP",      "PROTO", "Block ping sweeps"),
            ("ALLOW", "127.0.0.1", "IP",    "Localhost — always trusted"),
            ("BLOCK", "0.0.0.0",   "IP",    "Null route — reserved"),
            ("BLOCK", "11211",     "PORT",  "Memcached — amplification risk"),
        ]
        for action, target, rtype, reason in defaults:
            rule = firewall.add_manual_rule(action, target, rtype, reason)
            self._fw_insert_tree(rule)

    # ════════════════════════════════════════
    #  IDS TAB
    # ════════════════════════════════════════
    def _build_ids(self, tab):
        top = tk.Frame(tab, bg=BG1, pady=10)
        top.pack(fill=tk.X, padx=12, pady=(12,0))
        tk.Label(top, text="⌁  INTRUSION DETECTION SYSTEM v4.0",
                 bg=BG1, fg=CYAN_LT, font=F_HEAD, padx=16).pack(side=tk.LEFT)
        self._btn(top, "⌫ CLEAR SESSIONS", BG3, AMBER,
                  self._ids_clear_sessions).pack(side=tk.RIGHT, padx=16)

        cards = tk.Frame(tab, bg=BG0)
        cards.pack(fill=tk.X, padx=12, pady=10)
        self.ids_stat_vars = {}
        for label, color, key in [
            ("TOTAL ALERTS", RED,    "total"),
            ("CRITICAL",     RED,    "critical"),
            ("HIGH",         AMBER,  "high"),
            ("MEDIUM",       GOLD,   "medium"),
        ]:
            card = tk.Frame(cards, bg=BG2, padx=14, pady=10)
            card.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=6)
            tk.Label(card, text=label, bg=BG2, fg=TEXT_DIM, font=F_TINY).pack()
            var = tk.StringVar(value="0")
            tk.Label(card, textvariable=var, bg=BG2, fg=color,
                     font=("Courier New", 22, "bold")).pack()
            self.ids_stat_vars[key] = var

        # Signatures
        sig_frame = tk.Frame(tab, bg=BG1)
        sig_frame.pack(fill=tk.X, padx=12, pady=4)
        tk.Label(sig_frame, text=f"LOADED SIGNATURES ({len(IDSEngine.SIGNATURES)})",
                 bg=BG1, fg=GOLD, font=F_TINY, pady=6).pack(anchor="w", padx=8)
        sig_row = tk.Frame(sig_frame, bg=BG1)
        sig_row.pack(fill=tk.X, padx=8)
        for sig in IDSEngine.SIGNATURES:
            color = RED if sig["severity"] >= 4 else AMBER if sig["severity"] == 3 else GOLD
            tk.Label(sig_row, text=f"◈ {sig['name']}",
                     bg=BG2, fg=color, font=F_TINY,
                     padx=8, pady=4, relief="flat").pack(side=tk.LEFT, padx=2, pady=2)

        # Alert table
        tk.Label(tab, text="LIVE ALERT STREAM  (double-click for IP profile)",
                 bg=BG0, fg=CYAN_LT, font=F_TINY, pady=6).pack(anchor="w", padx=20)

        cols = ("Time","IP Address","Alert Name","Detail","Severity")
        self.ids_tree = ttk.Treeview(tab, columns=cols, show="headings", height=15)
        for c, w in zip(cols, [80,130,160,300,90]):
            self.ids_tree.heading(c, text=c)
            self.ids_tree.column(c, width=w, anchor="center" if w<100 else "w")
        for tag, color in [("CRITICAL",RED),("HIGH",AMBER),("MEDIUM",GOLD),("LOW",GREEN)]:
            self.ids_tree.tag_configure(tag, foreground=color)
        self.ids_tree.bind("<Double-1>", self._ids_show_ip_profile)
        isb = ttk.Scrollbar(tab, orient="vertical", command=self.ids_tree.yview)
        self.ids_tree.configure(yscrollcommand=isb.set)
        self.ids_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(12,0), pady=4)
        isb.pack(side=tk.RIGHT, fill=tk.Y, pady=4, padx=(0,12))

    def _ids_on_alert(self, alert: dict):
        self.ids_tree.insert("", 0,
            values=(alert["time"], alert["ip"], alert["name"],
                    alert["detail"], alert["level"]),
            tags=(alert["level"],))
        self.ids_feed.config(state="normal")
        self.ids_feed.insert(tk.END,
            f"[{alert['time']}] {alert['ip']:15} | {alert['name']:22} | {alert['detail']}\n",
            alert["level"])
        self.ids_feed.see(tk.END)
        self.ids_feed.config(state="disabled")

    def _ids_show_ip_profile(self, event):
        sel = self.ids_tree.selection()
        if not sel: return
        ip = str(self.ids_tree.item(sel[0])["values"][1])
        level, _ = firewall.get_threat_level(ip)
        score = firewall.ip_scores.get(ip, 0)
        profile = firewall.get_profile_summary(ip)
        sess = ids._sessions.get(ip, {})
        messagebox.showinfo(
            f"IP Intelligence — {ip}",
            f"Threat Level: {level}\n"
            f"Score:        {score:.1f}\n"
            f"Unique Ports: {len(sess.get('unique_ports', set()))}\n"
            f"Total Events: {sess.get('total', 0)}\n\n"
            f"Behavioral Profile:\n{profile}"
        )

    def _ids_clear_sessions(self):
        with ids._lock:
            ids._sessions.clear()
            ids._windows.clear()
            ids._escalation.clear()
        glog("IDS", "All session counters cleared", "INFO")

    # ════════════════════════════════════════
    #  SANDBOX TAB
    # ════════════════════════════════════════
    def _build_sandbox(self, tab):
        top = tk.Frame(tab, bg=BG1, pady=10)
        top.pack(fill=tk.X, padx=12, pady=(12,0))
        tk.Label(top, text="⚔  ATTACK SANDBOX  —  Test Your Own Defences",
                 bg=BG1, fg=RED_LT, font=F_HEAD, padx=16).pack(side=tk.LEFT)
        tk.Label(top, text="SIMULATES ON LOCALHOST ONLY",
                 bg=BG2, fg=AMBER, font=F_TINY, padx=10, pady=4).pack(side=tk.RIGHT, padx=16)

        sel = tk.Frame(tab, bg=BG0)
        sel.pack(fill=tk.X, padx=12, pady=8)
        tk.Label(sel, text="SELECT ATTACK:", bg=BG0, fg=TEXT_DIM,
                 font=F_TINY).pack(side=tk.LEFT, padx=8)
        self.sandbox_attack_var = ttk.Combobox(sel,
            values=[a["name"] for a in SandboxEngine.ATTACK_TYPES],
            width=28, state="readonly", font=F_MONO)
        self.sandbox_attack_var.set(SandboxEngine.ATTACK_TYPES[0]["name"])
        self.sandbox_attack_var.pack(side=tk.LEFT, padx=8)

        tk.Label(sel, text="ROUNDS:", bg=BG0, fg=TEXT_DIM,
                 font=F_TINY).pack(side=tk.LEFT, padx=(16,4))
        self.sandbox_count = tk.Entry(sel, bg=BG3, fg=GOLD_LT,
                                      insertbackground=GOLD, font=F_MONO,
                                      width=6, relief="flat", bd=4)
        self.sandbox_count.insert(0, "30")
        self.sandbox_count.pack(side=tk.LEFT, padx=4)

        tk.Label(sel, text="DELAY(s):", bg=BG0, fg=TEXT_DIM,
                 font=F_TINY).pack(side=tk.LEFT, padx=(8,4))
        self.sandbox_delay = tk.Entry(sel, bg=BG3, fg=GOLD_LT,
                                      insertbackground=GOLD, font=F_MONO,
                                      width=6, relief="flat", bd=4)
        self.sandbox_delay.insert(0, "0.05")
        self.sandbox_delay.pack(side=tk.LEFT, padx=4)

        self._btn(sel, "▶ LAUNCH",      RED,    WHITE, self._sandbox_run).pack(side=tk.LEFT, padx=12)
        self._btn(sel, "⚡ FULL ASSAULT",CRIMSON,WHITE, self._sandbox_full).pack(side=tk.LEFT, padx=4)
        self._btn(sel, "■ STOP",        BG3,    RED,   self._sandbox_stop).pack(side=tk.LEFT, padx=4)

        split = tk.Frame(tab, bg=BG0)
        split.pack(fill=tk.BOTH, expand=True, padx=12, pady=6)

        left = tk.Frame(split, bg=BG1)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,6))
        tk.Label(left, text="LIVE ATTACK RESULTS",
                 bg=BG1, fg=RED_LT, font=F_TINY, pady=6).pack()
        self.sandbox_output = scrolledtext.ScrolledText(
            left, bg=BG1, fg=TEXT, font=F_MONO_S, relief="flat", state="disabled")
        self.sandbox_output.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)
        for tag, color in [("blocked",RED),("allowed",GREEN),("ai",AMBER),
                           ("alert",CYAN_LT),("dim",TEXT_DIM),("header",GOLD_LT)]:
            self.sandbox_output.tag_config(tag, foreground=color)

        right = tk.Frame(split, bg=BG1, width=230)
        right.pack(side=tk.RIGHT, fill=tk.Y)
        right.pack_propagate(False)
        tk.Label(right, text="DEFENCE SCORE",
                 bg=BG1, fg=GOLD, font=F_TINY, pady=8).pack()
        tk.Frame(right, bg=GOLD_DIM, height=1).pack(fill=tk.X)

        self.sandbox_stat_vars = {}
        for label, color in [
            ("Attacks Sent",   TEXT), ("Blocked",       RED),
            ("Allowed",        GREEN), ("AI Auto-Blocks", AMBER),
            ("IDS Alerts",     CYAN_LT), ("Block Rate",   GOLD_LT),
        ]:
            f = tk.Frame(right, bg=BG2, pady=6)
            f.pack(fill=tk.X, padx=8, pady=3)
            tk.Label(f, text=label.upper(), bg=BG2, fg=TEXT_DIM, font=F_TINY).pack()
            var = tk.StringVar(value="0")
            tk.Label(f, textvariable=var, bg=BG2, fg=color,
                     font=("Courier New", 18, "bold")).pack()
            self.sandbox_stat_vars[label] = var

        self._sandbox_stats = {"sent":0,"blocked":0,"allowed":0,"ai":0,"alerts":0}

    def _sandbox_run(self):
        idx = self.sandbox_attack_var.current()
        try:
            count = int(self.sandbox_count.get() or 30)
            delay = float(self.sandbox_delay.get() or 0.05)
        except Exception:
            count, delay = 30, 0.05
        self._sandbox_stats = {"sent":0,"blocked":0,"allowed":0,"ai":0,"alerts":0}
        self._sandbox_log(f"◈ Launching: {SandboxEngine.ATTACK_TYPES[idx]['name']}", "header")
        glog("SANDBOX", f"Attack started: {SandboxEngine.ATTACK_TYPES[idx]['name']}", "WARN")
        sandbox.run_attack(idx, count, delay, self._sandbox_callback)

    def _sandbox_full(self):
        self._sandbox_stats = {"sent":0,"blocked":0,"allowed":0,"ai":0,"alerts":0}
        self._sandbox_log("⚡ FULL ASSAULT — All attack types launching...", "header")
        glog("SANDBOX", "FULL ASSAULT initiated", "CRITICAL")
        sandbox.run_full_assault(self._sandbox_callback)

    def _sandbox_stop(self):
        sandbox.running = False
        self._sandbox_log("■ Attack stopped.", "dim")
        glog("SANDBOX", "Attack simulation stopped")

    def _sandbox_callback(self, result):
        if result.get("done"):
            self.root.after(0, lambda r=result: self._sandbox_done(r))
        else:
            self.root.after(0, lambda r=result: self._sandbox_update(r))

    def _sandbox_update(self, result):
        self._sandbox_stats["sent"] += 1
        action = result["action"]
        if action == "BLOCK":
            self._sandbox_stats["blocked"] += 1
            self._sandbox_log(
                f"[{result['time']}] BLOCKED  {result['src_ip']:16} → Port {result['port']:5}  "
                f"| {result['attack']}", "blocked")
        else:
            self._sandbox_stats["allowed"] += 1
            self._sandbox_log(
                f"[{result['time']}] ALLOWED  {result['src_ip']:16} → Port {result['port']:5}  "
                f"| {result['attack']}", "allowed")
        if result.get("auto"):
            self._sandbox_stats["ai"] += 1
            self._sandbox_log(f"         ★ AI AUTO-BLOCKED {result['src_ip']}", "ai")
        for alert in result.get("alerts", []):
            self._sandbox_stats["alerts"] += 1
            self._sandbox_log(f"         ⚡ IDS: {alert}", "alert")
        self._sandbox_refresh_stats()

    def _sandbox_done(self, result):
        total   = result.get("total", 1)
        blocked = self._sandbox_stats["blocked"]
        pct     = round(blocked / max(total,1) * 100, 1)
        self._sandbox_log(f"\n✔ Complete — {blocked}/{total} blocked ({pct}%)\n", "header")
        glog("SANDBOX", f"Simulation complete — {blocked}/{total} blocked ({pct}%)")
        self._sandbox_refresh_stats()

    def _sandbox_refresh_stats(self):
        s = self._sandbox_stats
        total = max(s["sent"], 1)
        self.sandbox_stat_vars["Attacks Sent"].set(str(s["sent"]))
        self.sandbox_stat_vars["Blocked"].set(str(s["blocked"]))
        self.sandbox_stat_vars["Allowed"].set(str(s["allowed"]))
        self.sandbox_stat_vars["AI Auto-Blocks"].set(str(s["ai"]))
        self.sandbox_stat_vars["IDS Alerts"].set(str(s["alerts"]))
        self.sandbox_stat_vars["Block Rate"].set(f"{s['blocked']/total*100:.0f}%")

    def _sandbox_log(self, text, tag=""):
        self.sandbox_output.config(state="normal")
        self.sandbox_output.insert(tk.END, text + "\n", tag)
        self.sandbox_output.see(tk.END)
        self.sandbox_output.config(state="disabled")

    # ════════════════════════════════════════
    #  PORT SCANNER TAB
    # ════════════════════════════════════════
    def _build_portscanner(self, tab):
        top = tk.Frame(tab, bg=BG1, pady=10)
        top.pack(fill=tk.X, padx=12, pady=(12,0))
        tk.Label(top, text="⌕  ADVANCED PORT SCANNER + PORT CLOSER",
                 bg=BG1, fg=GOLD_LT, font=F_HEAD, padx=16).pack(side=tk.LEFT)

        ctrl = tk.Frame(tab, bg=BG2, pady=10)
        ctrl.pack(fill=tk.X, padx=12, pady=6)
        fields = [("TARGET IP:", "scan_ip", 18, "127.0.0.1"),
                  ("START:",     "scan_s",  7,  "1"),
                  ("END:",       "scan_e",  7,  "1024"),
                  ("TIMEOUT ms:","scan_t",  6,  "400")]
        self.scan_entries = {}
        col = 0
        for label, key, w, default in fields:
            tk.Label(ctrl, text=label, bg=BG2, fg=TEXT_DIM,
                     font=F_TINY).grid(row=0, column=col, padx=(14,4), sticky="w")
            e = tk.Entry(ctrl, bg=BG3, fg=GOLD_LT, insertbackground=GOLD,
                         font=F_MONO, width=w, relief="flat", bd=4)
            e.insert(0, default)
            e.grid(row=0, column=col+1, padx=4)
            self.scan_entries[key] = e
            col += 2

        self.scan_btn  = self._btn(ctrl, "▶ SCAN", GOLD, BG0, self._scan_start)
        self.scan_btn.grid(row=0, column=col, padx=12)
        self.scan_stop = self._btn(ctrl, "■ STOP", RED, WHITE, self._scan_stop)
        self.scan_stop.grid(row=0, column=col+1, padx=4)
        self.scan_stop.config(state="disabled")

        pf = tk.Frame(tab, bg=BG0)
        pf.pack(fill=tk.X, padx=12, pady=2)
        self.scan_pv = tk.DoubleVar()
        ttk.Progressbar(pf, variable=self.scan_pv, maximum=100).pack(
            side=tk.LEFT, fill=tk.X, expand=True)
        self.scan_sv = tk.StringVar(value="Ready")
        tk.Label(pf, textvariable=self.scan_sv, bg=BG0,
                 fg=TEXT_DIM, font=F_TINY).pack(side=tk.LEFT, padx=10)

        split = tk.Frame(tab, bg=BG0)
        split.pack(fill=tk.BOTH, expand=True, padx=12, pady=6)

        left = tk.Frame(split, bg=BG1)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,6))
        tk.Label(left, text="OPEN PORTS  —  Select + CLOSE PORT to shut down",
                 bg=BG1, fg=GOLD, font=F_TINY, pady=6).pack()
        cols = ("Port","Service","PID","Process","Risk","Status")
        self.port_tree = ttk.Treeview(left, columns=cols, show="headings", height=14)
        for c, w in zip(cols, [70,100,70,150,80,90]):
            self.port_tree.heading(c, text=c)
            self.port_tree.column(c, width=w, anchor="center" if w<100 else "w")
        self.port_tree.tag_configure("open",   foreground=RED)
        self.port_tree.tag_configure("closed", foreground=TEXT_DIM)
        self.port_tree.tag_configure("risky",  foreground=AMBER)
        psb = ttk.Scrollbar(left, orient="vertical", command=self.port_tree.yview)
        self.port_tree.configure(yscrollcommand=psb.set)
        self.port_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        psb.pack(side=tk.RIGHT, fill=tk.Y)

        abf = tk.Frame(left, bg=BG1, pady=6)
        abf.pack(fill=tk.X)
        self._btn(abf, "● CLOSE PORT",   RED,    WHITE, self._port_close_one).pack(side=tk.LEFT, padx=8)
        self._btn(abf, "⊘ CLOSE ALL",    CRIMSON,WHITE, self._port_close_all).pack(side=tk.LEFT, padx=4)
        self._btn(abf, "↻ REFRESH PIDs", BG3,    GOLD,  self._port_refresh_pids).pack(side=tk.LEFT, padx=4)

        right = tk.Frame(split, bg=BG1, width=180)
        right.pack(side=tk.RIGHT, fill=tk.Y)
        right.pack_propagate(False)
        self.scan_stat_vars = {}
        for label, color in [("Scanned",GOLD),("Open",RED),("Closed",TEXT_DIM),("Time",GREEN)]:
            f = tk.Frame(right, bg=BG2, pady=8)
            f.pack(fill=tk.X, padx=8, pady=4)
            tk.Label(f, text=label.upper(), bg=BG2, fg=TEXT_DIM, font=F_TINY).pack()
            var = tk.StringVar(value="0")
            tk.Label(f, textvariable=var, bg=BG2, fg=color,
                     font=("Courier New", 20, "bold")).pack()
            self.scan_stat_vars[label] = var
        if not PSUTIL_OK:
            tk.Label(right, text="pip install psutil\nto enable port closing",
                     bg=BG2, fg=AMBER, font=F_TINY, justify="center").pack(padx=8, pady=8)

    def _scan_start(self):
        if self.scan_running: return
        ip = self.scan_entries["scan_ip"].get().strip()
        try:
            s = int(self.scan_entries["scan_s"].get())
            e = int(self.scan_entries["scan_e"].get())
            t = int(self.scan_entries["scan_t"].get()) / 1000
        except Exception:
            messagebox.showerror("Error","Invalid values."); return
        self.scan_running = True
        self.port_tree.delete(*self.port_tree.get_children())
        for v in self.scan_stat_vars.values(): v.set("0")
        self.scan_btn.config(state="disabled")
        self.scan_stop.config(state="normal")
        glog("SCANNER", f"Scan started: {ip} ports {s}–{e}")
        threading.Thread(target=self._scan_worker, args=(ip,s,e,t), daemon=True).start()

    def _scan_stop(self):
        self.scan_running = False
        self.scan_sv.set("Stopped")
        self.scan_btn.config(state="normal")
        self.scan_stop.config(state="disabled")

    def _scan_worker(self, ip, start, end, timeout):
        t0 = time.time()
        open_c = 0
        for i, port in enumerate(range(start, end+1)):
            if not self.scan_running: break
            pct = (i+1)/(end-start+1)*100
            self.root.after(0, lambda p=pct, po=port:
                (self.scan_pv.set(p),
                 self.scan_sv.set(f"Scanning {po}..."),
                 self.scan_stat_vars["Scanned"].set(str(i+1)),
                 self.scan_stat_vars["Time"].set(f"{time.time()-t0:.0f}s")))
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                if sock.connect_ex((ip, port)) == 0:
                    open_c += 1
                    self.root.after(0, lambda p=port, o=open_c:
                        (self._scan_add(p), self.scan_stat_vars["Open"].set(str(o))))
                sock.close()
            except Exception:
                pass
            closed = i + 1 - open_c
            self.root.after(0, lambda c=closed: self.scan_stat_vars["Closed"].set(str(c)))
        elapsed = time.time() - t0
        self.root.after(0, lambda: (
            self.scan_sv.set(f"✔ Done — {open_c} open port(s) in {elapsed:.1f}s"),
            self.scan_btn.config(state="normal"),
            self.scan_stop.config(state="disabled")))
        self.scan_running = False
        glog("SCANNER", f"Scan complete — {open_c} open ports on {ip}")

    def _scan_add(self, port):
        service = PORT_SERVICES.get(port, "Unknown")
        pid, proc = self._get_pid(port)
        risk_ports = {23:"CRITICAL",445:"CRITICAL",3389:"HIGH",21:"HIGH",
                      3306:"HIGH",27017:"CRITICAL",11211:"CRITICAL",6379:"CRITICAL"}
        risk  = risk_ports.get(port, "LOW")
        tag   = "risky" if risk in ("CRITICAL","HIGH") else "open"
        self.port_tree.insert("", "end",
            values=(port, service, pid, proc, risk, "● OPEN"), tags=(tag,))

    def _get_pid(self, port):
        if not PSUTIL_OK: return "N/A", "Install psutil"
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr.port == port and conn.status == 'LISTEN':
                    try: return conn.pid, psutil.Process(conn.pid).name()
                    except: return conn.pid, "Unknown"
        except: pass
        return "—", "Not listening"

    def _port_refresh_pids(self):
        for item in self.port_tree.get_children():
            vals = list(self.port_tree.item(item)["values"])
            if "OPEN" in str(vals[5]):
                pid, proc = self._get_pid(int(vals[0]))
                vals[2] = pid; vals[3] = proc
                self.port_tree.item(item, values=vals)

    def _port_close_one(self):
        sel = self.port_tree.selection()
        if not sel: messagebox.showinfo("Select port","Click a port first."); return
        vals = self.port_tree.item(sel[0])["values"]
        port, pid, proc = vals[0], vals[2], vals[3]
        if str(pid) in ("N/A","—",""):
            messagebox.showwarning("No PID",f"No process found for port {port}.\nRun as Admin."); return
        if not messagebox.askyesno("Close Port", f"STOP process on port {port}?\n\nPID: {pid}\nProcess: {proc}"):
            return
        try:
            if PSUTIL_OK: psutil.Process(int(pid)).terminate()
            else: subprocess.run(["taskkill","/PID",str(pid),"/F"], capture_output=True)
            new = list(vals); new[5] = "✔ CLOSED"
            self.port_tree.item(sel[0], values=new, tags=("closed",))
            glog("SCANNER", f"Port {port} closed (PID {pid})")
            messagebox.showinfo("Closed", f"Port {port} closed successfully.")
        except Exception as ex:
            messagebox.showerror("Error", str(ex))

    def _port_close_all(self):
        items = [i for i in self.port_tree.get_children()
                 if "OPEN" in str(self.port_tree.item(i)["values"][5])]
        if not items: messagebox.showinfo("None","No open ports."); return
        if not messagebox.askyesno("Close ALL", f"Stop ALL {len(items)} open port processes?"): return
        ok = fail = 0
        for item in items:
            vals = self.port_tree.item(item)["values"]
            pid = vals[2]
            if str(pid) in ("N/A","—",""): fail += 1; continue
            try:
                if PSUTIL_OK: psutil.Process(int(pid)).terminate()
                else: subprocess.run(["taskkill","/PID",str(pid),"/F"], capture_output=True)
                new = list(vals); new[5] = "✔ CLOSED"
                self.port_tree.item(item, values=new, tags=("closed",))
                ok += 1
            except: fail += 1
        messagebox.showinfo("Done", f"Closed: {ok}  Failed: {fail}")

    # ════════════════════════════════════════
    #  VULNERABILITY SCANNER TAB
    # ════════════════════════════════════════
    def _build_vulnscan(self, tab):
        top = tk.Frame(tab, bg=BG1, pady=10)
        top.pack(fill=tk.X, padx=12, pady=(12,0))
        tk.Label(top, text="⛨  VULNERABILITY SCANNER",
                 bg=BG1, fg=GREEN_LT, font=F_HEAD, padx=16).pack(side=tk.LEFT)

        ctrl = tk.Frame(tab, bg=BG2, pady=10)
        ctrl.pack(fill=tk.X, padx=12, pady=6)
        tk.Label(ctrl, text="TARGET:", bg=BG2, fg=TEXT_DIM, font=F_TINY).pack(side=tk.LEFT, padx=(16,4))
        self.vuln_ip = tk.Entry(ctrl, bg=BG3, fg=GOLD_LT, insertbackground=GOLD,
                                font=F_MONO, width=20, relief="flat", bd=4)
        self.vuln_ip.insert(0, "127.0.0.1")
        self.vuln_ip.pack(side=tk.LEFT, padx=4)
        self._btn(ctrl, "▶ SCAN FOR VULNERABILITIES", GREEN, BG0, self._vuln_scan).pack(side=tk.LEFT, padx=16)
        self.vuln_status = tk.StringVar(value="Ready — scans YOUR system only")
        tk.Label(ctrl, textvariable=self.vuln_status,
                 bg=BG2, fg=TEXT_DIM, font=F_TINY).pack(side=tk.LEFT, padx=8)

        self.vuln_cards_frame = tk.Frame(tab, bg=BG0)
        self.vuln_cards_frame.pack(fill=tk.X, padx=12, pady=6)
        self.vuln_counts = {}
        for risk, color in [("CRITICAL",RED),("HIGH",AMBER),("MEDIUM",GOLD),("LOW",GREEN)]:
            c = tk.Frame(self.vuln_cards_frame, bg=BG2, padx=20, pady=10)
            c.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=6)
            tk.Label(c, text=risk, bg=BG2, fg=color, font=F_TINY).pack()
            var = tk.StringVar(value="0")
            tk.Label(c, textvariable=var, bg=BG2, fg=color,
                     font=("Courier New", 22, "bold")).pack()
            self.vuln_counts[risk] = var

        cols = ("Check","Port","Risk","Status","Recommendation")
        self.vuln_tree = ttk.Treeview(tab, columns=cols, show="headings", height=16)
        for c, w in zip(cols, [180,60,90,80,320]):
            self.vuln_tree.heading(c, text=c)
            self.vuln_tree.column(c, width=w, anchor="w" if w>100 else "center")
        for tag, color in [("CRITICAL",RED),("HIGH",AMBER),("MEDIUM",GOLD),("LOW",GREEN),("safe",TEXT_DIM)]:
            self.vuln_tree.tag_configure(tag, foreground=color)
        self.vuln_tree.bind("<Double-1>", self._vuln_cve_lookup)
        vsb = ttk.Scrollbar(tab, orient="vertical", command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=vsb.set)
        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(12,0), pady=6)
        vsb.pack(side=tk.RIGHT, fill=tk.Y, pady=6, padx=(0,12))
        tk.Label(tab, text="Double-click a finding to look it up in CVE Threat Intelligence",
                 bg=BG0, fg=TEXT_DIM, font=F_TINY).pack(anchor="w", padx=14, pady=(0,6))

    def _vuln_scan(self):
        target = self.vuln_ip.get().strip()
        self.vuln_tree.delete(*self.vuln_tree.get_children())
        for v in self.vuln_counts.values(): v.set("0")
        self.vuln_status.set("Scanning...")
        counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        glog("VULN", f"Vulnerability scan started on {target}")

        def worker():
            results = vuln.scan(target, callback=lambda r:
                self.root.after(0, lambda res=r: self._vuln_add(res, counts)))
            found = sum(1 for r in results if r["found"])
            self.root.after(0, lambda: (
                self.vuln_status.set(f"✔ Done — {found} vulnerabilities found"),
                [self.vuln_counts[k].set(str(v)) for k,v in counts.items()]))
            glog("VULN", f"Scan complete — {found} vulnerabilities found on {target}",
                 "WARN" if found else "INFO")
        threading.Thread(target=worker, daemon=True).start()

    def _vuln_add(self, r, counts):
        if r["found"]:
            tag = r["risk"]; status = "⚠ VULNERABLE"
            counts[r["risk"]] = counts.get(r["risk"], 0) + 1
        else:
            tag = "safe"; status = "✔ Not Found"
        self.vuln_tree.insert("", "end",
            values=(r["name"], r["port"], r["risk"] if r["found"] else "—",
                    status, r["desc"] if r["found"] else ""), tags=(tag,))

    def _vuln_cve_lookup(self, event):
        """Cross-wire: double-click a finding to search CVE Lookup for it (v4.0)."""
        sel = self.vuln_tree.selection()
        if not sel: return
        vals = self.vuln_tree.item(sel[0])["values"]
        check_name = str(vals[0])
        keyword = check_name.replace("Open", "").replace("Exposed", "").strip()
        if not keyword:
            return
        self._show_page("cve")
        self.cve_query.delete(0, tk.END)
        self.cve_query.insert(0, keyword)
        self._cve_search()

    # ════════════════════════════════════════
    #  PASSWORD TAB
    # ════════════════════════════════════════
    def _build_password(self, tab):
        top = tk.Frame(tab, bg=BG1, pady=10)
        top.pack(fill=tk.X, padx=12, pady=(12,0))
        tk.Label(top, text="⚿  PASSWORD ANALYZER + HASH CRACKER",
                 bg=BG1, fg=GOLD_LT, font=F_HEAD, padx=16).pack(side=tk.LEFT)

        inp = tk.Frame(tab, bg=BG2, pady=12)
        inp.pack(fill=tk.X, padx=12, pady=6)
        tk.Label(inp, text="PASSWORD:", bg=BG2, fg=TEXT_DIM,
                 font=F_TINY).pack(side=tk.LEFT, padx=(16,8))
        self.pw_entry = tk.Entry(inp, bg=BG3, fg=GOLD_LT, insertbackground=GOLD,
                                 font=("Courier New",13), width=32,
                                 relief="flat", bd=4, show="●")
        self.pw_entry.pack(side=tk.LEFT, padx=4)
        self.pw_entry.bind("<KeyRelease>", lambda e: self._pw_analyze())
        self.pw_show = tk.BooleanVar()
        tk.Checkbutton(inp, text="Show", variable=self.pw_show, bg=BG2, fg=TEXT_DIM,
                       font=F_TINY, selectcolor=BG3, activebackground=BG2,
                       command=lambda: self.pw_entry.config(
                           show="" if self.pw_show.get() else "●")).pack(side=tk.LEFT, padx=8)

        split = tk.Frame(tab, bg=BG0)
        split.pack(fill=tk.BOTH, expand=True, padx=12, pady=6)

        left = tk.Frame(split, bg=BG1, width=320)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0,6))
        left.pack_propagate(False)
        tk.Label(left, text="STRENGTH ANALYSIS", bg=BG1, fg=GOLD, font=F_TINY, pady=8).pack()
        self.pw_score_var = tk.StringVar(value="—")
        self.pw_score_lbl = tk.Label(left, textvariable=self.pw_score_var,
                 bg=BG1, fg=TEXT_DIM, font=("Courier New",38,"bold"))
        self.pw_score_lbl.pack()
        self.pw_rating_var = tk.StringVar(value="Enter a password")
        self.pw_rating_lbl = tk.Label(left, textvariable=self.pw_rating_var,
                 bg=BG1, fg=TEXT_DIM, font=F_HEAD)
        self.pw_rating_lbl.pack(pady=4)
        self.pw_bar = tk.Canvas(left, width=280, height=14, bg=BG3, highlightthickness=0)
        self.pw_bar.pack(padx=16, pady=8)

        self.pw_stat_vars = {}
        for label in ["Length","Entropy","Crack Time","SHA-256","MD5"]:
            f = tk.Frame(left, bg=BG2, pady=6)
            f.pack(fill=tk.X, padx=10, pady=2)
            tk.Label(f, text=label.upper(), bg=BG2, fg=TEXT_DIM, font=F_TINY).pack(side=tk.LEFT, padx=8)
            var = tk.StringVar(value="—")
            tk.Label(f, textvariable=var, bg=BG2, fg=TEXT, font=F_MONO_S).pack(side=tk.RIGHT, padx=8)
            self.pw_stat_vars[label] = var

        right = tk.Frame(split, bg=BG0)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(6,0))

        ck_frame = tk.Frame(right, bg=BG1)
        ck_frame.pack(fill=tk.X, pady=(0,6))
        tk.Label(ck_frame, text="SECURITY CHECKLIST", bg=BG1, fg=GOLD, font=F_TINY, pady=8).pack()
        self.pw_checks = {}
        checks = [
            ("len8","8+ characters"),("len12","12+ characters"),
            ("len16","16+ characters (ideal)"),("lower","Lowercase letters"),
            ("upper","Uppercase letters"),("digits","Numbers (0-9)"),
            ("special","Special characters"),("common","Not a common password"),
            ("repeat","No repeated characters"),("seq","No sequential patterns"),
        ]
        grid = tk.Frame(ck_frame, bg=BG1)
        grid.pack(fill=tk.X, padx=10)
        for i, (key, text) in enumerate(checks):
            f = tk.Frame(grid, bg=BG2, pady=5)
            f.grid(row=i//2, column=i%2, sticky="ew", padx=3, pady=2)
            grid.columnconfigure(i%2, weight=1)
            iv = tk.StringVar(value="○")
            il = tk.Label(f, textvariable=iv, bg=BG2, fg=TEXT_DIM, font=F_MONO, width=2)
            il.pack(side=tk.LEFT, padx=6)
            tl = tk.Label(f, text=text, bg=BG2, fg=TEXT_DIM, font=F_MONO_S)
            tl.pack(side=tk.LEFT)
            self.pw_checks[key] = (iv, il, tl)

        crack = tk.Frame(right, bg=BG1)
        crack.pack(fill=tk.BOTH, expand=True, pady=6)
        tk.Label(crack, text="HASH CRACKER  (YOUR OWN HASHES ONLY)",
                 bg=BG1, fg=RED_LT, font=F_TINY, pady=6).pack()
        cctrl = tk.Frame(crack, bg=BG1)
        cctrl.pack(fill=tk.X, padx=10)
        tk.Label(cctrl, text="HASH:", bg=BG1, fg=TEXT_DIM, font=F_TINY).pack(side=tk.LEFT, padx=4)
        self.crack_hash = tk.Entry(cctrl, bg=BG3, fg=GOLD_LT, insertbackground=GOLD,
                                   font=F_MONO, width=36, relief="flat", bd=4)
        self.crack_hash.pack(side=tk.LEFT, padx=4)
        self.crack_type = ttk.Combobox(cctrl, values=["MD5","SHA-1","SHA-256"],
                                       width=8, state="readonly", font=F_MONO)
        self.crack_type.set("MD5")
        self.crack_type.pack(side=tk.LEFT, padx=4)
        self._btn(cctrl, "CRACK", RED, WHITE, self._pw_crack).pack(side=tk.LEFT, padx=8)
        self.crack_result = tk.Label(crack, text="", bg=BG1, fg=GREEN, font=F_MONO_L)
        self.crack_result.pack(pady=4)

    def _pw_analyze(self):
        pw = self.pw_entry.get()
        if not pw:
            self.pw_score_var.set("—")
            self.pw_score_lbl.config(fg=TEXT_DIM)
            self.pw_rating_var.set("Enter a password")
            self.pw_bar.delete("all")
            for k,(iv,il,tl) in self.pw_checks.items():
                iv.set("○"); il.config(fg=TEXT_DIM); tl.config(fg=TEXT_DIM)
            return

        checks = {
            "len8":   len(pw)>=8,  "len12": len(pw)>=12,  "len16": len(pw)>=16,
            "lower":  bool(re.search(r'[a-z]',pw)),
            "upper":  bool(re.search(r'[A-Z]',pw)),
            "digits": bool(re.search(r'[0-9]',pw)),
            "special":bool(re.search(r'[^a-zA-Z0-9]',pw)),
            "common": pw.lower() not in COMMON_PASSWORDS,
            "repeat": not bool(re.search(r'(.)\1{2,}',pw)),
            "seq":    not any(s in pw.lower() for s in ['abcdef','qwerty','123456','abcabc']),
        }
        score = sum(checks.values())
        pct   = int(score/len(checks)*100)
        color = GREEN if pct>=75 else AMBER if pct>=50 else RED
        label = "⛨  STRONG" if pct>=75 else "⚠  MODERATE" if pct>=50 else "⚠  WEAK"

        self.pw_score_var.set(f"{pct}%")
        self.pw_score_lbl.config(fg=color)
        self.pw_rating_var.set(label)
        self.pw_rating_lbl.config(fg=color)
        self.pw_bar.delete("all")
        self.pw_bar.create_rectangle(0,0,int(280*pct/100),14,fill=color,outline="")

        for key,(iv,il,tl) in self.pw_checks.items():
            p = checks.get(key, False)
            iv.set("✔" if p else "✘")
            il.config(fg=GREEN if p else RED)
            tl.config(fg=TEXT if p else TEXT_DIM)

        charset = sum([26 if re.search(r'[a-z]',pw) else 0,
                       26 if re.search(r'[A-Z]',pw) else 0,
                       10 if re.search(r'[0-9]',pw) else 0,
                       32 if re.search(r'[^a-zA-Z0-9]',pw) else 0])
        entropy = round(len(pw)*math.log2(charset),1) if charset else 0
        secs    = 2**entropy / 1_000_000_000 if entropy else 0
        if secs<60:         crack="< 1 minute"
        elif secs<3600:     crack=f"{secs/60:.1f} minutes"
        elif secs<86400:    crack=f"{secs/3600:.1f} hours"
        elif secs<31536000: crack=f"{secs/86400:.0f} days"
        else:               crack=f"{secs/31536000:.1e} years"

        self.pw_stat_vars["Length"].set(f"{len(pw)} characters")
        self.pw_stat_vars["Entropy"].set(f"{entropy} bits")
        self.pw_stat_vars["Crack Time"].set(crack)
        self.pw_stat_vars["SHA-256"].set(hashlib.sha256(pw.encode()).hexdigest()[:20]+"...")
        self.pw_stat_vars["MD5"].set(hashlib.md5(pw.encode()).hexdigest()[:20]+"...")

    def _pw_crack(self):
        target = self.crack_hash.get().strip().lower()
        algo   = self.crack_type.get()
        if not target: return
        hash_fn = {"MD5":hashlib.md5,"SHA-1":hashlib.sha1,"SHA-256":hashlib.sha256}.get(algo)
        self.crack_result.config(text="Cracking...", fg=AMBER)
        def worker():
            for pw in COMMON_PASSWORDS:
                if hash_fn(pw.encode()).hexdigest() == target:
                    self.root.after(0, lambda p=pw:
                        self.crack_result.config(text=f"✔ CRACKED!  Password = '{p}'", fg=GREEN))
                    glog("PASSWORD", "Hash cracked successfully")
                    return
            self.root.after(0, lambda:
                self.crack_result.config(text="✘ Not found in wordlist", fg=TEXT_DIM))
        threading.Thread(target=worker, daemon=True).start()

    # ════════════════════════════════════════
    #  VAULT TAB  (full v3.0 layout restored + v3.1 fixes)
    # ════════════════════════════════════════
    def _build_vault(self, tab):
        top = tk.Frame(tab, bg=BG1, pady=10)
        top.pack(fill=tk.X, padx=12, pady=(12,0))
        tk.Label(top,
                 text="⌬  ENCRYPTION VAULT  —  AES-256  |  Text / Files / Videos / Batch",
                 bg=BG1, fg=CYAN_LT, font=F_HEAD, padx=16).pack(side=tk.LEFT)

        if not CRYPTO_OK:
            tk.Label(tab, text="⚠  pip install cryptography  then restart.",
                     bg=BG0, fg=AMBER, font=F_HEAD).pack(pady=40)
            return

        # ── Key row ──────────────────────────────────────────────
        key_f = tk.Frame(tab, bg=BG2, pady=10)
        key_f.pack(fill=tk.X, padx=12, pady=(6,2))
        tk.Label(key_f, text="⚷  KEY:", bg=BG2, fg=TEXT_DIM,
                 font=F_TINY).pack(side=tk.LEFT, padx=(16,6))
        self.vault_key = tk.Entry(key_f, bg=BG3, fg=GOLD_LT, insertbackground=GOLD,
                                  font=F_MONO, width=38, relief="flat", bd=4, show="●")
        self.vault_key.pack(side=tk.LEFT, padx=4)
        self.vault_show_key = tk.BooleanVar()
        tk.Checkbutton(key_f, text="Show", variable=self.vault_show_key,
                       bg=BG2, fg=TEXT_DIM, font=F_TINY, selectcolor=BG3, activebackground=BG2,
                       command=lambda: self.vault_key.config(
                           show="" if self.vault_show_key.get() else "●")).pack(side=tk.LEFT, padx=4)
        self._btn(key_f, "⚂  GENERATE",  GOLD,  BG0,   self._vault_gen_key).pack(side=tk.LEFT, padx=8)
        self._btn(key_f, "⇩  SAVE KEY",  BG3,   GOLD,  self._vault_save_key).pack(side=tk.LEFT, padx=4)
        self._btn(key_f, "▸  LOAD KEY",  BG3,   GOLD,  self._vault_load_key).pack(side=tk.LEFT, padx=4)

        # ── Progress bar ─────────────────────────────────────────
        prog_f = tk.Frame(tab, bg=BG0)
        prog_f.pack(fill=tk.X, padx=12, pady=2)
        self.vault_progress = ttk.Progressbar(prog_f, maximum=100, mode="determinate")
        self.vault_progress.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.vault_prog_lbl = tk.Label(prog_f, text="", bg=BG0, fg=TEXT_DIM, font=F_TINY)
        self.vault_prog_lbl.pack(side=tk.LEFT, padx=8)

        # ── Main split: left=text+files, right=vault log ─────────
        split = tk.Frame(tab, bg=BG0)
        split.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

        left = tk.Frame(split, bg=BG1)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,6))

        # Text section
        text_hdr = tk.Frame(left, bg=BG1)
        text_hdr.pack(fill=tk.X)
        tk.Label(text_hdr, text="TEXT  ENCRYPT / DECRYPT",
                 bg=BG1, fg=CYAN_LT, font=F_TINY, pady=6).pack(side=tk.LEFT, padx=8)
        tk.Label(text_hdr,
                 text="Type or paste text — encrypted/decrypted result replaces it.",
                 bg=BG1, fg=TEXT_DIM, font=F_TINY).pack(side=tk.LEFT)

        self.vault_text = scrolledtext.ScrolledText(
            left, bg=BG1, fg=GOLD_LT, font=F_MONO,
            insertbackground=GOLD, relief="flat", height=8)
        self.vault_text.pack(fill=tk.X, padx=8, pady=(0,4))

        txt_btns = tk.Frame(left, bg=BG1)
        txt_btns.pack(fill=tk.X, padx=8, pady=4)
        self._btn(txt_btns, "⌬  ENCRYPT TEXT", CYAN_LT, BG0,  self._vault_encrypt).pack(side=tk.LEFT, padx=4)
        self._btn(txt_btns, "◇  DECRYPT TEXT", GREEN,   BG0,  self._vault_decrypt).pack(side=tk.LEFT, padx=4)
        self._btn(txt_btns, "▤  COPY RESULT",  BG3,     GOLD, self._vault_copy).pack(side=tk.LEFT, padx=4)
        self._btn(txt_btns, "⌫  CLEAR",        BG3,     TEXT,
                  lambda: self.vault_text.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=4)

        # File / Video section
        file_hdr = tk.Frame(left, bg=BG2, pady=6)
        file_hdr.pack(fill=tk.X, padx=8, pady=(8,0))
        tk.Label(file_hdr, text="FILE / VIDEO ENCRYPT / DECRYPT",
                 bg=BG2, fg=CYAN_LT, font=F_TINY, padx=8).pack(side=tk.LEFT)
        tk.Label(file_hdr,
                 text="Works with ANY file: .mp4 .avi .mkv .pdf .docx .jpg .zip ...",
                 bg=BG2, fg=TEXT_DIM, font=F_TINY).pack(side=tk.LEFT, padx=8)

        file_btns = tk.Frame(left, bg=BG1)
        file_btns.pack(fill=tk.X, padx=8, pady=4)
        for label, color, fg_c, cmd in [
            ("⌬  ENCRYPT FILE",  CYAN_LT,  BG0,   self._vault_enc_file),
            ("◇  DECRYPT FILE",  GREEN,    BG0,   self._vault_dec_file),
            ("▶  ENCRYPT VIDEO", RED,      WHITE, self._vault_enc_video),
            ("▶  DECRYPT VIDEO", GREEN_LT, BG0,   self._vault_dec_video),
            ("▸  BATCH ENCRYPT", AMBER,    BG0,   self._vault_batch_enc),
            ("▸  BATCH DECRYPT", GOLD,     BG0,   self._vault_batch_dec),
        ]:
            self._btn(file_btns, label, color, fg_c, cmd).pack(side=tk.LEFT, padx=3)

        # Supported formats info
        fmt_f = tk.Frame(left, bg=BG2, pady=6)
        fmt_f.pack(fill=tk.X, padx=8, pady=(8,0))
        tk.Label(fmt_f, text="SUPPORTED FILE TYPES",
                 bg=BG2, fg=TEXT_DIM, font=F_TINY).pack(anchor="w", padx=8)
        fmt_row = tk.Frame(fmt_f, bg=BG2)
        fmt_row.pack(fill=tk.X, padx=8)
        for icon, exts in [
            ("▶ Videos",  "mp4 avi mkv mov wmv"),
            ("▣ Images",  "jpg png gif bmp webp"),
            ("▭ Docs",    "pdf docx xlsx pptx"),
            ("▪ Archives","zip rar 7z tar gz"),
            ("⇩ Any",     "exe dll bin iso ..."),
        ]:
            f2 = tk.Frame(fmt_row, bg=BG2)
            f2.pack(side=tk.LEFT, padx=10, pady=2)
            tk.Label(f2, text=icon, bg=BG2, fg=CYAN_LT, font=F_TINY).pack(side=tk.LEFT)
            tk.Label(f2, text=f" {exts}", bg=BG2, fg=TEXT_DIM, font=F_TINY).pack(side=tk.LEFT)

        # Right panel: vault log
        right = tk.Frame(split, bg=BG1, width=260)
        right.pack(side=tk.RIGHT, fill=tk.Y)
        right.pack_propagate(False)
        tk.Label(right, text="VAULT LOG", bg=BG1, fg=GOLD, font=F_TINY, pady=8).pack()
        tk.Frame(right, bg=GOLD_DIM, height=1).pack(fill=tk.X)
        self.vault_log = scrolledtext.ScrolledText(
            right, bg=BG1, fg=TEXT, font=F_TINY,
            relief="flat", state="disabled", height=12)
        self.vault_log.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.vault_log.tag_config("ok",   foreground=GREEN)
        self.vault_log.tag_config("err",  foreground=RED)
        self.vault_log.tag_config("info", foreground=GOLD)
        self.vault_log.tag_config("dim",  foreground=TEXT_DIM)

        self.vault_status = tk.Label(right, text="Ready",
                                     bg=BG1, fg=TEXT_DIM, font=F_MONO_S, wraplength=240)
        self.vault_status.pack(padx=8, pady=6)

    # ── Vault helpers ─────────────────────────────────────────────
    def _vault_vlog(self, msg, tag="info"):
        self.vault_log.config(state="normal")
        self.vault_log.insert(tk.END,
            f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n", tag)
        self.vault_log.see(tk.END)
        self.vault_log.config(state="disabled")

    def _vault_get_cipher(self):
        key_str = self.vault_key.get().strip()
        if not key_str:
            messagebox.showwarning("Key required",
                "Enter a password key or click GENERATE."); return None
        if not CRYPTO_OK: return None
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                         salt=b"KingSabatsu_v31_2025",
                         iterations=390000, backend=default_backend())
        key = base64.urlsafe_b64encode(kdf.derive(key_str.encode()))
        return Fernet(key)

    def _vault_gen_key(self):
        import secrets, string
        chars = string.ascii_letters + string.digits + "!@#$%^&*()"
        key = "".join(secrets.choice(chars) for _ in range(32))
        self.vault_key.delete(0, tk.END)
        self.vault_key.insert(0, key)
        self.vault_status.config(text="✔ Strong key generated", fg=GREEN)
        self._vault_vlog("New key generated", "ok")

    def _vault_save_key(self):
        key = self.vault_key.get().strip()
        if not key:
            messagebox.showwarning("No key","Generate or enter a key first."); return
        path = filedialog.asksaveasfilename(
            defaultextension=".key",
            filetypes=[("Key file","*.key"),("Text","*.txt")])
        if not path: return
        try:
            with open(path, "w") as f: f.write(key)
            self.vault_status.config(text=f"✔ Key saved: {os.path.basename(path)}", fg=GREEN)
            self._vault_vlog(f"Key saved → {os.path.basename(path)}", "ok")
        except Exception as e:
            self.vault_status.config(text=str(e), fg=RED)

    def _vault_load_key(self):
        path = filedialog.askopenfilename(
            filetypes=[("Key file","*.key"),("Text","*.txt"),("All","*.*")])
        if not path: return
        try:
            with open(path) as f: key = f.read().strip()
            self.vault_key.delete(0, tk.END)
            self.vault_key.insert(0, key)
            self.vault_status.config(text=f"✔ Key loaded: {os.path.basename(path)}", fg=GREEN)
            self._vault_vlog(f"Key loaded ← {os.path.basename(path)}", "ok")
        except Exception as e:
            self.vault_status.config(text=str(e), fg=RED)

    def _vault_copy(self):
        text = self.vault_text.get(1.0, tk.END).strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.vault_status.config(text="✔ Copied to clipboard", fg=GREEN)

    def _vault_encrypt(self):
        f = self._vault_get_cipher()
        if not f: return
        text = self.vault_text.get(1.0, tk.END).strip()
        if not text: messagebox.showinfo("Empty","Type some text first."); return
        try:
            enc = f.encrypt(text.encode()).decode()
            self.vault_text.delete(1.0, tk.END)
            self.vault_text.insert(tk.END, enc)
            self.vault_status.config(text=f"✔ Encrypted ({len(text)} → {len(enc)} chars)", fg=GREEN)
            self._vault_vlog(f"Text encrypted ({len(text)} chars)", "ok")
            glog("VAULT", "Text encrypted")
        except Exception as e:
            self.vault_status.config(text=f"Error: {e}", fg=RED)

    def _vault_decrypt(self):
        f = self._vault_get_cipher()
        if not f: return
        text = self.vault_text.get(1.0, tk.END).strip()
        if not text: messagebox.showinfo("Empty","Paste encrypted text first."); return
        try:
            dec = f.decrypt(text.encode()).decode()
            self.vault_text.delete(1.0, tk.END)
            self.vault_text.insert(tk.END, dec)
            self.vault_status.config(text="✔ Text decrypted successfully", fg=GREEN)
            self._vault_vlog("Text decrypted", "ok")
            glog("VAULT", "Text decrypted")
        except Exception:
            self.vault_status.config(text="✘ Wrong key or corrupted ciphertext", fg=RED)
            self._vault_vlog("Decrypt failed — wrong key?", "err")

    # ── Chunked file processor (supports large videos) ────────────
    def _vault_process_file(self, path: str, mode: str, out_path: str = None) -> bool:
        f = self._vault_get_cipher()
        if not f: return False
        size = os.path.getsize(path)
        name = os.path.basename(path)
        if out_path is None:
            if mode == "encrypt":
                out_path = path + ".enc"
            else:
                out_path = (path[:-4] if path.endswith(".enc") else path + "_decrypted")
                if os.path.exists(out_path):
                    out_path = out_path + "_2"
        self.root.after(0, lambda: (
            self.vault_status.config(text=f"Processing {name}...", fg=AMBER),
            self.vault_progress.__setitem__("value", 0),
            self.vault_prog_lbl.config(text="0%")))
        try:
            CHUNK = 10 * 1024 * 1024  # 10 MB
            with open(path, "rb") as fin, open(out_path, "wb") as fout:
                if mode == "encrypt":
                    if size <= CHUNK * 5:
                        data = fin.read()
                        fout.write(f.encrypt(data))
                    else:
                        buf = bytearray()
                        done = 0
                        while True:
                            chunk = fin.read(CHUNK)
                            if not chunk: break
                            buf.extend(chunk)
                            done += len(chunk)
                            pct = int(done / size * 50)
                            self.root.after(0, lambda p=pct: (
                                self.vault_progress.__setitem__("value", p),
                                self.vault_prog_lbl.config(text=f"{p}% reading...")))
                        fout.write(f.encrypt(bytes(buf)))
                else:
                    fout.write(f.decrypt(fin.read()))
            out_size = os.path.getsize(out_path)
            msg = (f"{'Encrypted' if mode=='encrypt' else 'Decrypted'}: {name} "
                   f"({self._fmt_size(size)} → {self._fmt_size(out_size)})")
            self.root.after(0, lambda: (
                self.vault_progress.__setitem__("value", 100),
                self.vault_prog_lbl.config(text="100% ✔"),
                self.vault_status.config(text=f"✔ {msg}", fg=GREEN),
                self._vault_vlog(msg, "ok")))
            glog("VAULT", msg)
            return True
        except Exception as e:
            err = str(e)[:60]
            self.root.after(0, lambda: (
                self.vault_status.config(text="✘ Failed — wrong key or file corrupted", fg=RED),
                self._vault_vlog(f"Error: {err}", "err")))
            if os.path.exists(out_path):
                try: os.remove(out_path)
                except: pass
            return False

    def _fmt_size(self, size: int) -> str:
        if size < 1024:       return f"{size} B"
        elif size < 1024**2:  return f"{size/1024:.1f} KB"
        elif size < 1024**3:  return f"{size/1024**2:.1f} MB"
        else:                 return f"{size/1024**3:.2f} GB"

    def _vault_enc_file(self):
        f = self._vault_get_cipher()
        if not f: return
        path = filedialog.askopenfilename(title="Select file to encrypt")
        if not path: return
        self._vault_vlog(f"Encrypting: {os.path.basename(path)}", "info")
        threading.Thread(target=self._vault_process_file, args=(path,"encrypt"), daemon=True).start()

    def _vault_dec_file(self):
        f = self._vault_get_cipher()
        if not f: return
        path = filedialog.askopenfilename(title="Select file to decrypt",
            filetypes=[("Encrypted","*.enc"),("All","*.*")])
        if not path: return
        self._vault_vlog(f"Decrypting: {os.path.basename(path)}", "info")
        threading.Thread(target=self._vault_process_file, args=(path,"decrypt"), daemon=True).start()

    def _vault_enc_video(self):
        f = self._vault_get_cipher()
        if not f: return
        path = filedialog.askopenfilename(title="Select video to encrypt",
            filetypes=[("Video","*.mp4 *.avi *.mkv *.mov *.wmv *.flv *.webm"),("All","*.*")])
        if not path: return
        size = os.path.getsize(path)
        self._vault_vlog(f"Encrypting video: {os.path.basename(path)} ({self._fmt_size(size)})", "info")
        messagebox.showinfo("Encrypting Video",
            f"File: {os.path.basename(path)}\nSize: {self._fmt_size(size)}\n\n"
            f"Large videos may take a minute.\nEncrypted → {os.path.basename(path)}.enc\n\n"
            f"Keep your key safe — you need it to decrypt!")
        threading.Thread(target=self._vault_process_file, args=(path,"encrypt"), daemon=True).start()

    def _vault_dec_video(self):
        f = self._vault_get_cipher()
        if not f: return
        path = filedialog.askopenfilename(title="Select encrypted video (.enc)",
            filetypes=[("Encrypted","*.enc"),("All","*.*")])
        if not path: return
        self._vault_vlog(f"Decrypting video: {os.path.basename(path)}", "info")
        threading.Thread(target=self._vault_process_file, args=(path,"decrypt"), daemon=True).start()

    def _vault_batch_enc(self):
        f = self._vault_get_cipher()
        if not f: return
        paths = filedialog.askopenfilenames(title="Select files to encrypt (multi-select)")
        if not paths: return
        self._vault_vlog(f"Batch encrypt: {len(paths)} files", "info")
        def worker():
            ok = fail = 0
            for path in paths:
                if self._vault_process_file(path, "encrypt"): ok += 1
                else: fail += 1
            self.root.after(0, lambda: (
                self.vault_status.config(text=f"✔ Batch done: {ok} encrypted, {fail} failed", fg=GREEN),
                self._vault_vlog(f"Batch complete: {ok} ok, {fail} failed", "ok")))
        threading.Thread(target=worker, daemon=True).start()

    def _vault_batch_dec(self):
        f = self._vault_get_cipher()
        if not f: return
        paths = filedialog.askopenfilenames(title="Select .enc files to decrypt",
            filetypes=[("Encrypted","*.enc"),("All","*.*")])
        if not paths: return
        self._vault_vlog(f"Batch decrypt: {len(paths)} files", "info")
        def worker():
            ok = fail = 0
            for path in paths:
                if self._vault_process_file(path, "decrypt"): ok += 1
                else: fail += 1
            self.root.after(0, lambda: (
                self.vault_status.config(text=f"✔ Batch done: {ok} decrypted, {fail} failed", fg=GREEN),
                self._vault_vlog(f"Batch complete: {ok} ok, {fail} failed", "ok")))
        threading.Thread(target=worker, daemon=True).start()

    # ════════════════════════════════════════
    #  CVE THREAT INTELLIGENCE TAB
    # ════════════════════════════════════════
    def _build_cve(self, tab):
        top = tk.Frame(tab, bg=BG1, pady=10)
        top.pack(fill=tk.X, padx=12, pady=(12,0))
        tk.Label(top, text="⊕  CVE THREAT INTELLIGENCE LOOKUP",
                 bg=BG1, fg=GOLD_LT, font=F_HEAD, padx=16).pack(side=tk.LEFT)
        tk.Label(top, text="Powered by NVD / CIRCL API",
                 bg=BG2, fg=TEXT_DIM, font=F_TINY, padx=10, pady=4).pack(side=tk.RIGHT, padx=16)

        if not REQUESTS_OK:
            tk.Label(tab, text="⚠  pip install requests  to enable CVE lookups.",
                     bg=BG0, fg=AMBER, font=F_HEAD).pack(pady=40)
            return

        # Search controls
        ctrl = tk.Frame(tab, bg=BG2, pady=10)
        ctrl.pack(fill=tk.X, padx=12, pady=6)

        tk.Label(ctrl, text="CVE ID / KEYWORD:", bg=BG2, fg=TEXT_DIM,
                 font=F_TINY).grid(row=0, column=0, padx=(14,4), sticky="w")
        self.cve_query = tk.Entry(ctrl, bg=BG3, fg=GOLD_LT, insertbackground=GOLD,
                                  font=F_MONO, width=28, relief="flat", bd=4)
        self.cve_query.insert(0, "CVE-2021-44228")
        self.cve_query.grid(row=0, column=1, padx=4)
        self.cve_query.bind("<Return>", lambda e: self._cve_search())

        tk.Label(ctrl, text="MAX RESULTS:", bg=BG2, fg=TEXT_DIM,
                 font=F_TINY).grid(row=0, column=2, padx=(16,4))
        self.cve_max = ttk.Combobox(ctrl, values=["5","10","20","50"],
                                    width=5, state="readonly", font=F_MONO)
        self.cve_max.set("10")
        self.cve_max.grid(row=0, column=3, padx=4)

        self._btn(ctrl, "⌕  SEARCH", GOLD, BG0, self._cve_search).grid(row=0, column=4, padx=16)
        self._btn(ctrl, "⇩  EXPORT", BG3,  GOLD, self._cve_export).grid(row=0, column=5, padx=4)

        self.cve_status = tk.StringVar(value="Enter a CVE ID (e.g. CVE-2021-44228) or keyword")
        tk.Label(ctrl, textvariable=self.cve_status,
                 bg=BG2, fg=TEXT_DIM, font=F_TINY).grid(row=1, column=0, columnspan=6,
                                                          padx=14, pady=(4,0), sticky="w")

        # Results split
        split = tk.Frame(tab, bg=BG0)
        split.pack(fill=tk.BOTH, expand=True, padx=12, pady=6)

        # CVE list table
        left = tk.Frame(split, bg=BG1)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,6))
        tk.Label(left, text="RESULTS  (click to see full details)",
                 bg=BG1, fg=GOLD, font=F_TINY, pady=6).pack()

        cols = ("CVE ID","Published","CVSS","Severity","Description")
        self.cve_tree = ttk.Treeview(left, columns=cols, show="headings", height=16)
        for c, w in zip(cols, [130,100,60,90,340]):
            self.cve_tree.heading(c, text=c)
            self.cve_tree.column(c, width=w, anchor="center" if w<120 else "w")
        for tag, color in [("CRITICAL",RED),("HIGH",AMBER),("MEDIUM",GOLD),("LOW",GREEN),("NONE",TEXT_DIM)]:
            self.cve_tree.tag_configure(tag, foreground=color)
        self.cve_tree.bind("<<TreeviewSelect>>", self._cve_on_select)
        csb = ttk.Scrollbar(left, orient="vertical", command=self.cve_tree.yview)
        self.cve_tree.configure(yscrollcommand=csb.set)
        self.cve_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
        csb.pack(side=tk.RIGHT, fill=tk.Y)

        # Detail panel
        right = tk.Frame(split, bg=BG1, width=300)
        right.pack(side=tk.RIGHT, fill=tk.Y)
        right.pack_propagate(False)
        tk.Label(right, text="CVE DETAIL", bg=BG1, fg=AMBER, font=F_TINY, pady=8).pack()
        tk.Frame(right, bg=AMBER, height=1).pack(fill=tk.X)
        self.cve_detail = scrolledtext.ScrolledText(
            right, bg=BG1, fg=TEXT, font=F_MONO_S,
            relief="flat", state="disabled", wrap=tk.WORD)
        self.cve_detail.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.cve_detail.tag_config("header",   foreground=GOLD_LT)
        self.cve_detail.tag_config("critical", foreground=RED)
        self.cve_detail.tag_config("high",     foreground=AMBER)
        self.cve_detail.tag_config("medium",   foreground=GOLD)
        self.cve_detail.tag_config("low",      foreground=GREEN)
        self.cve_detail.tag_config("label",    foreground=CYAN_LT)
        self._cve_data = []

    def _cve_search(self):
        query = self.cve_query.get().strip()
        if not query: return
        max_r = int(self.cve_max.get())
        cache_key = f"{query.upper()}::{max_r}"

        # v4.0 — serve from SQLite cache if fresh, skip the network entirely
        try:
            cached = db.cve_cache_get(cache_key, max_age_hours=CVE_CACHE_HOURS)
        except Exception:
            cached = None
        if cached is not None:
            self.cve_status.set(f"Searching for: {query} ...")
            self.cve_tree.delete(*self.cve_tree.get_children())
            self._cve_display(cached, query, from_cache=True)
            return

        self.cve_status.set(f"Searching for: {query} ...")
        self.cve_tree.delete(*self.cve_tree.get_children())
        self._cve_data = []
        glog("CVE", f"Lookup: {query}")

        def worker():
            results = []
            try:
                headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
                # Try NVD API first (no key needed for basic queries, but rate-limited without one)
                if query.upper().startswith("CVE-"):
                    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={query.upper()}"
                else:
                    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage={max_r}"
                resp = requests.get(url, headers=headers, timeout=10)
                if resp.status_code == 429:
                    self.root.after(0, lambda: self.cve_status.set(
                        "✘ NVD rate limit hit — add an API key in Settings, or wait 30s"))
                    glog("CVE", "NVD rate limit (429)", "WARN")
                    return
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("vulnerabilities", [])[:max_r]:
                        cve = item.get("cve", {})
                        cve_id    = cve.get("id","N/A")
                        published = cve.get("published","")[:10]
                        descs     = cve.get("descriptions",[])
                        desc      = next((d["value"] for d in descs if d.get("lang")=="en"),
                                         "No description available.")
                        # CVSS score
                        metrics = cve.get("metrics",{})
                        score   = "N/A"
                        sev     = "NONE"
                        for key in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
                            if key in metrics and metrics[key]:
                                m = metrics[key][0]
                                score = str(m.get("cvssData",{}).get("baseScore","N/A"))
                                sev   = m.get("cvssData",{}).get("baseSeverity",
                                        m.get("baseSeverity","NONE")).upper()
                                break
                        results.append({
                            "id": cve_id, "published": published,
                            "score": score, "severity": sev,
                            "desc": desc, "raw": cve
                        })
                    try:
                        db.cve_cache_set(cache_key, results)
                    except Exception:
                        pass
            except requests.exceptions.ConnectionError:
                self.root.after(0, lambda: self.cve_status.set(
                    "✘ No internet connection — CVE lookup requires internet access"))
                glog("CVE", "Network error — no connection", "ERROR")
                return
            except Exception as e:
                self.root.after(0, lambda: self.cve_status.set(f"✘ API error: {str(e)[:60]}"))
                glog("CVE", f"Search error: {e}", "ERROR")
                return

            self.root.after(0, lambda: self._cve_display(results, query))

        threading.Thread(target=worker, daemon=True).start()

    def _cve_display(self, results, query, from_cache=False):
        self._cve_data = results
        self.cve_tree.delete(*self.cve_tree.get_children())
        for r in results:
            desc_short = r["desc"][:80] + "..." if len(r["desc"]) > 80 else r["desc"]
            tag = r["severity"] if r["severity"] in ("CRITICAL","HIGH","MEDIUM","LOW") else "NONE"
            self.cve_tree.insert("", "end",
                values=(r["id"], r["published"], r["score"], r["severity"], desc_short),
                tags=(tag,))
        count = len(results)
        cache_note = " (from cache)" if from_cache else ""
        self.cve_status.set(f"✔ Found {count} result(s) for: {query}{cache_note}")
        glog("CVE", f"Search complete — {count} results for '{query}'{cache_note}")
        if results:
            first = self.cve_tree.get_children()[0]
            self.cve_tree.selection_set(first)
            self._cve_show_detail(results[0])

    def _cve_on_select(self, event):
        sel = self.cve_tree.selection()
        if not sel: return
        idx = self.cve_tree.index(sel[0])
        if idx < len(self._cve_data):
            self._cve_show_detail(self._cve_data[idx])

    def _cve_show_detail(self, r: dict):
        self.cve_detail.config(state="normal")
        self.cve_detail.delete(1.0, tk.END)
        sev_tag = r["severity"].lower() if r["severity"] in ("CRITICAL","HIGH","MEDIUM","LOW") else "label"
        self.cve_detail.insert(tk.END, f"{r['id']}\n", "header")
        self.cve_detail.insert(tk.END, f"Severity: ", "label")
        self.cve_detail.insert(tk.END, f"{r['severity']}  (CVSS: {r['score']})\n", sev_tag)
        self.cve_detail.insert(tk.END, f"Published: ", "label")
        self.cve_detail.insert(tk.END, f"{r['published']}\n\n")
        self.cve_detail.insert(tk.END, "DESCRIPTION\n", "label")
        self.cve_detail.insert(tk.END, f"{r['desc']}\n\n")
        # References
        raw = r.get("raw", {})
        refs = raw.get("references", [])
        if refs:
            self.cve_detail.insert(tk.END, "REFERENCES\n", "label")
            for ref in refs[:8]:
                self.cve_detail.insert(tk.END, f"• {ref.get('url','')}\n")
        # CWE
        weaknesses = raw.get("weaknesses", [])
        if weaknesses:
            self.cve_detail.insert(tk.END, "\nCWE\n", "label")
            for w in weaknesses:
                for d in w.get("description", []):
                    self.cve_detail.insert(tk.END, f"• {d.get('value','')}\n")
        self.cve_detail.config(state="disabled")

    def _cve_export(self):
        if not self._cve_data:
            messagebox.showinfo("Nothing to export","Run a search first."); return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON","*.json"),("Text","*.txt")],
            initialfile=f"cve_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        if not path: return
        try:
            with open(path, "w") as f:
                json.dump(self._cve_data, f, indent=2, default=str)
            messagebox.showinfo("Exported", f"CVE data saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ════════════════════════════════════════
    #  NETWORK DEVICE MAPPER TAB
    # ════════════════════════════════════════
    def _build_netmapper(self, tab):
        top = tk.Frame(tab, bg=BG1, pady=10)
        top.pack(fill=tk.X, padx=12, pady=(12,0))
        tk.Label(top, text="⌖  NETWORK DEVICE MAPPER",
                 bg=BG1, fg=GREEN_LT, font=F_HEAD, padx=16).pack(side=tk.LEFT)
        tk.Label(top, text="Scans YOUR local network only",
                 bg=BG2, fg=AMBER, font=F_TINY, padx=10, pady=4).pack(side=tk.RIGHT, padx=16)

        ctrl = tk.Frame(tab, bg=BG2, pady=10)
        ctrl.pack(fill=tk.X, padx=12, pady=6)

        tk.Label(ctrl, text="SUBNET (CIDR):", bg=BG2, fg=TEXT_DIM,
                 font=F_TINY).grid(row=0, column=0, padx=(14,4), sticky="w")
        self.nm_subnet = tk.Entry(ctrl, bg=BG3, fg=GOLD_LT, insertbackground=GOLD,
                                  font=F_MONO, width=20, relief="flat", bd=4)
        self.nm_subnet.insert(0, "192.168.1.0/24")
        self.nm_subnet.grid(row=0, column=1, padx=4)

        tk.Label(ctrl, text="TIMEOUT ms:", bg=BG2, fg=TEXT_DIM,
                 font=F_TINY).grid(row=0, column=2, padx=(16,4))
        self.nm_timeout = tk.Entry(ctrl, bg=BG3, fg=GOLD_LT, insertbackground=GOLD,
                                   font=F_MONO, width=6, relief="flat", bd=4)
        self.nm_timeout.insert(0, "300")
        self.nm_timeout.grid(row=0, column=3, padx=4)

        tk.Label(ctrl, text="PROBE PORTS:", bg=BG2, fg=TEXT_DIM,
                 font=F_TINY).grid(row=0, column=4, padx=(16,4))
        self.nm_ports = tk.Entry(ctrl, bg=BG3, fg=GOLD_LT, insertbackground=GOLD,
                                 font=F_MONO, width=22, relief="flat", bd=4)
        self.nm_ports.insert(0, "22,80,443,445,3389,8080")
        self.nm_ports.grid(row=0, column=5, padx=4)

        self.nm_btn  = self._btn(ctrl, "▶  SCAN NETWORK", GREEN, BG0, self._nm_scan)
        self.nm_btn.grid(row=0, column=6, padx=14)
        self.nm_stop_btn = self._btn(ctrl, "■  STOP", RED, WHITE, self._nm_stop)
        self.nm_stop_btn.grid(row=0, column=7, padx=4)
        self.nm_stop_btn.config(state="disabled")

        # Progress
        pf = tk.Frame(tab, bg=BG0)
        pf.pack(fill=tk.X, padx=12, pady=2)
        self.nm_pv = tk.DoubleVar()
        ttk.Progressbar(pf, variable=self.nm_pv, maximum=100).pack(
            side=tk.LEFT, fill=tk.X, expand=True)
        self.nm_sv = tk.StringVar(value="Ready")
        tk.Label(pf, textvariable=self.nm_sv, bg=BG0, fg=TEXT_DIM,
                 font=F_TINY).pack(side=tk.LEFT, padx=10)

        # Summary cards
        cards = tk.Frame(tab, bg=BG0)
        cards.pack(fill=tk.X, padx=12, pady=6)
        self.nm_stat_vars = {}
        for label, color in [("HOSTS SCANNED",GOLD),("ALIVE",GREEN),("OPEN PORTS",RED),("UNIQUE SERVICES",CYAN_LT)]:
            c = tk.Frame(cards, bg=BG2, padx=16, pady=10)
            c.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=6)
            tk.Label(c, text=label, bg=BG2, fg=TEXT_DIM, font=F_TINY).pack()
            var = tk.StringVar(value="0")
            tk.Label(c, textvariable=var, bg=BG2, fg=color,
                     font=("Courier New",20,"bold")).pack()
            self.nm_stat_vars[label] = var

        # Results
        split = tk.Frame(tab, bg=BG0)
        split.pack(fill=tk.BOTH, expand=True, padx=12, pady=6)

        left = tk.Frame(split, bg=BG1)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,6))
        tk.Label(left, text="DISCOVERED DEVICES  (click for port details)",
                 bg=BG1, fg=GREEN_LT, font=F_TINY, pady=6).pack()

        cols = ("IP Address","Hostname","Open Ports","Services","Risk","Status")
        self.nm_tree = ttk.Treeview(left, columns=cols, show="headings", height=14)
        for c, w in zip(cols, [130,160,90,200,80,80]):
            self.nm_tree.heading(c, text=c)
            self.nm_tree.column(c, width=w, anchor="center" if w<100 else "w")
        self.nm_tree.tag_configure("risky",  foreground=RED)
        self.nm_tree.tag_configure("warn",   foreground=AMBER)
        self.nm_tree.tag_configure("ok",     foreground=GREEN)
        self.nm_tree.bind("<Double-1>", self._nm_show_detail)
        nmsb = ttk.Scrollbar(left, orient="vertical", command=self.nm_tree.yview)
        self.nm_tree.configure(yscrollcommand=nmsb.set)
        self.nm_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
        nmsb.pack(side=tk.RIGHT, fill=tk.Y)

        bot = tk.Frame(left, bg=BG1, pady=4)
        bot.pack(fill=tk.X)
        self._btn(bot, "⇩ EXPORT RESULTS", GOLD, BG0, self._nm_export).pack(side=tk.LEFT, padx=8)
        self._btn(bot, "⊘ BLOCK THIS IP",  RED,  WHITE, self._nm_block_selected).pack(side=tk.LEFT, padx=4)
        self._btn(bot, "⛨ VULN SCAN THIS IP", GREEN, BG0, self._nm_vulnscan_selected).pack(side=tk.LEFT, padx=4)
        self._btn(bot, "⊕ CVE LOOKUP", CYAN, BG0, self._nm_cve_selected).pack(side=tk.LEFT, padx=4)

        # Network topology text panel
        right = tk.Frame(split, bg=BG1, width=260)
        right.pack(side=tk.RIGHT, fill=tk.Y)
        right.pack_propagate(False)
        tk.Label(right, text="DEVICE DETAIL", bg=BG1, fg=GREEN_LT, font=F_TINY, pady=8).pack()
        tk.Frame(right, bg=GREEN, height=1).pack(fill=tk.X)
        self.nm_detail = scrolledtext.ScrolledText(
            right, bg=BG1, fg=TEXT, font=F_MONO_S,
            relief="flat", state="disabled", wrap=tk.WORD)
        self.nm_detail.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.nm_detail.tag_config("header", foreground=GREEN_LT)
        self.nm_detail.tag_config("label",  foreground=CYAN_LT)
        self.nm_detail.tag_config("risky",  foreground=RED)
        self.nm_detail.tag_config("ok",     foreground=GREEN)

        self._nm_running  = False
        self._nm_results  = []

    def _nm_scan(self):
        subnet_str = self.nm_subnet.get().strip()
        try:
            network = ipaddress.IPv4Network(subnet_str, strict=False)
        except ValueError as e:
            messagebox.showerror("Invalid subnet", str(e)); return
        try:
            timeout = int(self.nm_timeout.get()) / 1000
        except Exception:
            timeout = 0.3
        try:
            probe_ports = [int(p.strip()) for p in self.nm_ports.get().split(",") if p.strip().isdigit()]
        except Exception:
            probe_ports = [22, 80, 443, 445, 3389]

        hosts = list(network.hosts())
        if len(hosts) > 512:
            messagebox.showwarning("Large subnet",
                f"Subnet has {len(hosts)} hosts — limiting to first 512 for speed."); return
        if not messagebox.askyesno("Confirm Scan",
            f"Scan {len(hosts)} hosts on {subnet_str}?\n\n"
            "Only scan networks you own or have permission to test."):
            return

        self._nm_running = True
        self._nm_results = []
        self.nm_tree.delete(*self.nm_tree.get_children())
        for v in self.nm_stat_vars.values(): v.set("0")
        self.nm_btn.config(state="disabled")
        self.nm_stop_btn.config(state="normal")
        glog("NETMAP", f"Network scan started: {subnet_str} ({len(hosts)} hosts)")

        threading.Thread(target=self._nm_worker,
                         args=(hosts, probe_ports, timeout), daemon=True).start()

    def _nm_stop(self):
        self._nm_running = False
        self.nm_sv.set("Stopped")
        self.nm_btn.config(state="normal")
        self.nm_stop_btn.config(state="disabled")

    def _nm_worker(self, hosts, probe_ports, timeout):
        alive_count = 0
        open_port_total = 0
        services_seen = set()
        t0 = time.time()

        for i, host in enumerate(hosts):
            if not self._nm_running: break
            ip = str(host)
            pct = (i+1) / len(hosts) * 100
            self.root.after(0, lambda p=pct, h=ip: (
                self.nm_pv.set(p),
                self.nm_sv.set(f"Scanning {h}..."),
                self.nm_stat_vars["HOSTS SCANNED"].set(str(i+1))))

            open_ports = []
            for port in probe_ports:
                if not self._nm_running: break
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout)
                    if s.connect_ex((ip, port)) == 0:
                        svc = PORT_SERVICES.get(port, f"port/{port}")
                        open_ports.append((port, svc))
                        services_seen.add(svc)
                        open_port_total += 1
                    s.close()
                except Exception:
                    pass

            if open_ports:
                alive_count += 1
                # Try hostname resolution
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    hostname = "—"

                risky_ports = {23, 445, 3389, 3306, 27017, 6379, 11211}
                port_nums = {p for p, _ in open_ports}
                risk = "HIGH" if port_nums & risky_ports else "LOW"
                tag  = "risky" if risk == "HIGH" else "ok"

                port_str   = ", ".join(str(p) for p, _ in open_ports[:6])
                svc_str    = ", ".join(s for _, s in open_ports[:4])

                device = {
                    "ip": ip, "hostname": hostname,
                    "ports": open_ports, "risk": risk,
                }
                self._nm_results.append(device)

                self.root.after(0, lambda d=device, ps=port_str, ss=svc_str, r=risk, t=tag:
                    (self.nm_tree.insert("", "end",
                        values=(d["ip"], d["hostname"], ps, ss, r, "● ALIVE"), tags=(t,)),
                     self.nm_stat_vars["ALIVE"].set(str(alive_count)),
                     self.nm_stat_vars["OPEN PORTS"].set(str(open_port_total)),
                     self.nm_stat_vars["UNIQUE SERVICES"].set(str(len(services_seen)))))

        elapsed = time.time() - t0
        self._nm_running = False
        self.root.after(0, lambda: (
            self.nm_sv.set(f"✔ Done — {alive_count} devices found in {elapsed:.1f}s"),
            self.nm_btn.config(state="normal"),
            self.nm_stop_btn.config(state="disabled")))
        glog("NETMAP", f"Scan complete — {alive_count} alive hosts, {open_port_total} open ports")

    def _nm_show_detail(self, event):
        sel = self.nm_tree.selection()
        if not sel: return
        idx = self.nm_tree.index(sel[0])
        if idx >= len(self._nm_results): return
        d = self._nm_results[idx]
        self.nm_detail.config(state="normal")
        self.nm_detail.delete(1.0, tk.END)
        self.nm_detail.insert(tk.END, f"Device: {d['ip']}\n", "header")
        self.nm_detail.insert(tk.END, "Hostname: ", "label")
        self.nm_detail.insert(tk.END, f"{d['hostname']}\n")
        self.nm_detail.insert(tk.END, "Risk: ", "label")
        tag = "risky" if d["risk"] == "HIGH" else "ok"
        self.nm_detail.insert(tk.END, f"{d['risk']}\n\n", tag)
        self.nm_detail.insert(tk.END, "OPEN PORTS\n", "label")
        risky_ports = {23, 445, 3389, 3306, 27017, 6379, 11211}
        for port, svc in d["ports"]:
            ptag = "risky" if port in risky_ports else "ok"
            self.nm_detail.insert(tk.END, f"  {port:5}  {svc}\n", ptag)
        self.nm_detail.config(state="disabled")

    def _nm_block_selected(self):
        sel = self.nm_tree.selection()
        if not sel: messagebox.showinfo("Select device","Click a device first."); return
        ip = str(self.nm_tree.item(sel[0])["values"][0])
        rule = firewall.add_manual_rule("BLOCK", ip, "IP", "Blocked via Net Mapper")
        self._fw_insert_tree(rule)
        messagebox.showinfo("Blocked", f"IP {ip} added to firewall block rules.")
        glog("NETMAP", f"Device {ip} blocked via Net Mapper", "WARN")

    def _nm_export(self):
        if not self._nm_results:
            messagebox.showinfo("No results","Run a scan first."); return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON","*.json"),("Text","*.txt")],
            initialfile=f"network_map_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        if not path: return
        try:
            export_data = [
                {"ip": d["ip"], "hostname": d["hostname"], "risk": d["risk"],
                 "ports": [{"port": p, "service": s} for p,s in d["ports"]]}
                for d in self._nm_results
            ]
            with open(path, "w") as f:
                json.dump(export_data, f, indent=2)
            messagebox.showinfo("Exported", f"Network map saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _nm_vulnscan_selected(self):
        """Cross-wire: jump to Vuln Scan tab pre-filled with the selected device (v4.0)."""
        sel = self.nm_tree.selection()
        if not sel: messagebox.showinfo("Select device","Click a device first."); return
        ip = str(self.nm_tree.item(sel[0])["values"][0])
        self.vuln_ip.delete(0, tk.END)
        self.vuln_ip.insert(0, ip)
        self._show_page("vulnscan")
        self._vuln_scan()

    def _nm_cve_selected(self):
        """Cross-wire: jump to CVE Lookup tab with a keyword built from the device's services (v4.0)."""
        sel = self.nm_tree.selection()
        if not sel: messagebox.showinfo("Select device","Click a device first."); return
        idx = self.nm_tree.index(sel[0])
        if idx >= len(self._nm_results): return
        d = self._nm_results[idx]
        svc = d["ports"][0][1] if d["ports"] else ""
        self._show_page("cve")
        self.cve_query.delete(0, tk.END)
        self.cve_query.insert(0, svc)
        self._cve_search()

    # ════════════════════════════════════════
    #  GEO THREAT TRACKER TAB  (v4.0 — new)
    # ════════════════════════════════════════
    def _build_geotracker(self, tab):
        top = tk.Frame(tab, bg=BG1, pady=10)
        top.pack(fill=tk.X, padx=12, pady=(12,0))
        tk.Label(top, text="◎  GEO THREAT TRACKER",
                 bg=BG1, fg=CYAN_LT, font=F_HEAD, padx=16).pack(side=tk.LEFT)
        tk.Label(top, text="Geolocates blocked / flagged public IPs — private IPs are skipped",
                 bg=BG2, fg=TEXT_DIM, font=F_TINY, padx=10, pady=4).pack(side=tk.RIGHT, padx=16)

        ctrl = tk.Frame(tab, bg=BG2, pady=8)
        ctrl.pack(fill=tk.X, padx=12, pady=6)
        self._btn(ctrl, "◎  LOCATE THREATS", CYAN, BG0, self._geo_locate).pack(side=tk.LEFT, padx=14)
        self.geo_status = tk.StringVar(value="Ready — pulls from Firewall blocked IPs + top threat scores")
        tk.Label(ctrl, textvariable=self.geo_status, bg=BG2, fg=TEXT_DIM,
                 font=F_TINY).pack(side=tk.LEFT, padx=10)

        if not REQUESTS_OK:
            tk.Label(tab, text="⚠  pip install requests  to enable geolocation.",
                     bg=BG0, fg=AMBER, font=F_HEAD).pack(pady=40)
            return

        split = tk.Frame(tab, bg=BG0)
        split.pack(fill=tk.BOTH, expand=True, padx=12, pady=6)

        # Rotating globe canvas
        left = tk.Frame(split, bg=BG1, width=440)
        left.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0,6))
        left.pack_propagate(False)
        tk.Label(left, text="LIVE THREAT GLOBE", bg=BG1, fg=GOLD, font=F_TINY, pady=6).pack()
        self.geo_canvas = tk.Canvas(left, bg=BG0, highlightthickness=0)
        self.geo_canvas.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        # Defer globe creation until canvas has real size
        self.root.after(150, self._geo_init_globe)

        # Geolocated threat table
        right = tk.Frame(split, bg=BG1)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(6,0))
        tk.Label(right, text="GEOLOCATED THREAT IPs", bg=BG1, fg=CYAN_LT, font=F_TINY, pady=6).pack()
        cols = ("IP","Country","City","Score","Level")
        self.geo_tree = ttk.Treeview(right, columns=cols, show="headings", height=18)
        for c, w in zip(cols, [130,120,120,70,90]):
            self.geo_tree.heading(c, text=c)
            self.geo_tree.column(c, width=w, anchor="center" if w<100 else "w")
        for tag, color in [("CRITICAL",RED),("HIGH",AMBER),("MEDIUM",GOLD),("LOW",GREEN),("NONE",TEXT_DIM)]:
            self.geo_tree.tag_configure(tag, foreground=color)
        gsb = ttk.Scrollbar(right, orient="vertical", command=self.geo_tree.yview)
        self.geo_tree.configure(yscrollcommand=gsb.set)
        self.geo_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
        gsb.pack(side=tk.RIGHT, fill=tk.Y)

    def _geo_init_globe(self):
        w = self.geo_canvas.winfo_width() or 400
        h = self.geo_canvas.winfo_height() or 400
        r = max(60, min(w, h) // 2 - 20)
        self.geo_globe = GeoGlobe(self.geo_canvas, w/2, h/2, r)
        self.geo_globe.draw()

    def _geo_locate(self):
        # Gather candidate IPs: hard-blocked + top-scored
        ips = set(firewall.blocked_ips)
        sorted_ips = sorted(firewall.ip_scores.items(), key=lambda x: x[1], reverse=True)[:40]
        ips.update(ip for ip, _ in sorted_ips)
        ips = list(ips)
        if not ips:
            self.geo_status.set("No blocked / flagged IPs yet — run the Sandbox or wait for real traffic.")
            return
        self.geo_status.set(f"Locating {len(ips)} IP(s)...")
        glog("GEO", f"Geolocating {len(ips)} threat IP(s)")

        def worker():
            results = geolocator.locate_many(ips)
            self.root.after(0, lambda: self._geo_display(results))
        threading.Thread(target=worker, daemon=True).start()

    def _geo_display(self, results):
        self.geo_tree.delete(*self.geo_tree.get_children())
        pins = []
        for r in results:
            if r.get("lat") is None:
                continue
            level, _ = firewall.get_threat_level(r["ip"])
            tag = level if level in ("CRITICAL","HIGH","MEDIUM","LOW") else "NONE"
            score = firewall.ip_scores.get(r["ip"], 0)
            self.geo_tree.insert("", "end",
                values=(r["ip"], r.get("country","—"), r.get("city","—"),
                        f"{score:.0f}", level), tags=(tag,))
            pins.append({"lat": r["lat"], "lon": r["lon"], "severity": tag})
        if hasattr(self, "geo_globe"):
            self.geo_globe.set_pins(pins)
        self.geo_status.set(f"✔ Located {len(pins)} of {len(results)} IP(s) on the globe")
        glog("GEO", f"Located {len(pins)} threat IP(s) on the globe")

    # ════════════════════════════════════════
    #  SETTINGS TAB  (v4.0 — new)
    # ════════════════════════════════════════
    def _build_settings(self, tab):
        top = tk.Frame(tab, bg=BG1, pady=10)
        top.pack(fill=tk.X, padx=12, pady=(12,0))
        tk.Label(top, text="⚙  SETTINGS",
                 bg=BG1, fg=GOLD_LT, font=F_HEAD, padx=16).pack(side=tk.LEFT)

        body = tk.Frame(tab, bg=BG0)
        body.pack(fill=tk.BOTH, expand=True, padx=20, pady=16)

        # ── AI Firewall tuning ─────────────────────────────────
        fw_card = tk.LabelFrame(body, text=" AI FIREWALL TUNING ", bg=BG1, fg=GOLD,
                                 font=F_TINY, padx=16, pady=14, bd=1, relief="flat")
        fw_card.pack(fill=tk.X, pady=(0,14))

        self.set_entries = {}
        rows = [
            ("Auto-block score threshold", "auto_block_score", str(firewall.thresholds["auto_block_score"])),
            ("Adaptive floor (min threshold)", "adaptive_min", str(firewall.thresholds["adaptive_min"])),
            ("Score decay factor (0-1, closer to 1 = slower decay)", "decay_factor", str(firewall._decay_factor)),
        ]
        for i, (label, key, default) in enumerate(rows):
            tk.Label(fw_card, text=label, bg=BG1, fg=TEXT_DIM, font=F_TINY,
                     width=42, anchor="w").grid(row=i, column=0, sticky="w", pady=5)
            e = tk.Entry(fw_card, bg=BG3, fg=GOLD_LT, insertbackground=GOLD,
                         font=F_MONO, width=12, relief="flat", bd=4)
            e.insert(0, default)
            e.grid(row=i, column=1, padx=10, pady=5)
            self.set_entries[key] = e

        self._btn(fw_card, "✓  APPLY", GREEN, BG0, self._settings_apply_fw).grid(
            row=len(rows), column=0, columnspan=2, pady=(10,0), sticky="w")

        # ── CVE / API ───────────────────────────────────────────
        api_card = tk.LabelFrame(body, text=" NVD API ", bg=BG1, fg=GOLD,
                                  font=F_TINY, padx=16, pady=14, bd=1, relief="flat")
        api_card.pack(fill=tk.X, pady=(0,14))
        tk.Label(api_card, text="NVD API Key (optional — raises rate limit from 5 to 50 req/30s)",
                 bg=BG1, fg=TEXT_DIM, font=F_TINY, width=52, anchor="w").grid(row=0, column=0, sticky="w", pady=5)
        self.set_nvd_key = tk.Entry(api_card, bg=BG3, fg=GOLD_LT, insertbackground=GOLD,
                                    font=F_MONO, width=34, relief="flat", bd=4, show="•")
        self.set_nvd_key.insert(0, db.get_setting("nvd_api_key", ""))
        self.set_nvd_key.grid(row=0, column=1, padx=10, pady=5)
        tk.Label(api_card, text="CVE cache lifetime (hours)",
                 bg=BG1, fg=TEXT_DIM, font=F_TINY, width=52, anchor="w").grid(row=1, column=0, sticky="w", pady=5)
        self.set_cve_ttl = tk.Entry(api_card, bg=BG3, fg=GOLD_LT, insertbackground=GOLD,
                                    font=F_MONO, width=12, relief="flat", bd=4)
        self.set_cve_ttl.insert(0, db.get_setting("cve_cache_hours", "24"))
        self.set_cve_ttl.grid(row=1, column=1, padx=10, pady=5)
        self._btn(api_card, "✓  APPLY", GREEN, BG0, self._settings_apply_api).grid(
            row=2, column=0, columnspan=2, pady=(10,0), sticky="w")

        # ── Database ────────────────────────────────────────────
        db_card = tk.LabelFrame(body, text=" PERSISTENCE ", bg=BG1, fg=GOLD,
                                 font=F_TINY, padx=16, pady=14, bd=1, relief="flat")
        db_card.pack(fill=tk.X)
        tk.Label(db_card, text=f"SQLite database: {os.path.abspath(db.path)}",
                 bg=BG1, fg=TEXT_DIM, font=F_TINY, anchor="w").pack(fill=tk.X, pady=(0,8))
        self._btn(db_card, "⌫  CLEAR ALL PERSISTED DATA", RED, WHITE,
                  self._settings_wipe_db).pack(side=tk.LEFT)

        self.set_status = tk.StringVar(value="")
        tk.Label(body, textvariable=self.set_status, bg=BG0, fg=GREEN_LT,
                 font=F_TINY).pack(anchor="w", pady=10)

    def _settings_apply_fw(self):
        try:
            abs_score = float(self.set_entries["auto_block_score"].get())
            adaptive  = float(self.set_entries["adaptive_min"].get())
            decay     = float(self.set_entries["decay_factor"].get())
            if not (0 < decay <= 1):
                raise ValueError("Decay factor must be between 0 and 1")
            firewall.apply_settings(auto_block_score=abs_score,
                                    adaptive_min=adaptive, decay_factor=decay)
            self.set_status.set("✔ Firewall tuning applied and saved.")
            glog("SETTINGS", "AI Firewall thresholds updated")
        except ValueError as e:
            messagebox.showerror("Invalid value", str(e))

    def _settings_apply_api(self):
        key = self.set_nvd_key.get().strip()
        try:
            ttl = int(self.set_cve_ttl.get())
        except ValueError:
            messagebox.showerror("Invalid value", "CVE cache lifetime must be a whole number.")
            return
        db.set_setting("nvd_api_key", key)
        db.set_setting("cve_cache_hours", ttl)
        global NVD_API_KEY, CVE_CACHE_HOURS
        NVD_API_KEY = key
        CVE_CACHE_HOURS = ttl
        self.set_status.set("✔ NVD API settings saved.")
        glog("SETTINGS", "NVD API settings updated")

    def _settings_wipe_db(self):
        if not messagebox.askyesno("Clear ALL persisted data",
            "This deletes all saved firewall rules, threat scores, activity log, "
            "CVE cache, and geo cache from disk.\n\nThis does NOT affect the running "
            "session until restart. Continue?"):
            return
        try:
            db.clear_fw_rules()
            with db._lock, db._conn as c:
                c.execute("DELETE FROM fw_state")
                c.execute("DELETE FROM activity_log")
                c.execute("DELETE FROM cve_cache")
                c.execute("DELETE FROM geo_cache")
            self.set_status.set("✔ Persisted data cleared. Restart the app to see a clean slate.")
            glog("SETTINGS", "All persisted data wiped by user", "WARN")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ════════════════════════════════════════
    #  ACTIVITY LOG TAB  (v3.1 — full rebuild)
    # ════════════════════════════════════════
    def _build_log(self, tab):
        # ── Top controls ─────────────────────────────────────────
        top = tk.Frame(tab, bg=BG1, pady=8)
        top.pack(fill=tk.X, padx=12, pady=(12,0))

        tk.Label(top, text="▤  ACTIVITY LOG", bg=BG1, fg=GOLD_LT,
                 font=F_HEAD, padx=16).pack(side=tk.LEFT)

        # Right-side buttons
        self._btn(top, "⌫ CLEAR",      CRIMSON, WHITE, self._log_clear      ).pack(side=tk.RIGHT, padx=4)
        self._btn(top, "⇩ TXT",        GOLD,    BG0,   self._log_export_txt ).pack(side=tk.RIGHT, padx=4)
        self._btn(top, "⇩ CSV",        GOLD,    BG0,   self._log_export_csv ).pack(side=tk.RIGHT, padx=4)
        self._btn(top, "⇩ JSON",       GOLD,    BG0,   self._log_export_json).pack(side=tk.RIGHT, padx=4)

        # ── Filter bar ────────────────────────────────────────────
        fbar = tk.Frame(tab, bg=BG2, pady=8)
        fbar.pack(fill=tk.X, padx=12, pady=4)

        tk.Label(fbar, text="LEVEL:", bg=BG2, fg=TEXT_DIM, font=F_TINY).pack(side=tk.LEFT, padx=(12,4))
        self.log_filter_level = ttk.Combobox(fbar,
            values=["ALL","DEBUG","INFO","WARN","ERROR","CRITICAL"],
            width=10, state="readonly", font=F_MONO)
        self.log_filter_level.set("ALL")
        self.log_filter_level.pack(side=tk.LEFT, padx=4)
        self.log_filter_level.bind("<<ComboboxSelected>>", lambda e: self._log_refresh())

        tk.Label(fbar, text="SOURCE:", bg=BG2, fg=TEXT_DIM, font=F_TINY).pack(side=tk.LEFT, padx=(16,4))
        self.log_filter_source = ttk.Combobox(fbar,
            values=["ALL"], width=12, state="readonly", font=F_MONO)
        self.log_filter_source.set("ALL")
        self.log_filter_source.pack(side=tk.LEFT, padx=4)
        self.log_filter_source.bind("<<ComboboxSelected>>", lambda e: self._log_refresh())

        tk.Label(fbar, text="SEARCH:", bg=BG2, fg=TEXT_DIM, font=F_TINY).pack(side=tk.LEFT, padx=(16,4))
        self.log_search_var = tk.StringVar()
        self.log_search_var.trace("w", lambda *_: self._log_refresh())
        self.log_search_entry = tk.Entry(fbar, textvariable=self.log_search_var,
                                         bg=BG3, fg=GOLD_LT, insertbackground=GOLD,
                                         font=F_MONO, width=26, relief="flat", bd=4)
        self.log_search_entry.pack(side=tk.LEFT, padx=4)

        self._btn(fbar, "✕ CLEAR SEARCH", BG3, TEXT_DIM,
                  lambda: self.log_search_var.set("")).pack(side=tk.LEFT, padx=6)

        # Auto-scroll toggle
        self.log_autoscroll = tk.BooleanVar(value=True)
        tk.Checkbutton(fbar, text="Auto-scroll", variable=self.log_autoscroll,
                       bg=BG2, fg=TEXT_DIM, font=F_TINY, selectcolor=BG3,
                       activebackground=BG2).pack(side=tk.LEFT, padx=16)

        # Live counter
        self.log_count_var = tk.StringVar(value="0 records")
        tk.Label(fbar, textvariable=self.log_count_var,
                 bg=BG2, fg=GOLD_DIM, font=F_TINY).pack(side=tk.RIGHT, padx=12)

        # ── Log text area ─────────────────────────────────────────
        self.log_text = scrolledtext.ScrolledText(
            tab, bg=BG1, fg=TEXT, font=F_MONO_S,
            relief="flat", insertbackground=GOLD, state="disabled")
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=12, pady=(4,12))

        # Tag colours
        self.log_text.tag_config("INFO",     foreground=TEXT)
        self.log_text.tag_config("WARN",     foreground=AMBER)
        self.log_text.tag_config("ERROR",    foreground=RED)
        self.log_text.tag_config("CRITICAL", foreground=RED_LT)
        self.log_text.tag_config("DEBUG",    foreground=TEXT_DIM)
        self.log_text.tag_config("dim",      foreground=TEXT_DIM)
        self.log_text.tag_config("source",   foreground=GOLD)
        self.log_text.tag_config("seq",      foreground=GOLD_DIM)

        # Track last rendered seq to avoid full redraws
        self._log_last_seq = 0
        self._log_pending_refresh = False

    def _log_append(self, record: dict):
        """Called via bus — append a single new record if filters match."""
        level  = self.log_filter_level.get() if hasattr(self, "log_filter_level") else "ALL"
        source = self.log_filter_source.get() if hasattr(self, "log_filter_source") else "ALL"
        search = self.log_search_var.get()    if hasattr(self, "log_search_var")    else ""

        if level  != "ALL" and record["level"]  != level:  return
        if source != "ALL" and record["source"] != source: return
        if search and search.lower() not in record["message"].lower() \
                  and search.lower() not in record["source"].lower():  return

        self._log_render_record(record)
        self._log_update_source_dropdown()
        self.log_count_var.set(f"{len(log.get_all())} records")

    def _log_render_record(self, record: dict):
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, f"#{record['seq']:<5} ", "seq")
        self.log_text.insert(tk.END, f"[{record['time']}] ", "dim")
        self.log_text.insert(tk.END, f"{record['source']:12} ", "source")
        self.log_text.insert(tk.END, f"[{record['level']:8}] ", record["level"])
        self.log_text.insert(tk.END, f"{record['message']}\n", record["level"])
        if self.log_autoscroll.get():
            self.log_text.see(tk.END)
        self.log_text.config(state="disabled")

    def _log_refresh(self):
        """Full redraw when filter changes."""
        if self._log_pending_refresh:
            return
        self._log_pending_refresh = True
        self.root.after(100, self._log_do_refresh)

    def _log_do_refresh(self):
        self._log_pending_refresh = False
        level  = self.log_filter_level.get()
        source = self.log_filter_source.get()
        search = self.log_search_var.get()
        records = log.filtered(
            level  = level  if level  != "ALL" else None,
            source = source if source != "ALL" else None,
            search = search or None,
        )
        self.log_text.config(state="normal")
        self.log_text.delete(1.0, tk.END)
        for record in reversed(records):
            self._log_render_record(record)
        self.log_text.config(state="disabled")
        self.log_count_var.set(f"{len(records)} records (filtered)")

    def _log_update_source_dropdown(self):
        sources = ["ALL"] + log.sources()
        current = self.log_filter_source.get()
        self.log_filter_source["values"] = sources
        if current not in sources:
            self.log_filter_source.set("ALL")

    def _log_clear(self):
        log.clear()
        self.log_text.config(state="normal")
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state="disabled")
        self.log_count_var.set("0 records")

    def _log_export_txt(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text","*.txt"),("All","*.*")],
            initialfile=f"king_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        if not path: return
        try:
            log.export_txt(path)
            messagebox.showinfo("Exported", f"Log saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _log_export_csv(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV","*.csv"),("All","*.*")],
            initialfile=f"king_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        if not path: return
        try:
            log.export_csv(path)
            messagebox.showinfo("Exported", f"CSV saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _log_export_json(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON","*.json"),("All","*.*")],
            initialfile=f"king_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        if not path: return
        try:
            log.export_json(path)
            messagebox.showinfo("Exported", f"JSON saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ════════════════════════════════════════
    #  SHARED HELPERS
    # ════════════════════════════════════════
    def _btn(self, parent, text, bg, fg, cmd, width=None):
        kw = dict(text=text, bg=bg, fg=fg,
                  font=("Courier New",9,"bold"), relief="flat",
                  padx=12, pady=6, cursor="hand2", command=cmd,
                  activebackground=bg, activeforeground=fg)
        if width: kw["width"] = width
        return tk.Button(parent, **kw)

    def _start_clock(self):
        def tick():
            self.clock_var.set(datetime.now().strftime("%Y-%m-%d   %H:%M:%S"))
            self.root.after(1000, tick)
        tick()

    def _start_live_updates(self):
        def update():
            # Header stats
            self.hdr_stats["THREATS"].set(str(len(firewall.blocked_ips)))
            self.hdr_stats["BLOCKED"].set(str(firewall.stats["total_blocked"]))
            self.hdr_stats["ALERTS"].set(str(ids.stats["total_alerts"]))

            # Dashboard cards
            if hasattr(self, "dash_vars"):
                self.dash_vars["total_seen"].set(str(firewall.stats["total_seen"]))
                self.dash_vars["total_blocked"].set(str(firewall.stats["total_blocked"]))
                self.dash_vars["auto_blocked"].set(str(firewall.stats["auto_blocked"]))
                self.dash_vars["ids_alerts"].set(str(ids.stats["total_alerts"]))
                self.dash_vars["rules"].set(str(len(firewall.rules)))
                self.dash_vars["ai_rules"].set(str(len(firewall.auto_rules)))

            # IDS stat cards
            if hasattr(self, "ids_stat_vars"):
                self.ids_stat_vars["total"].set(str(ids.stats["total_alerts"]))
                self.ids_stat_vars["critical"].set(str(ids.stats["critical"]))
                self.ids_stat_vars["high"].set(str(ids.stats["high"]))
                self.ids_stat_vars["medium"].set(str(ids.stats["medium"]))

            # AI threat scores panel
            if hasattr(self, "fw_scores_text") and firewall.ip_scores:
                self.fw_scores_text.config(state="normal")
                self.fw_scores_text.delete(1.0, tk.END)
                sorted_ips = sorted(firewall.ip_scores.items(),
                                    key=lambda x: x[1], reverse=True)[:25]
                for ip, score in sorted_ips:
                    level, _ = firewall.get_threat_level(ip)
                    blocked  = "⊘" if ip in firewall.blocked_ips else "  "
                    tag = level if level in ("CRITICAL","HIGH","MEDIUM") else ""
                    self.fw_scores_text.insert(tk.END,
                        f"{blocked} {ip:16} {score:6.1f}  {level}\n", tag)
                self.fw_scores_text.config(state="disabled")

            # Threat feed (from attack log)
            if hasattr(self, "threat_feed") and firewall.attack_log:
                entry = firewall.attack_log[0]
                level, _ = firewall.get_threat_level(entry["ip"])
                tag = level.lower() if level != "NONE" else "ok"
                self.threat_feed.config(state="normal")
                self.threat_feed.insert(tk.END,
                    f"[{entry['time']}] {entry['ip']:15} "
                    f"| {entry['type']:14} | Score:{entry['score']:7.1f} | {level}\n", tag)
                self.threat_feed.see(tk.END)
                self.threat_feed.config(state="disabled")

            self.root.after(900, update)
        self.root.after(1200, update)


# ═══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    root = tk.Tk()
    app  = BastionApp(root)
    root.mainloop()
