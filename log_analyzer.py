#!/usr/bin/env python3
"""
Log Analyzer & Viewer
----------------------

"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re
import sys
import os
import io
import csv
import json
import gzip
import zipfile
import threading
import webbrowser
from datetime import datetime, timezone

try:
    import sqlite3
except Exception:
    # Some Python builds are compiled without SQLite support -- fall back to
    # a JSON file store automatically (see LogDataStore) instead of crashing.
    sqlite3 = None

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_LIB_AVAILABLE = True
except Exception:
    Observer = None
    FileSystemEventHandler = object
    WATCHDOG_LIB_AVAILABLE = False

APP_TITLE = "IRISec Log Analyzer"


def resource_path(relative_path):
    """Resolve a path to a bundled resource (e.g. the app icon) so it works
    both when running this script directly and when running as a PyInstaller
    -onefile standalone executable (which unpacks bundled data files into a
    temporary folder referenced by sys._MEIPASS)."""
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)



CATEGORIES = [
    "System Logs",
    "Application Logs",
    "Security Logs",
    "Access Logs",
    "Audit Logs",
    "Database Logs",
]

# Local persistent storage for all uploaded log data. SQLite is used as the
# backend when available (DB_PATH); if the Python install lacks SQLite
# support, LogDataStore transparently falls back to a JSON file (JSON_DB_PATH)
# instead -- either way, every upload APPENDS to it (rows are written to disk,
# not accumulated in a big Python list), "Clear All Data" wipes it, and it's
# what the app restores from automatically on the next launch.
APP_DATA_DIR = os.path.join(os.path.expanduser("~"), ".log_analyzer")
DB_PATH = os.path.join(APP_DATA_DIR, "log_analyzer.db")
JSON_DB_PATH = os.path.join(APP_DATA_DIR, "log_analyzer_store.json")

# All uploaded log lines, merged from every file and sorted chronologically by
# their parsed timestamp, are continuously written out to this single local
# file -- a de-duplicated, time-ordered "master log". Deleted on Clear All.
MERGED_LOG_PATH = os.path.join(APP_DATA_DIR, "merged_sorted.log")

# --------------------------------------------------------------------- #
#              Shared color palette / fonts (professional theme)        #
# --------------------------------------------------------------------- #
PALETTE = {
    "bg": "#eef1f6",          # window background
    "surface": "#ffffff",     # cards / panels
    "primary": "#1f3a5f",     # dark navy - headers, primary buttons
    "primary_dark": "#152944",
    "accent": "#09255e",      # accent blue - links, highlights
    "text": "#1f2937",        # main text
    "muted": "#5b6675",       # secondary / help text
    "border": "#d7dce3",
    "row_odd": "#f6f8fb",
    "row_even": "#ffffff",
    "row_hover": "#eaf1ff",
    "col_selected": "#dbe9ff",
    "success": "#16742c",
    "danger": "#791508",
}
MUTED_TEXT = PALETTE["muted"]
FONT_BASE = ("Segoe UI", 9)
FONT_HEADING = ("Segoe UI", 9, "bold")
FONT_MONO = ("Consolas", 9)
FONT_TITLE = ("Segoe UI", 16, "bold")
FONT_SUBTITLE = ("Segoe UI", 9)

COLUMNS = ["category", "source", "ip", "method", "path", "status", "time", "description"]
COLUMN_LABELS = {
    "category": "Category",
    "source": "Source File",
    "ip": "IP Address",
    "method": "Method",
    "path": "Path",
    "status": "Status",
    "time": "Time",
    "description": "Description",
}
COLUMN_WIDTHS = {
    "category": 120,
    "source": 150,
    "ip": 110,
    "method": 70,
    "path": 260,
    "status": 60,
    "time": 260,
    "description": 680,
}

# --------------------------------------------------------------------- #
#                       Log line parsing helpers                        #
# --------------------------------------------------------------------- #
IP_RE = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')
METHOD_RE = re.compile(r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\b')
COMBINED_RE = re.compile(r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"')
PATH_RE = re.compile(r'(?<!\S)(/[^\s"\'()<>,;]+)')

# Ordered status extraction strategies (tried in order, first match wins)
STATUS_PATTERNS = [
    re.compile(r'"\s+([1-5]\d{2})\b'),
    re.compile(r'\bstatus(?:[:=]\s*|\s+is\s+)(\d{3})\b', re.IGNORECASE),
    re.compile(r'(?<!\S)([1-5]\d{2})(?!\S)'),
]

# Ordered time extraction strategies (most specific first; bracketed value last
# since brackets are also used for PIDs etc. and should only be a fallback)
TIME_PATTERNS = [
    re.compile(r'\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b'),
    re.compile(r'\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\s+\d{4})?)\b'),
    re.compile(r'\b(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})\b'),
    re.compile(r'\[([^\]]+)\]'),
]

# Candidate strptime formats tried (in order) to turn an extracted time string
# into a real datetime for chronological sorting in the merged log file.
_TIME_SORT_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S",
    "%b %d %H:%M:%S %Y", "%b %d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
]


def parse_time_for_sort(time_str, fallback_year=None):
    """Best-effort parse of a log entry's extracted time string into a real
    datetime, for chronological sorting. Returns None if no format matches --
    callers should treat that as 'unknown time' rather than crashing."""
    if not time_str:
        return None
    candidate = time_str.strip()
    candidate = re.sub(r'^\[|\]$', '', candidate)  # strip stray brackets
    candidate = re.sub(r':(\d{2})$', r'\1', candidate) if re.search(r'[+-]\d{2}:\d{2}$', candidate) else candidate

    for fmt in _TIME_SORT_FORMATS:
        try:
            dt = datetime.strptime(candidate, fmt)
            if dt.year == 1900 and fallback_year:  # syslog-style formats have no year
                dt = dt.replace(year=fallback_year)
            return dt
        except ValueError:
            continue
    return None


# --------------------------------------------------------------------- #
#            Field-aware search query parsing ("Field: value")          #
# --------------------------------------------------------------------- #
# Maps everything a user might type before the colon to the actual column key.
FIELD_ALIASES = {
    "category": "category", "cat": "category",
    "source": "source", "source file": "source", "sourcefile": "source",
    "file": "source", "filename": "source", "file name": "source",
    "ip": "ip", "ip address": "ip", "ipaddress": "ip",
    "method": "method",
    "path": "path", "url": "path",
    "status": "status", "status code": "status", "statuscode": "status", "code": "status",
    "time": "time", "timestamp": "time", "date": "time",
    "description": "description", "desc": "description", "message": "description", "msg": "description",
}

# Matches "<field name>:<value-with-no-spaces>" tokens, e.g. "IP: 192.168.1.10".
# Built from the known alias keywords (longest first) so it only ever grabs a
# recognised field name as the label -- it won't swallow preceding free words.
_ALIAS_KEYS_BY_LENGTH = sorted(FIELD_ALIASES.keys(), key=len, reverse=True)
_ALIAS_PATTERN = "|".join(re.escape(k) for k in _ALIAS_KEYS_BY_LENGTH)
FIELD_TOKEN_RE = re.compile(rf'\b({_ALIAS_PATTERN})\s*:\s*(\S+)', re.IGNORECASE)


def parse_search_query(text):
    """Split a search string into explicit field filters and free-text keywords.

    Supports syntax like:
        Source: access.log
        IP: 192.168.1.10
        IP address: 192.168.34.1
        Source: access.log, Status: 404          (commas/semicolons optional)
        failed login IP: 10.0.0.5                (mixes free words + a field filter)
        IP: 192.168.34.5,10.5.36.4               (multi-value: matches EITHER IP --
                                                    any value with no matches is simply
                                                    skipped, not treated as an error)

    Returns (field_filters, keywords) where field_filters is a list of
    (column_key, [value1, value2, ...]) tuples -- a row matches a field
    filter if its value contains ANY one of the listed values -- and
    keywords is a list of lowercase free-text words to search across
    (selected) columns.
    """
    field_filters = []
    remaining = text

    for match in FIELD_TOKEN_RE.finditer(text):
        label = match.group(1).strip().lower()
        raw_value = match.group(2).strip().strip(",;")
        column = FIELD_ALIASES.get(label)
        if not column or not raw_value:
            continue
        # split on commas for multi-value search within the same field, e.g.
        # "ip:192.168.34.5,10.5.36.4" -- blank pieces (from a trailing comma
        # before the next "Field: value" pair) are dropped automatically
        values = [v.strip().lower() for v in raw_value.split(",") if v.strip()]
        if values:
            field_filters.append((column, values))
            remaining = remaining.replace(match.group(0), " ", 1)

    # whatever wasn't consumed as a field:value pair becomes free-text keywords
    leftover = remaining.replace(",", " ").replace(";", " ")
    keywords = [w.lower() for w in leftover.split() if w.strip()]
    return field_filters, keywords


def parse_log_line(line, category, source):
    """Extract structured fields (ip, method, path, status, time, description)
    from a single raw log line using a set of tolerant regular expressions.
    Works reasonably well for Apache/Nginx combined logs, syslog style
    system/application logs, and generic key=value security/audit logs.
    """
    line = line.rstrip("\n")
    if not line.strip():
        return None

    ip_match = IP_RE.search(line)
    ip = ip_match.group(0) if ip_match else ""

    combined_match = COMBINED_RE.search(line)
    if combined_match:
        method = combined_match.group("method")
        path = combined_match.group("path")
    else:
        method_match = METHOD_RE.search(line)
        method = method_match.group(1) if method_match else ""
        path_match = PATH_RE.search(line)
        path = path_match.group(1) if path_match else ""

    status = ""
    for pattern in STATUS_PATTERNS:
        m = pattern.search(line)
        if m:
            status = m.group(1)
            break

    time_val = ""
    for pattern in TIME_PATTERNS:
        m = pattern.search(line)
        if m:
            time_val = m.group(1).strip()
            break

    return {
        "category": category,
        "source": source,
        "ip": ip,
        "method": method,
        "path": path,
        "status": status,
        "time": time_val,
        "description": line.strip(),
    }


# --------------------------------------------------------------------- #
#     Reading & parsing ANY uploaded file format (not just .log/.txt)   #
# --------------------------------------------------------------------- #
def read_file_as_text(path):
    """Read an uploaded file's content as text, regardless of its extension.
    Handles gzip (.gz) and zip (.zip) archives transparently by decompressing
    them first; everything else (including files with no/unknown extension,
    or genuinely binary files) is read as text with undecodable bytes replaced
    so the upload never crashes -- it just degrades gracefully."""
    ext = os.path.splitext(path)[1].lower()
    try:
        if ext == ".gz":
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
                return f.read()
        if ext == ".zip":
            parts = []
            with zipfile.ZipFile(path) as zf:
                for name in zf.namelist():
                    if name.endswith("/"):
                        continue
                    with zf.open(name) as zfile:
                        content = zfile.read().decode("utf-8", errors="replace")
                    parts.append(f"===== {name} (inside {os.path.basename(path)}) =====\n{content}")
            return "\n".join(parts)
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        # last-resort fallback for anything the above couldn't handle
        with open(path, "rb") as f:
            return f.read().decode("utf-8", errors="replace")


def parse_csv_content(text, category, source):
    """Parse .csv content. If the header row contains recognisable field
    names (ip, status, time, method, path, description, ...) map columns
    directly; otherwise fall back to treating each row as a generic log line."""
    rows = []
    try:
        raw_rows = list(csv.reader(io.StringIO(text)))
    except Exception:
        raw_rows = []
    if not raw_rows:
        return rows

    header = [h.strip().lower() for h in raw_rows[0]]
    header_columns = [FIELD_ALIASES.get(h) for h in header]
    has_recognized_header = any(header_columns)

    if has_recognized_header:
        for values in raw_rows[1:]:
            if not any(v.strip() for v in values):
                continue
            row = {c: "" for c in COLUMNS}
            row["category"] = category
            row["source"] = source
            for col_key, val in zip(header_columns, values):
                if col_key:
                    row[col_key] = val.strip()
            if not row["description"]:
                row["description"] = ", ".join(v.strip() for v in values)
            rows.append(row)
    else:
        for values in raw_rows:
            line = ", ".join(values)
            parsed = parse_log_line(line, category, source)
            if parsed:
                rows.append(parsed)
    return rows


def parse_json_content(text, category, source):
    """Parse .json (or NDJSON) content. Handles a JSON array of log objects,
    a wrapper object with a 'logs'/'entries'/'records'/'data'/'items' array,
    a single JSON object, or newline-delimited JSON. Falls back to generic
    line parsing if the content isn't valid JSON at all."""
    rows = []
    try:
        data = json.loads(text)
    except Exception:
        data = None

    items = None
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for key in ("logs", "entries", "records", "data", "items"):
            if isinstance(data.get(key), list):
                items = data[key]
                break
        if items is None:
            items = [data]

    if items is not None:
        for item in items:
            if isinstance(item, dict):
                row = {c: "" for c in COLUMNS}
                row["category"] = category
                row["source"] = source
                for k, v in item.items():
                    col = FIELD_ALIASES.get(str(k).strip().lower())
                    if col:
                        row[col] = str(v)
                if not row["description"]:
                    row["description"] = json.dumps(item, ensure_ascii=False)
                rows.append(row)
            else:
                parsed = parse_log_line(str(item), category, source)
                if parsed:
                    rows.append(parsed)
        return rows

    # not a JSON array/object -> try newline-delimited JSON, then plain lines
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except Exception:
            obj = None
        if isinstance(obj, dict):
            row = {c: "" for c in COLUMNS}
            row["category"] = category
            row["source"] = source
            for k, v in obj.items():
                col = FIELD_ALIASES.get(str(k).strip().lower())
                if col:
                    row[col] = str(v)
            if not row["description"]:
                row["description"] = json.dumps(obj, ensure_ascii=False)
            rows.append(row)
        else:
            parsed = parse_log_line(line, category, source)
            if parsed:
                rows.append(parsed)
    return rows


def parse_file_content(text, ext, category, source):
    """Route an uploaded file's text content to the right parser based on its
    extension. Anything not specifically handled (.log, .txt, .sql, .dblog,
    .out, content extracted from .gz/.zip, or literally any other/unknown
    extension) uses the generic line-by-line regex parser, so every file
    format is supported -- the more specific parsers just do a better job on
    .csv and .json."""
    ext = (ext or "").lower()
    if ext == ".csv":
        return parse_csv_content(text, category, source)
    if ext == ".json":
        return parse_json_content(text, category, source)

    rows = []
    for line in text.splitlines():
        if line.startswith("===== ") and line.rstrip().endswith(" ====="):
            continue  # internal marker line inserted for extracted zip members
        parsed = parse_log_line(line, category, source)
        if parsed:
            rows.append(parsed)
    return rows


# --------------------------------------------------------------------- #
#        Automatic log category detection ("what kind of log is it")   #
# --------------------------------------------------------------------- #
# Filename hints are a strong, cheap signal (checked first / weighted heavily).
CATEGORY_FILENAME_HINTS = {
    "Access Logs": ["access", "http", "nginx", "apache"],
    "Security Logs": ["security", "secure", "auth", "firewall", "ids", "ips"],
    "Audit Logs": ["audit"],
    "Database Logs": ["db", "database", "sql", "mysql", "postgres", "postgresql", "mongo", "oracle"],
    "System Logs": ["system", "syslog", "sys", "kern", "boot"],
    "Application Logs": ["app", "application", "service"],
}

# Content keyword signals (lower-cased substring counts).
CATEGORY_CONTENT_KEYWORDS = {
    "Access Logs": [' http/1.', ' http/2', '" get ', '" post ', '" put ', '" delete ', ' 200 ', ' 404 ', ' 304 '],
    "Security Logs": ['failed password', 'authentication fail', 'unauthoriz', 'blocked',
                       'firewall', 'intrusion', 'attack', 'denied', 'sshd', 'brute force',
                       'malicious', 'permission denied'],
    "Audit Logs": ['audit', 'action=', 'user=', 'modified by', 'changed by', 'created by',
                   'deleted by', 'approved by', 'compliance'],
    "Database Logs": ['select ', 'insert into', 'update ', 'delete from', 'mysqld', 'postgres',
                       'statement:', 'duration:', 'db=', 'query', 'transaction', 'rollback', 'commit'],
    "System Logs": ['kernel:', 'cron[', 'systemd', 'syslog', 'reboot', 'shutdown', 'sshd[',
                     'disk usage', 'memory usage', 'cpu usage'],
    "Application Logs": [' info ', ' error ', ' warn ', ' debug ', 'exception', 'traceback',
                          'service]', 'started', 'stopped'],
}


def detect_log_category(text, filename):
    """Guess which of the CATEGORIES a file belongs to, using filename hints
    (weighted heavily) plus a keyword-frequency scan of its content. Falls
    back to 'Application Logs' as a sensible generic default when nothing
    scores above zero."""
    lowered = " " + text.lower() + " "
    fname = filename.lower()

    scores = {cat: 0 for cat in CATEGORIES}

    for cat, hints in CATEGORY_FILENAME_HINTS.items():
        for hint in hints:
            if hint in fname:
                scores[cat] += 8  # filename is a strong, cheap signal

    sample = lowered[:20000]  # cap scan size for very large files
    for cat, keywords in CATEGORY_CONTENT_KEYWORDS.items():
        for kw in keywords:
            count = sample.count(kw)
            if count:
                scores[cat] += min(count, 20)  # diminishing returns per keyword

    best_cat = max(scores, key=scores.get)
    if scores[best_cat] == 0:
        return "Application Logs"
    return best_cat


# --------------------------------------------------------------------- #
#   Persistent storage: SQLite backend, JSON file fallback if SQLite    #
#   isn't available on this Python install. The rest of the app only   #
#   ever talks to this class, never to sqlite3/json directly.          #
# --------------------------------------------------------------------- #
class LogDataStore:
    """Uploaded log data lives here, on disk, from the moment it's inserted --
    never accumulated in a big permanent Python list elsewhere in the app.
    Uses SQLite (DB_PATH) when available; if the Python install lacks SQLite
    support, or the database file can't be opened for any reason, falls back
    automatically to a plain JSON file (JSON_DB_PATH) -- either way, the app
    behaves identically: append on upload, wipe on Clear All, restore on the
    next launch."""

    def __init__(self):
        self.backend = None
        self.conn = None
        self.json_path = JSON_DB_PATH
        self.last_error = None
        self._init_backend()

    def _init_backend(self):
        try:
            os.makedirs(APP_DATA_DIR, exist_ok=True)
        except Exception as exc:
            self.last_error = str(exc)

        if sqlite3 is not None:
            try:
                conn = sqlite3.connect(DB_PATH, timeout=5, check_same_thread=False)
                cur = conn.cursor()
                cur.execute("""CREATE TABLE IF NOT EXISTS log_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT, source TEXT, ip TEXT, method TEXT, path TEXT,
                    status TEXT, time TEXT, description TEXT, uploaded_at TEXT
                )""")
                cur.execute("""CREATE TABLE IF NOT EXISTS raw_chunks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT, source TEXT, text TEXT, uploaded_at TEXT
                )""")
                cur.execute("""CREATE TABLE IF NOT EXISTS uploaded_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT, category TEXT, detected_category TEXT,
                    row_count INTEGER, uploaded_at TEXT, upload_mode TEXT
                )""")
                conn.commit()
                self.conn = conn
                self.backend = "sqlite"
                self.write_lock = threading.Lock()  # sqlite3 objects aren't thread-safe by default
                return
            except Exception as exc:
                self.last_error = str(exc)
                print(f"Warning: SQLite unavailable ({exc}); falling back to a JSON file store.")
                self.conn = None

        # ---- JSON fallback ---- #
        self.backend = "json"
        self.write_lock = threading.Lock()
        if not os.path.exists(self.json_path):
            self._json_write({"log_entries": [], "raw_chunks": [], "uploaded_files": []})

    # ------------------------------------------------------------- #
    #  JSON backend helpers
    # ------------------------------------------------------------- #
    def _json_read(self):
        try:
            with open(self.json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            data.setdefault("log_entries", [])
            data.setdefault("raw_chunks", [])
            data.setdefault("uploaded_files", [])
            return data
        except Exception:
            return {"log_entries": [], "raw_chunks": [], "uploaded_files": []}

    def _json_write(self, data):
        try:
            with open(self.json_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
        except Exception as exc:
            self.last_error = str(exc)
            print(f"Warning: could not write to {self.json_path}: {exc}")

    # ------------------------------------------------------------- #
    #  Public API used by the app (identical on either backend).
    #  All writes are guarded by a lock since the watchdog file
    #  monitor can call these from a background thread concurrently
    #  with the main GUI thread.
    # ------------------------------------------------------------- #
    def insert_entries(self, rows):
        if not rows:
            return
        ts = datetime.now().isoformat(timespec="seconds")
        with self.write_lock:
            if self.backend == "sqlite":
                try:
                    cur = self.conn.cursor()
                    cur.executemany(
                        "INSERT INTO log_entries (category, source, ip, method, path, status, time, description, uploaded_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?)",
                        [(r.get("category", ""), r.get("source", ""), r.get("ip", ""), r.get("method", ""),
                          r.get("path", ""), r.get("status", ""), r.get("time", ""), r.get("description", ""), ts)
                         for r in rows],
                    )
                    self.conn.commit()
                except Exception as exc:
                    print(f"Warning: could not write log entries to database: {exc}")
            else:
                data = self._json_read()
                for r in rows:
                    data["log_entries"].append({
                        "category": r.get("category", ""), "source": r.get("source", ""),
                        "ip": r.get("ip", ""), "method": r.get("method", ""), "path": r.get("path", ""),
                        "status": r.get("status", ""), "time": r.get("time", ""),
                        "description": r.get("description", ""), "uploaded_at": ts,
                    })
                self._json_write(data)

    def insert_raw_chunk(self, category, source, text):
        ts = datetime.now().isoformat(timespec="seconds")
        with self.write_lock:
            if self.backend == "sqlite":
                try:
                    cur = self.conn.cursor()
                    cur.execute(
                        "INSERT INTO raw_chunks (category, source, text, uploaded_at) VALUES (?,?,?,?)",
                        (category, source, text, ts))
                    self.conn.commit()
                except Exception as exc:
                    print(f"Warning: could not write raw chunk to database: {exc}")
            else:
                data = self._json_read()
                data["raw_chunks"].append({"category": category, "source": source, "text": text, "uploaded_at": ts})
                self._json_write(data)

    def insert_file_record(self, filename, category, detected_category, row_count, upload_mode):
        ts = datetime.now().isoformat(timespec="seconds")
        record = {
            "filename": filename, "category": category,
            "detected_category": detected_category or "", "row_count": row_count,
            "uploaded_at": ts, "upload_mode": upload_mode,
        }
        with self.write_lock:
            if self.backend == "sqlite":
                try:
                    cur = self.conn.cursor()
                    cur.execute(
                        "INSERT INTO uploaded_files (filename, category, detected_category, row_count, uploaded_at, upload_mode) "
                        "VALUES (?,?,?,?,?,?)",
                        (filename, category, detected_category or "", row_count, ts, upload_mode))
                    self.conn.commit()
                except Exception as exc:
                    print(f"Warning: could not write file record to database: {exc}")
            else:
                data = self._json_read()
                data["uploaded_files"].append(record)
                self._json_write(data)
        return record

    def bump_file_row_count(self, filename, additional_rows):
        """Used by the watchdog live-tail feature: add to an existing file
        record's row_count instead of inserting a brand new record every
        time a watched file grows."""
        if additional_rows <= 0:
            return
        with self.write_lock:
            if self.backend == "sqlite":
                try:
                    cur = self.conn.cursor()
                    cur.execute(
                        "UPDATE uploaded_files SET row_count = row_count + ? "
                        "WHERE id = (SELECT id FROM uploaded_files WHERE filename = ? ORDER BY id DESC LIMIT 1)",
                        (additional_rows, filename))
                    self.conn.commit()
                except Exception as exc:
                    print(f"Warning: could not update file record row count: {exc}")
            else:
                data = self._json_read()
                for rec in reversed(data["uploaded_files"]):
                    if rec.get("filename") == filename:
                        rec["row_count"] = rec.get("row_count", 0) + additional_rows
                        break
                self._json_write(data)

    def fetch_rows(self, cat_f="All", methods=None, statuses=None):
        """methods/statuses: None or 'All' means no filter; otherwise a list
        of values to match (OR-ed together) -- this is what lets the Method
        and Status filters select combinations like GET + POST at once."""
        method_list = None if not methods or methods == "All" else list(methods)
        status_list = None if not statuses or statuses == "All" else list(statuses)

        if self.backend == "sqlite":
            query = ("SELECT category, source, ip, method, path, status, time, description "
                      "FROM log_entries WHERE 1=1")
            params = []
            if cat_f != "All":
                query += " AND category = ?"; params.append(cat_f)
            if method_list:
                query += " AND method IN (%s)" % ",".join("?" * len(method_list))
                params.extend(method_list)
            if status_list:
                query += " AND status IN (%s)" % ",".join("?" * len(status_list))
                params.extend(status_list)
            query += " ORDER BY id"
            try:
                cur = self.conn.cursor()
                cur.execute(query, params)
                return [
                    {"category": c, "source": s, "ip": ip, "method": m, "path": p,
                     "status": st, "time": t, "description": d}
                    for (c, s, ip, m, p, st, t, d) in cur.fetchall()
                ]
            except Exception as exc:
                print(f"Warning: could not query database: {exc}")
                return []
        else:
            data = self._json_read()
            rows = data["log_entries"]
            if cat_f != "All":
                rows = [r for r in rows if r.get("category") == cat_f]
            if method_list:
                rows = [r for r in rows if r.get("method") in method_list]
            if status_list:
                rows = [r for r in rows if r.get("status") in status_list]
            return [{k: r.get(k, "") for k in COLUMNS} for r in rows]

    def distinct_methods(self):
        if self.backend == "sqlite":
            try:
                cur = self.conn.cursor()
                cur.execute("SELECT DISTINCT method FROM log_entries WHERE method != '' ORDER BY method")
                return [r[0] for r in cur.fetchall()]
            except Exception:
                return []
        data = self._json_read()
        return sorted({r.get("method", "") for r in data["log_entries"] if r.get("method")})

    def distinct_statuses(self):
        if self.backend == "sqlite":
            try:
                cur = self.conn.cursor()
                cur.execute("SELECT DISTINCT status FROM log_entries WHERE status != '' ORDER BY status")
                return [r[0] for r in cur.fetchall()]
            except Exception:
                return []
        data = self._json_read()
        return sorted({r.get("status", "") for r in data["log_entries"] if r.get("status")})

    def count_entries(self):
        if self.backend == "sqlite":
            try:
                cur = self.conn.cursor()
                cur.execute("SELECT COUNT(*) FROM log_entries")
                return cur.fetchone()[0]
            except Exception:
                return 0
        return len(self._json_read()["log_entries"])

    def fetch_raw_chunks(self):
        if self.backend == "sqlite":
            try:
                cur = self.conn.cursor()
                cur.execute("SELECT category, source, text FROM raw_chunks ORDER BY id")
                return cur.fetchall()
            except Exception as exc:
                print(f"Warning: could not read raw chunks: {exc}")
                return []
        data = self._json_read()
        return [(c.get("category", ""), c.get("source", ""), c.get("text", "")) for c in data["raw_chunks"]]

    def fetch_uploaded_files(self):
        if self.backend == "sqlite":
            try:
                cur = self.conn.cursor()
                cur.execute("SELECT filename, category, detected_category, row_count, uploaded_at, upload_mode "
                            "FROM uploaded_files ORDER BY id")
                return [
                    {"filename": f, "category": c, "detected_category": dc, "row_count": rc,
                     "uploaded_at": ua, "upload_mode": um}
                    for (f, c, dc, rc, ua, um) in cur.fetchall()
                ]
            except Exception as exc:
                print(f"Warning: could not read uploaded file list: {exc}")
                return []
        return list(self._json_read()["uploaded_files"])

    def clear_all(self):
        with self.write_lock:
            if self.backend == "sqlite":
                try:
                    cur = self.conn.cursor()
                    cur.execute("DELETE FROM log_entries")
                    cur.execute("DELETE FROM raw_chunks")
                    cur.execute("DELETE FROM uploaded_files")
                    self.conn.commit()
                    cur.execute("VACUUM")
                except Exception as exc:
                    print(f"Warning: could not clear database: {exc}")
            else:
                self._json_write({"log_entries": [], "raw_chunks": [], "uploaded_files": []})

    def close(self):
        if self.backend == "sqlite" and self.conn:
            try:
                self.conn.close()
            except Exception:
                pass


# --------------------------------------------------------------------- #
#   File modification watcher: uses the `watchdog` package when it's    #
#   installed (real OS-level file system events); otherwise falls back  #
#   to a lightweight polling thread. Either way, uploaded files can be  #
#   "watched" so newly appended log lines are imported automatically.   #
# --------------------------------------------------------------------- #
class LogFileWatcher:
    """Watches uploaded files on disk for modifications and reports them
    (from a background thread) via an on_modified(path) callback. The app
    is responsible for reading only the newly-appended bytes and marshaling
    any UI update back onto the main thread (Tkinter isn't thread-safe).

    Fully LAZY: no background thread or OS-level watchdog Observer is
    created until watch() is actually called for the first time. This
    means simply constructing a LogFileWatcher (as the app does at
    startup) can never itself cause a hang -- nothing runs until the
    'Watch files for changes' feature is actually used."""

    POLL_INTERVAL_SECONDS = 2.0

    def __init__(self, on_modified):
        self.on_modified = on_modified
        self.watched = {}   # abs path -> last known size in bytes
        self.lock = threading.Lock()
        self._stop_event = threading.Event()
        self._poll_thread = None
        self._observer = None
        self._handler = None
        self._scheduled_dirs = set()
        self._backend_started = False

    def _ensure_backend_started(self):
        if self._backend_started:
            return
        self._backend_started = True
        if WATCHDOG_LIB_AVAILABLE:
            self._start_watchdog()
        else:
            self._start_polling()

    # ---- watchdog backend ---- #
    def _start_watchdog(self):
        outer = self

        class _Handler(FileSystemEventHandler):
            def on_modified(self, event):
                if event.is_directory:
                    return
                path = os.path.abspath(event.src_path)
                with outer.lock:
                    is_watched = path in outer.watched
                if is_watched:
                    outer.on_modified(path)

        try:
            self._handler = _Handler()
            self._observer = Observer()
            self._observer.daemon = True   # never blocks process exit
            self._observer.start()
        except Exception as exc:
            print(f"Warning: could not start watchdog observer ({exc}); falling back to polling.")
            self._observer = None
            self._start_polling()

    def _watchdog_schedule_dir(self, directory):
        if not self._observer or directory in self._scheduled_dirs:
            return
        try:
            self._observer.schedule(self._handler, directory, recursive=False)
            self._scheduled_dirs.add(directory)
        except Exception as exc:
            print(f"Warning: could not watch directory {directory}: {exc}")

    # ---- polling fallback backend ---- #
    def _start_polling(self):
        if self._poll_thread:
            return
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

    def _poll_loop(self):
        while not self._stop_event.is_set():
            with self.lock:
                paths = list(self.watched.items())
            for path, last_size in paths:
                try:
                    size = os.path.getsize(path)
                except OSError:
                    continue
                if size != last_size:
                    self.on_modified(path)
            self._stop_event.wait(self.POLL_INTERVAL_SECONDS)

    # ---- public API ---- #
    def watch(self, path):
        self._ensure_backend_started()
        path = os.path.abspath(path)
        with self.lock:
            if path in self.watched:
                return
            try:
                self.watched[path] = os.path.getsize(path)
            except OSError:
                self.watched[path] = 0
        if WATCHDOG_LIB_AVAILABLE and self._observer:
            self._watchdog_schedule_dir(os.path.dirname(path) or ".")

    def update_known_size(self, path, size):
        with self.lock:
            self.watched[os.path.abspath(path)] = size

    def stop(self):
        self._stop_event.set()
        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=2)
            except Exception:
                pass


class LogAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1400x900")
        self.root.minsize(1000, 600)
        self._set_app_icon()

        # NOTE: log data is NOT kept permanently in a big Python list anymore.
        # The local store (SQLite, or JSON fallback) is the single source of
        # truth. self._current_view_rows (set in _refresh_table) holds only
        # whatever is currently shown in the table, fetched from the store
        # fresh on every search/filter -- this is what keeps RAM usage down
        # even with a large number/size of uploaded files.
        self.uploaded_files = []   # small metadata list: filename/category/detected_category/row_count/uploaded_at/upload_mode
        self.selected_columns = set()   # columns toggled via header click
        self.dedupe_var = tk.BooleanVar(value=False)  # remove duplicate entries on copy/export
        self.base_domain_var = tk.StringVar(value="")  # domain used to open a clicked Path in the browser

        # Watchdog: auto-import new lines appended to uploaded files on disk
        self.watch_enabled_var = tk.BooleanVar(value=False)
        self.watched_file_info = {}   # abs path -> {"category", "source", "last_size"}
        self.watcher = LogFileWatcher(on_modified=self._on_file_modified_background)

        self._init_database()
        self._build_style()
        self._build_widgets()
        self._load_from_database()
        self._refresh_table()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _set_app_icon(self):
        """Set the window/taskbar icon. Tries the .ico first (best on
        Windows), then falls back to the .png (works via iconphoto on
        Linux/macOS/Windows alike). Never fatal if icon files are missing --
        the app just runs with the default Tk icon instead."""
        try:
            ico_path = resource_path("icon.ico")
            if os.path.exists(ico_path):
                self.root.iconbitmap(ico_path)
                return
        except Exception:
            pass
        try:
            png_path = resource_path("icon.png")
            if os.path.exists(png_path):
                icon_img = tk.PhotoImage(file=png_path)
                self.root.iconphoto(True, icon_img)
                self._icon_img_ref = icon_img  # keep a reference so it isn't garbage-collected
        except Exception:
            pass

    # ------------------------------------------------------------- #
    #  Styling
    # ------------------------------------------------------------- #
    def _build_style(self):
        self.root.configure(bg=PALETTE["bg"])

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(".", font=FONT_BASE, background=PALETTE["bg"], foreground=PALETTE["text"])

        style.configure("TFrame", background=PALETTE["bg"])
        style.configure("Surface.TFrame", background=PALETTE["surface"])

        style.configure("TLabel", background=PALETTE["bg"], foreground=PALETTE["text"])
        style.configure("Muted.TLabel", background=PALETTE["bg"], foreground=PALETTE["muted"])

        style.configure("TLabelframe", background=PALETTE["bg"], bordercolor=PALETTE["border"])
        style.configure("TLabelframe.Label", background=PALETTE["bg"],
                         foreground=PALETTE["primary"], font=FONT_HEADING)

        style.configure("TButton", font=FONT_BASE, padding=5)
        style.configure("Accent.TButton", font=FONT_HEADING, padding=6,
                         background=PALETTE["accent"], foreground="white")
        style.map("Accent.TButton",
                  background=[("active", PALETTE["primary"]), ("pressed", PALETTE["primary_dark"])],
                  foreground=[("disabled", PALETTE["muted"])])

        style.configure("TEntry", padding=3)
        style.configure("TCombobox", padding=3)
        style.configure("TCheckbutton", background=PALETTE["bg"])
        style.configure("TRadiobutton", background=PALETTE["bg"])

        style.configure("TNotebook", background=PALETTE["bg"], bordercolor=PALETTE["border"])
        style.configure("TNotebook.Tab", font=FONT_HEADING, padding=(14, 7),
                         background=PALETTE["surface"], foreground=PALETTE["muted"])
        style.map("TNotebook.Tab",
                  background=[("selected", PALETTE["primary"])],
                  foreground=[("selected", "white")])

        style.configure("Treeview", rowheight=24, font=FONT_MONO,
                         background=PALETTE["surface"], fieldbackground=PALETTE["surface"],
                         foreground=PALETTE["text"], bordercolor=PALETTE["border"])
        style.configure("Treeview.Heading", font=FONT_HEADING,
                         background=PALETTE["primary"], foreground="white", relief="flat")
        style.map("Treeview.Heading", background=[("active", PALETTE["primary_dark"])])
        style.map("Treeview",
                  background=[("selected", PALETTE["accent"])],
                  foreground=[("selected", "white")])

        style.configure("Status.TLabel", background=PALETTE["primary"], foreground="white",
                         font=FONT_BASE, padding=5)
        
        style.configure("Danger.TLabel", foreground="red")
        style.configure("Success.TLabel", foreground="green")

    # ------------------------------------------------------------- #
    #  Widget construction
    # ------------------------------------------------------------- #
    def _build_widgets(self):
        self._build_loading_bar()
        self._build_header()
        self._build_upload_bar()
        self._build_search_bar()
        self._build_notebook()
        self._build_action_bar()
        self._build_status_bar()

    # ---------- Top loading bar (shown during uploads/search/etc.) ---------- #
    def _build_loading_bar(self):
        self.loading_frame = tk.Frame(self.root, bg=PALETTE["primary_dark"])
        # not packed yet -- only shown while work is in progress (see
        # _show_loading_bar / _hide_loading_bar)

        self.loading_label_var = tk.StringVar(value="")
        tk.Label(self.loading_frame, textvariable=self.loading_label_var,
                 bg=PALETTE["primary_dark"], fg="white", font=FONT_BASE,
                 anchor="w", padx=10, pady=3).pack(fill="x")

        self.loading_bar = ttk.Progressbar(self.loading_frame, mode="indeterminate")
        self.loading_bar.pack(fill="x", padx=0, pady=(0, 2))

    def _show_loading_bar(self, message):
        self.loading_label_var.set(message)
        self.loading_frame.pack(fill="x", side="top", before=self._header_frame)
        self.loading_bar.start(12)
        self.root.update_idletasks()

    def _hide_loading_bar(self):
        self.loading_bar.stop()
        self.loading_frame.pack_forget()
        self.root.update_idletasks()

    # ---------- Header banner ---------- #
    def _build_header(self):
        header = tk.Frame(self.root, bg=PALETTE["primary"])
        header.pack(fill="x", side="top")
        self._header_frame = header

        inner = tk.Frame(header, bg=PALETTE["primary"])
        inner.pack(fill="x", padx=16, pady=10)

        tk.Label(inner, text="IRISec RADAR Log Analyzer & Viewer", bg=PALETTE["primary"], fg="white",
                 font=FONT_TITLE).pack(side="left")
        #tk.Label(inner, text="  System · Application · Security · Access · Audit · Database",
                # bg=PALETTE["primary"], fg="#c9d6ea", font=FONT_SUBTITLE).pack(side="left", padx=(10, 0))

    # ---------- Upload bar ---------- #
    def _build_upload_bar(self):
        frame = ttk.LabelFrame(self.root, text="Upload Log Files")
        frame.pack(fill="x", padx=8, pady=(8, 4))

        row0 = ttk.Frame(frame)
        row0.pack(fill="x")

        ttk.Button(row0, text="+ Add File",
                   style="Accent.TButton", command=self._upload_files_auto_detect).pack(
            side="left", padx=4, pady=6)
        #ttk.Label(row0, text="one button, any number of files -- each file's log type "
               #               "is analyzed and assigned automatically",
                 # foreground=MUTED_TEXT).pack(side="left", padx=8)
        ttk.Separator(row0, orient="vertical").pack(side="left", fill="y", padx=8, pady=4)
        row1 = ttk.Frame(frame)
        row1.pack(fill="x")

        #ttk.Label(row0, text="Or upload to a specific category:", foreground=MUTED_TEXT).pack(
         #   side="left", padx=(4, 8), pady=(4, 6))

        for cat in CATEGORIES:
            btn = ttk.Button(row0, text=f"{cat}",
                              command=lambda c=cat: self._upload_files(c))
            btn.pack(side="left", padx=4, pady=6)

        ttk.Separator(row0, orient="vertical").pack(side="left", fill="y", padx=8, pady=4)

        ttk.Button(row0, text="Clear All Data", command=self._clear_all).pack(
            side="left", padx=4, pady=6)
        
        self.upload_summary_var = tk.StringVar(value="No files uploaded yet.")
        self.upload_summary_label = ttk.Label(
            row0,
            textvariable=self.upload_summary_var,
            style="Danger.TLabel"
        )
        self.upload_summary_label.pack(side="left", padx=12)

        #self.upload_summary_label.configure(foreground="green")

        #self.upload_summary_var = tk.StringVar(value="No files uploaded yet.")
        #ttk.Label(row0, textvariable=self.upload_summary_var, foreground=MUTED_TEXT).pack(
        #    side="left", padx=12)

        #ttk.Label(
        #    frame,
        #    text="Any file format is accepted -- .log, .txt, .csv, .json (incl. NDJSON), "
         #        ".sql, .dblog, .gz, .zip, files with no extension, or anything else. "
         #        ".csv/.json get smart column mapping when their fields are recognisable; "
         #        "everything else is parsed line-by-line.",
         #   foreground=MUTED_TEXT, wraplength=1300, justify="left",
       # ).pack(anchor="w", padx=4, pady=(0, 2))

        backend_name = "SQLite database" if self.store.backend == "sqlite" else "JSON file store (SQLite unavailable on this system)"
        backend_path = DB_PATH if self.store.backend == "sqlite" else JSON_DB_PATH
        #ttk.Label(
         #   frame,
         #   text=f"Local storage (appended on every upload, wiped by Clear All, restored on "
          #       f"next launch) -- {backend_name}: {backend_path}",
         #   foreground=MUTED_TEXT, wraplength=1300, justify="left",
       # ).pack(anchor="w", padx=4, pady=(0, 6))

        row2 = ttk.Frame(frame)
        row2.pack(fill="x")
        ttk.Label(row2, text="Browser domain:").pack(side="left", padx=(4, 4), pady=(0, 8))
        domain_entry = ttk.Entry(row2, textvariable=self.base_domain_var, width=30)
        domain_entry.pack(side="left", padx=(0, 8), pady=(0, 8))
        #ttk.Label(
        #    row2,
         #   text="e.g. example.com -- double-click any Path cell in the table (or use the "
         #        "right-click menu) to open https://<domain>/<path> in your browser.",
         #   foreground=MUTED_TEXT,
        #).pack(side="left", pady=(0, 8))

        row3 = ttk.Frame(frame)
        row3.pack(fill="x")
        watch_backend = "Wtchdog Library" if WATCHDOG_LIB_AVAILABLE else "Polling Fallback (watchdog package not installed)"
        ttk.Checkbutton(
            row2, text="Watch Uploaded Files For Changes",
            variable=self.watch_enabled_var,
        ).pack(side="left", padx=4, pady=(0, 8))
        ttk.Label(
            row2, text=f"Using: {watch_backend}",
            foreground=MUTED_TEXT,
        ).pack(side="left", padx=4, pady=(0, 8))

        #ttk.Label(
        #    frame,
         #   text=f"Merged, time-sorted log of everything uploaded (regenerated on every upload, "
         #        f"deleted by Clear All): {MERGED_LOG_PATH}",
          #  foreground=MUTED_TEXT, wraplength=1300, justify="left",
        #).pack(anchor="w", padx=4, pady=(0, 6))

    # ---------- Search bar ---------- #
    def _build_search_bar(self):
        frame = ttk.LabelFrame(self.root, text="Search / Filter")
        frame.pack(fill="x", padx=8, pady=4)

        ttk.Label(frame, text="Search text:").grid(row=0, column=0, padx=4, pady=(6, 0), sticky="w")
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(frame, textvariable=self.search_var, width=100)
        search_entry.grid(row=0, column=1, padx=4, pady=(6, 0), sticky="w")
        search_entry.bind("<Return>", lambda e: self._on_search_action())

        self.logic_var = tk.StringVar(value="AND")
        ttk.Radiobutton(frame, text="Match ALL words", variable=self.logic_var,
                         value="AND").grid(row=0, column=2, padx=4, pady=(6, 0), sticky="w")
        ttk.Radiobutton(frame, text="Match ANY word", variable=self.logic_var,
                         value="OR").grid(row=0, column=3, padx=4, pady=(6, 0), sticky="w")

        #hint_text = "Field search examples: Source: access.log   IP: 192.168.1.10   Status: 200  (combine with commas). Plain words with no field name search across all columns, or only the columns selected in the table header below."
        #ttk.Label(frame, text=hint_text, foreground=MUTED_TEXT, justify="left", wraplength=1150).grid(
       #     row=1, column=0, columnspan=6, padx=4, pady=(0, 6), sticky="w")

        # Field specific quick filters
        ttk.Label(frame, text="Category:").grid(row=2, column=0, padx=4, pady=6, sticky="w")
        self.filter_category_var = tk.StringVar(value="All")
        self.category_combo = ttk.Combobox(frame, textvariable=self.filter_category_var,
                                            values=["All"] + CATEGORIES, state="readonly", width=18)
        self.category_combo.grid(row=2, column=1, padx=4, sticky="w")

        # Method / Status use multi-select listboxes (not comboboxes) so
        # combinations like GET + POST, or 200 + 404, can be filtered at once.
        # Nothing selected == no filter (show all).
        ttk.Label(frame, text="Method\n(ctrl/shift-click\nfor multiple):", justify="left").grid(
            row=2, column=2, padx=4, sticky="nw", pady=(6, 0))
        method_frame = ttk.Frame(frame)
        method_frame.grid(row=2, column=3, padx=4, sticky="w")
        self.method_listbox = tk.Listbox(
            method_frame, selectmode="extended", exportselection=False,
            height=4, width=12, font=FONT_BASE,
            bg=PALETTE["surface"], fg=PALETTE["text"],
            selectbackground=PALETTE["accent"], selectforeground="white",
            relief="flat", highlightthickness=1, highlightbackground=PALETTE["border"])
        method_scroll = ttk.Scrollbar(method_frame, orient="vertical", command=self.method_listbox.yview)
        self.method_listbox.configure(yscrollcommand=method_scroll.set)
        self.method_listbox.pack(side="left")
        method_scroll.pack(side="left", fill="y")

        ttk.Label(frame, text="Status\n(ctrl/shift-click\nfor multiple):", justify="left").grid(
            row=2, column=4, padx=4, sticky="nw", pady=(6, 0))
        status_frame = ttk.Frame(frame)
        status_frame.grid(row=2, column=5, padx=4, sticky="w")
        self.status_listbox = tk.Listbox(
            status_frame, selectmode="extended", exportselection=False,
            height=4, width=12, font=FONT_BASE,
            bg=PALETTE["surface"], fg=PALETTE["text"],
            selectbackground=PALETTE["accent"], selectforeground="white",
            relief="flat", highlightthickness=1, highlightbackground=PALETTE["border"])
        status_scroll = ttk.Scrollbar(status_frame, orient="vertical", command=self.status_listbox.yview)
        self.status_listbox.configure(yscrollcommand=status_scroll.set)
        self.status_listbox.pack(side="left")
        status_scroll.pack(side="left", fill="y")

        ttk.Button(frame, text="Search", command=self._on_search_action).grid(
            row=2, column=6, padx=8, sticky="n")
        ttk.Button(frame, text="Clear Filters", command=self._clear_filters).grid(
            row=2, column=7, padx=4, sticky="n")

    # ---------- Notebook (Table + Raw) ---------- #
    def _build_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=4)

        # ---- Structured table tab ---- #
        table_tab = ttk.Frame(self.notebook)
        self.notebook.add(table_tab, text="Structured Log Table")
        self._build_table(table_tab)

        # ---- Raw combined log tab ---- #
        raw_tab = ttk.Frame(self.notebook)
        self.notebook.add(raw_tab, text="Combined Raw Log")
        self._build_raw_view(raw_tab)
        self.raw_tab_index = self.notebook.index("end") - 1

        # ---- Uploaded files tab ---- #
        files_tab = ttk.Frame(self.notebook)
        self.notebook.add(files_tab, text="Uploaded Files")
        self._build_uploaded_files_tab(files_tab)

    def _build_uploaded_files_tab(self, parent):
        #ttk.Label(
         #   parent,
         #   text="Every file added (via either upload method) is listed here, along with the "
         #        "category it was assigned, the category auto-detection guessed, how many rows "
         #        "were parsed from it, and when it was appended to the local database.",
          #  foreground=MUTED_TEXT, wraplength=1300, justify="left",
        #).pack(anchor="w", padx=6, pady=(6, 4))

        container = ttk.Frame(parent)
        container.pack(fill="both", expand=True, padx=4, pady=(0, 4))

        vscroll = ttk.Scrollbar(container, orient="vertical")
        hscroll = ttk.Scrollbar(container, orient="horizontal")

        file_columns = ("filename", "category", "detected_category", "row_count", "uploaded_at", "upload_mode")
        file_labels = {
            "filename": "File Name",
            "category": "Assigned Category",
            "detected_category": "Auto-Detected As",
            "row_count": "Rows Parsed",
            "uploaded_at": "Uploaded At",
            "upload_mode": "Upload Method",
        }
        file_widths = {
            "filename": 220, "category": 160, "detected_category": 160,
            "row_count": 100, "uploaded_at": 170, "upload_mode": 120,
        }

        self.files_tree = ttk.Treeview(
            container, columns=file_columns, show="headings",
            yscrollcommand=vscroll.set, xscrollcommand=hscroll.set,
        )
        vscroll.config(command=self.files_tree.yview)
        hscroll.config(command=self.files_tree.xview)

        for col in file_columns:
            self.files_tree.heading(col, text=file_labels[col])
            self.files_tree.column(col, width=file_widths[col], anchor="w", stretch=False)

        self.files_tree.tag_configure("oddrow", background=PALETTE["row_odd"])
        self.files_tree.tag_configure("evenrow", background=PALETTE["row_even"])

        self.files_tree.grid(row=0, column=0, sticky="nsew")
        vscroll.grid(row=0, column=1, sticky="ns")
        hscroll.grid(row=1, column=0, sticky="ew")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

    def _refresh_uploaded_files_list(self):
        if not hasattr(self, "files_tree"):
            return
        self.files_tree.delete(*self.files_tree.get_children())
        for i, rec in enumerate(self.uploaded_files):
            tag = "evenrow" if i % 2 == 0 else "oddrow"
            values = (
                rec.get("filename", ""), rec.get("category", ""),
                rec.get("detected_category", ""), rec.get("row_count", ""),
                rec.get("uploaded_at", ""), rec.get("upload_mode", ""),
            )
            self.files_tree.insert("", "end", iid=str(i), values=values, tags=(tag,))

    def _build_table(self, parent):
        container = ttk.Frame(parent)
        container.pack(fill="both", expand=True)

        vscroll = ttk.Scrollbar(container, orient="vertical")
        hscroll = ttk.Scrollbar(container, orient="horizontal")

        self.tree = ttk.Treeview(
            container, columns=COLUMNS, show="headings",
            selectmode="extended",
            yscrollcommand=vscroll.set, xscrollcommand=hscroll.set,
        )
        vscroll.config(command=self.tree.yview)
        hscroll.config(command=self.tree.xview)

        for col in COLUMNS:
            self.tree.heading(col, text=COLUMN_LABELS[col],
                               command=lambda c=col: self._toggle_column_selection(c))
            self.tree.column(col, width=COLUMN_WIDTHS[col], anchor="w", stretch=False)

        self.tree.tag_configure("oddrow", background=PALETTE["row_odd"])
        self.tree.tag_configure("evenrow", background=PALETTE["row_even"])
        self.tree.tag_configure("col_selected_marker", background=PALETTE["col_selected"])

        self.tree.grid(row=0, column=0, sticky="nsew")
        vscroll.grid(row=0, column=1, sticky="ns")
        hscroll.grid(row=1, column=0, sticky="ew")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

        # right click context menu
        self.context_menu = tk.Menu(self.tree, tearoff=0)
        self.context_menu.add_command(label="Copy Cell", command=self._copy_cell_popup)
        self.context_menu.add_command(label="Open Path in Browser", command=self._open_last_clicked_path_in_browser)
        self.context_menu.add_command(label="Move to Raw Log", command=self._jump_to_raw_log_from_context)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Selected Rows", command=self._copy_selected_rows)
        self.context_menu.add_command(label="Copy ALL Rows", command=self._copy_all_rows)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Selected Rows as JSON", command=lambda: self._copy_as_json(all_rows=False))
        self.context_menu.add_command(label="Copy ALL Rows as JSON", command=lambda: self._copy_as_json(all_rows=True))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Export Selected Rows to JSON file", command=lambda: self._export_json(all_rows=False))
        self.context_menu.add_command(label="Export ALL Rows to JSON file", command=lambda: self._export_json(all_rows=True))
        self.context_menu.add_separator()
        self.context_menu.add_checkbutton(
            label="Remove Duplicate", variable=self.dedupe_var)
        self.context_menu.add_command(label="Select All Rows (Ctrl+A)", command=self._select_all_rows)
        self.context_menu.add_command(label="Clear Column Selection", command=self._clear_column_selection)

        # -- mouse / keyboard interactions --
        self._last_click_row_col = None  # (row_id, col_index) set on click, used by double-click
        self.tree.bind("<Button-1>", self._on_tree_left_click)
        self.tree.bind("<Double-Button-1>", self._on_cell_double_click)   # double-click a row -> open its Path in browser
        self.tree.bind("<Button-3>", self._show_context_menu)   # Windows/Linux right click
        self.tree.bind("<Button-2>", self._show_context_menu)   # macOS right click (varies)
        self.tree.bind("<Control-c>", lambda e: self._copy_selected_rows())   # mouse-select rows, then Ctrl+C
        self.tree.bind("<Control-a>", lambda e: self._select_all_rows())
        # native click-and-drag across rows (extended selectmode) already selects a
        # range as the mouse is dragged; Shift-click / Ctrl-click extend/toggle it.

        # info label about column selection under the table
        #self.column_select_var = tk.StringVar(
        #    value="Tip: click a column header to select/deselect that column for copy/export "
        #          "(plain-word search will also be scoped to the selected column(s)).")
        #ttk.Label(parent, textvariable=self.column_select_var, foreground=MUTED_TEXT).pack(
         #   anchor="w", padx=4, pady=(2, 4))

        #mouse_tip = ("Mouse tips: click a row, or click-and-drag across rows to select a range, "
        #             "Ctrl+click to add/remove a row, Shift+click to select a span. "
         #            "Double-click any cell in a row to open its Path value at "
        #             "https://<domain>/<path> in your browser (set the domain above). "
        #             "Right-click a row for more options, including 'Move to Raw Log' to jump "
         #            "to and highlight that line in the Combined Raw Log tab, and 'Copy Cell' "
         #            "for a selectable copy popup. "
          #           "Ctrl+C copies the current selection, Ctrl+A selects everything.")
        #ttk.Label(parent, text=mouse_tip, foreground=MUTED_TEXT, wraplength=1300, justify="left").pack(
        #    anchor="w", padx=4, pady=(0, 4))

    def _build_raw_view(self, parent):
        container = ttk.Frame(parent)
        container.pack(fill="both", expand=True)

        vscroll = ttk.Scrollbar(container, orient="vertical")
        hscroll = ttk.Scrollbar(container, orient="horizontal")

        self.raw_text = tk.Text(container, wrap="none", font=FONT_MONO,
                                 bg=PALETTE["surface"], fg=PALETTE["text"],
                                 insertbackground=PALETTE["text"],
                                 selectbackground=PALETTE["accent"], selectforeground="white",
                                 relief="flat", borderwidth=1, highlightthickness=1,
                                 highlightbackground=PALETTE["border"],
                                 yscrollcommand=vscroll.set, xscrollcommand=hscroll.set)
        vscroll.config(command=self.raw_text.yview)
        hscroll.config(command=self.raw_text.xview)

        self.raw_text.grid(row=0, column=0, sticky="nsew")
        vscroll.grid(row=0, column=1, sticky="ns")
        hscroll.grid(row=1, column=0, sticky="ew")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

        self.raw_text.configure(state="disabled")

    # ---------- Action bar (below table) ---------- #
    def _build_action_bar(self):
        frame = ttk.LabelFrame(self.root)
        frame.pack(fill="x", padx=8, pady=4)
        
        header = ttk.Frame(frame)
        header.pack(fill="x")

        ttk.Label(
            header,
            text="Copy / Export",
            font=("Segoe UI", 10, "bold")
        ).pack(side="left", padx=(5, 10))
        
        ttk.Checkbutton(header, text="Remove duplicate entries",
            variable=self.dedupe_var,
        ).pack(side="left", padx=4, pady=(0, 6))
                
        row1 = ttk.Frame(frame)
        row1.pack(fill="x")  

        ttk.Button(row1, text="Copy Selected Row(s)", command=self._copy_selected_rows).pack(
            side="left", padx=4, pady=6)
        ttk.Button(row1, text="Copy ALL Rows", command=self._copy_all_rows).pack(
            side="left", padx=4, pady=6)
        ttk.Separator(row1, orient="vertical").pack(side="left", fill="y", padx=8, pady=4)
        ttk.Button(row1, text="Copy Selected as JSON", command=lambda: self._copy_as_json(all_rows=False)).pack(
            side="left", padx=4, pady=6)
        ttk.Button(row1, text="Copy ALL as JSON", command=lambda: self._copy_as_json(all_rows=True)).pack(
            side="left", padx=4, pady=6)
        ttk.Separator(row1, orient="vertical").pack(side="left", fill="y", padx=8, pady=4)
        ttk.Button(row1, text="Export Selected -> JSON file", command=lambda: self._export_json(all_rows=False),
                   style="Accent.TButton").pack(side="left", padx=4, pady=6)
        ttk.Button(row1, text="Export ALL -> JSON file", command=lambda: self._export_json(all_rows=True),
                   style="Accent.TButton").pack(side="left", padx=4, pady=6)
        ttk.Separator(row1, orient="vertical").pack(side="left", fill="y", padx=8, pady=4)
        ttk.Button(row1, text="Export Split by Search Value(s)...",
                   command=self._export_split_by_value).pack(side="left", padx=4, pady=(0, 6))
        
        #row2 = ttk.Frame(frame)
        #row2.pack(fill="x")

        

       # ttk.Label(
        #    row2,
        #    text="Duplicates are judged by the currently selected column(s) in the table "
          #       "header (e.g. select IP Address + Path only, then copy, to get a unique "
         #        "IP/Path list). If no column is selected, whole rows are compared.",
         #   foreground=MUTED_TEXT,
        #).pack(side="left", padx=4, pady=(0, 6))

        #row3 = ttk.Frame(frame)
        #row3.pack(fill="x")

        
        #ttk.Label(
        #    row3,
        #    text="Use a multi-value field search first, e.g. 'ip:192.168.34.5,10.5.36.4' -- "
        #         "writes one JSON file PER VALUE (containing only that value's matching rows) "
         #        "into a folder you choose. A value with no matches is simply skipped.",
         #   foreground=MUTED_TEXT,
       # ).pack(side="left", padx=4, pady=(0, 6))

    # ---------- Status bar ---------- #
    def _build_status_bar(self):
        self.status_var = tk.StringVar(value="Ready.")
        bar = ttk.Label(self.root, textvariable=self.status_var, anchor="w", style="Status.TLabel")
        bar.pack(fill="x", side="bottom")

    # ------------------------------------------------------------- #
    #  Upload handling
    # ------------------------------------------------------------- #
    # ------------------------------------------------------------- #
    #  Shared upload pipeline: read -> (auto-detect category) -> parse
    #  -> append in-memory -> append to local database -> record file
    # ------------------------------------------------------------- #
    def _process_uploaded_paths(self, filepaths, forced_category, upload_mode):
        added_total = 0
        failed = []

        plural = f"{len(filepaths)} file(s)" if len(filepaths) != 1 else f"'{os.path.basename(filepaths[0])}'"
        self._show_loading_bar(f"Loading and analyzing {plural}...")
        try:
            for path in filepaths:
                source = os.path.basename(path)
                ext = os.path.splitext(path)[1].lower()
                try:
                    raw_text = read_file_as_text(path)
                except Exception as exc:
                    failed.append(f"{source}: {exc}")
                    continue

                detected_category = detect_log_category(raw_text, source)
                category = forced_category if forced_category else detected_category
                rows = parse_file_content(raw_text, ext, category, source)

                # write straight to the database -- rows/raw_text are not kept
                # around in a growing Python list, so RAM use stays proportional
                # to "one file at a time" rather than "everything ever uploaded"
                file_record = self._db_insert_file_record(
                    source, category, detected_category, len(rows), upload_mode)
                self.uploaded_files.append(file_record)   # small metadata only
                self._db_insert_entries(rows)
                self._db_insert_raw_chunk(category, source, raw_text)

                if self.watch_enabled_var.get() and ext not in (".gz", ".zip"):
                    self._register_watch(path, category, source)

                del rows, raw_text   # let this file's data be freed before the next one

                added_total += file_record["row_count"]
                self.root.update_idletasks()   # keep the loading bar animating between files
        finally:
            self._hide_loading_bar()

        self._refresh_upload_summary()
        self._refresh_raw_view()
        self._refresh_filter_choices()
        self._refresh_uploaded_files_list()
        self._apply_filters()
        self._write_merged_log_file()

        if failed:
            messagebox.showwarning(
                "Some Files Could Not Be Read",
                "The following file(s) could not be read and were skipped:\n\n" + "\n".join(failed))

        ok_count = len(filepaths) - len(failed)
        return added_total, ok_count, len(failed)

    # ------------------------------------------------------------- #
    #  Watchdog: auto-import lines appended to watched files
    # ------------------------------------------------------------- #
    def _register_watch(self, path, category, source):
        abs_path = os.path.abspath(path)
        try:
            size = os.path.getsize(abs_path)
        except OSError:
            size = 0
        self.watched_file_info[abs_path] = {"category": category, "source": source, "last_size": size}
        self.watcher.watch(abs_path)

    def _on_file_modified_background(self, path):
        """Called from the watchdog/polling background thread -- must not
        touch Tkinter widgets directly, so hand off to the main thread."""
        self.root.after(0, lambda: self._handle_watched_file_delta(path))

    def _handle_watched_file_delta(self, path):
        if not self.watch_enabled_var.get():
            return
        info = self.watched_file_info.get(path)
        if not info:
            return

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(info["last_size"])
                new_text = f.read()
                new_size = f.tell()
        except Exception as exc:
            print(f"Watchdog: could not read changes from {path}: {exc}")
            return

        info["last_size"] = new_size
        self.watcher.update_known_size(path, new_size)

        if not new_text.strip():
            return

        category, source = info["category"], info["source"]
        ext = os.path.splitext(path)[1].lower()
        new_rows = parse_file_content(new_text, ext, category, source)

        if new_rows:
            self.store.insert_entries(new_rows)
        self.store.insert_raw_chunk(category, source, new_text)
        if new_rows:
            self.store.bump_file_row_count(source, len(new_rows))

        # refresh whatever's on screen -- already on the main thread here
        self._refresh_upload_summary()
        self._refresh_raw_view()
        self._refresh_filter_choices()
        self._refresh_uploaded_files_list()
        self._apply_filters()
        self._write_merged_log_file()
        self.status_var.set(
            f"Watchdog: '{source}' changed on disk -- imported {len(new_rows)} new line(s).")

    def _upload_files(self, category):
        filepaths = filedialog.askopenfilenames(
            title=f"Select one or more {category} files (any file format is supported)",
            filetypes=[
                ("All files (any format)", "*.*"),
                ("Log / Text files", "*.log *.txt *.out *.sql *.dblog"),
                ("Structured logs", "*.csv *.json"),
                ("Compressed logs", "*.gz *.zip"),
            ],
        )
        if not filepaths:
            return

        added, ok_count, fail_count = self._process_uploaded_paths(
            filepaths, forced_category=category, upload_mode="manual")

        backend_path = DB_PATH if self.store.backend == "sqlite" else JSON_DB_PATH
        message = (
            f"Added {added} log entrie(s) from {ok_count} file(s) under '{category}'"
            f"{' (' + str(fail_count) + ' skipped)' if fail_count else ''}. "
            f"Appended to local storage: {backend_path}")
        self.status_var.set(message)
        messagebox.showinfo("Upload Complete", message)

    def _upload_files_auto_detect(self):
        filepaths = filedialog.askopenfilenames(
            title="Add Log File(s) -- category will be auto-detected per file",
            filetypes=[
                ("All files (any format)", "*.*"),
                ("Log / Text files", "*.log *.txt *.out *.sql *.dblog"),
                ("Structured logs", "*.csv *.json"),
                ("Compressed logs", "*.gz *.zip"),
            ],
        )
        if not filepaths:
            return

        added, ok_count, fail_count = self._process_uploaded_paths(
            filepaths, forced_category=None, upload_mode="auto")

        backend_path = DB_PATH if self.store.backend == "sqlite" else JSON_DB_PATH
        message = (
            f"Auto-added {added} log entrie(s) from {ok_count} file(s) (category analyzed & "
            f"assigned per file -- see the 'Uploaded Files' tab)"
            f"{' (' + str(fail_count) + ' skipped)' if fail_count else ''}. "
            f"Appended to local storage: {backend_path}")
        self.status_var.set(message)
        messagebox.showinfo("Upload Complete", message)

    def _clear_all(self):
        if not self.uploaded_files:
            return
        if not messagebox.askyesno(
                "Clear All",
                "Remove all uploaded log data? This will permanently delete everything "
                "from local storage, including the merged sorted log file."):
            return
        self.uploaded_files.clear()
        self.selected_columns.clear()
        self.watched_file_info.clear()
        self._clear_database()
        self._delete_merged_log_file()
        self._refresh_upload_summary()
        self._refresh_raw_view()
        self._refresh_filter_choices()
        self._refresh_uploaded_files_list()
        self._apply_filters()
        backend_path = DB_PATH if self.store.backend == "sqlite" else JSON_DB_PATH
        message = f"Cleared all data from local storage ({backend_path}) and deleted the merged log file."
        self.status_var.set(message)
        messagebox.showinfo("Clear Complete", message)

    # ------------------------------------------------------------- #
    #  Local persistent storage -- see LogDataStore above. Every
    #  upload APPENDS to it; "Clear All Data" wipes it; the app
    #  restores from it automatically on the next launch.
    # ------------------------------------------------------------- #
    def _init_database(self):
        self.store = LogDataStore()

    def _db_insert_entries(self, rows):
        if rows:
            self.store.insert_entries(rows)

    def _db_insert_raw_chunk(self, category, source, text):
        self.store.insert_raw_chunk(category, source, text)

    def _db_insert_file_record(self, filename, category, detected_category, row_count, upload_mode):
        return self.store.insert_file_record(filename, category, detected_category, row_count, upload_mode)

    def _load_from_database(self):
        """Restore the uploaded-files list from local storage (if any exists)
        and refresh the UI, which itself queries storage for whatever it
        needs to display -- no bulk entries/raw_chunks list is pulled into
        RAM here."""
        self.uploaded_files = self.store.fetch_uploaded_files()
        if not self.uploaded_files:
            return

        total_entries = self.store.count_entries()
        self._refresh_upload_summary()
        self._refresh_raw_view()
        self._refresh_filter_choices()
        self._refresh_uploaded_files_list()
        self._apply_filters()
        backend_path = DB_PATH if self.store.backend == "sqlite" else JSON_DB_PATH
        self.status_var.set(
            f"Restored {total_entries} log entrie(s) from {len(self.uploaded_files)} file(s) "
            f"in local storage ({backend_path})")

    def _clear_database(self):
        self.store.clear_all()

    # ------------------------------------------------------------- #
    #  Merged, chronologically-sorted log file -- every log line from
    #  every uploaded file, written out to one local file on disk,
    #  ordered by parsed timestamp. Regenerated after every upload or
    #  watchdog update; deleted along with everything else on Clear All.
    # ------------------------------------------------------------- #
    def _write_merged_log_file(self):
        rows = self.store.fetch_rows()
        if not rows:
            self._delete_merged_log_file()
            return

        fallback_year = datetime.now().year

        def sort_key(row):
            dt = parse_time_for_sort(row.get("time", ""), fallback_year=fallback_year)
            if dt is not None and dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            # rows with an unparseable/missing time sort after everything
            # that does have a real timestamp, but are still included
            return (dt is None, dt or datetime.max, row.get("source", ""))

        try:
            rows_sorted = sorted(rows, key=sort_key)
        except Exception as exc:
            print(f"Warning: could not sort rows for merged log file: {exc}")
            rows_sorted = rows

        try:
            os.makedirs(APP_DATA_DIR, exist_ok=True)
            with open(MERGED_LOG_PATH, "w", encoding="utf-8") as f:
                for row in rows_sorted:
                    f.write(row.get("description", "") + "\n")
        except Exception as exc:
            print(f"Warning: could not write merged log file at {MERGED_LOG_PATH}: {exc}")

    def _delete_merged_log_file(self):
        try:
            if os.path.exists(MERGED_LOG_PATH):
                os.remove(MERGED_LOG_PATH)
        except Exception as exc:
            print(f"Warning: could not delete merged log file at {MERGED_LOG_PATH}: {exc}")

    def _on_close(self):
        try:
            self.watcher.stop()
        except Exception:
            pass
        try:
            self.store.close()
        except Exception:
            pass
        self.root.destroy()

    def _refresh_upload_summary(self):
        if not self.uploaded_files:
            self.upload_summary_var.set("No files uploaded yet.")
            return
        counts = {}
        for rec in self.uploaded_files:
            cat = rec.get("category", "")
            counts[cat] = counts.get(cat, 0) + 1
        summary = " | ".join(f"{c}: {n} file(s)" for c, n in counts.items())
        self.upload_summary_var.set(summary)

    def _refresh_raw_view(self):
        """Populate the Combined Raw Log tab by querying storage fresh --
        raw text is not kept in a separate Python list between refreshes.
        Chunks are packed tightly (no blank-line buffer between files)."""
        self.raw_text.configure(state="normal")
        self.raw_text.delete("1.0", "end")
        chunks = self.store.fetch_raw_chunks()
        for i, (cat, source, text) in enumerate(chunks):
            if i > 0:
                self.raw_text.insert("end", "\n")   # single blank line between files, not before every line
            header = f"===== [{cat}] {source} =====\n"
            self.raw_text.insert("end", header)
            trimmed = text.strip("\n")
            self.raw_text.insert("end", trimmed)
            self.raw_text.insert("end", "\n")
        self.raw_text.configure(state="disabled")

    def _refresh_filter_choices(self):
        methods = self.store.distinct_methods()
        statuses = self.store.distinct_statuses()

        # preserve current selections (by value) across a refresh
        prev_methods = self._get_listbox_selection(self.method_listbox)
        prev_statuses = self._get_listbox_selection(self.status_listbox)

        self.method_listbox.delete(0, "end")
        for m in methods:
            self.method_listbox.insert("end", m)
        self.status_listbox.delete(0, "end")
        for s in statuses:
            self.status_listbox.insert("end", s)

        self._set_listbox_selection(self.method_listbox, prev_methods)
        self._set_listbox_selection(self.status_listbox, prev_statuses)

    @staticmethod
    def _get_listbox_selection(listbox):
        return [listbox.get(i) for i in listbox.curselection()]

    @staticmethod
    def _set_listbox_selection(listbox, values):
        values = set(values)
        for i in range(listbox.size()):
            if listbox.get(i) in values:
                listbox.selection_set(i)

    # ------------------------------------------------------------- #
    #  Filtering / search -- queries storage directly rather than
    #  filtering a permanently-held in-memory list
    # ------------------------------------------------------------- #
    def _clear_filters(self):
        self.search_var.set("")
        self.filter_category_var.set("All")
        self.method_listbox.selection_clear(0, "end")
        self.status_listbox.selection_clear(0, "end")
        self.logic_var.set("AND")
        self._apply_filters()

    def _fetch_rows_from_db(self, cat_f, methods, statuses):
        """Pull only the rows matching the quick-filter selections from
        storage. methods/statuses are lists (possibly empty = no filter),
        so combinations like GET + POST or 200 + 404 are matched together.
        This is fetched fresh and transiently for each search -- it is not
        retained afterwards except as the currently-displayed result set
        (self._current_view_rows), which is replaced (not accumulated) on
        every call."""
        return self.store.fetch_rows(cat_f, methods, statuses)

    def _row_matches_search(self, row, field_filters, keywords, logic, search_columns):
        # explicit "Field: value" filters typed in the search box. Different
        # fields are AND-ed together; multiple comma-separated values for the
        # SAME field are OR-ed (row matches if it has any one of them) -- e.g.
        # "ip:192.168.34.5,10.5.36.4" matches rows with either IP.
        for column, values in field_filters:
            field_value = str(row.get(column, "")).lower()
            if not any(v in field_value for v in values):
                return False

        if not keywords:
            return True

        # free-text words: search only the selected column(s) if the user has
        # clicked column headers to select them, otherwise search all columns
        haystack = " ".join(str(row.get(c, "")) for c in search_columns).lower()
        checks = [kw in haystack for kw in keywords]
        return all(checks) if logic == "AND" else any(checks)

    def _on_search_action(self):
        """Wraps _apply_filters for the explicit Search button / Enter key
        press, showing a completion alert. Internal automatic refreshes
        (after upload, clear, column selection, etc.) call _apply_filters()
        directly and do NOT show this alert, so it only appears when the
        user actually asks for a search."""
        self._apply_filters()
        shown = len(self._current_view_rows)
        total = self.store.count_entries()
        messagebox.showinfo("Search Complete", f"Search done. Showing {shown} of {total} total log entries.")

    def _apply_filters(self):
        field_filters, keywords = parse_search_query(self.search_var.get())
        logic = self.logic_var.get()
        cat_f = self.filter_category_var.get()
        methods = self._get_listbox_selection(self.method_listbox)
        statuses = self._get_listbox_selection(self.status_listbox)

        # category/method/status are filtered in storage; only the resulting
        # candidate rows are pulled into Python, and only transiently
        candidate_rows = self._fetch_rows_from_db(cat_f, methods, statuses)

        # if the user has selected specific columns via header clicks, restrict
        # the plain free-text keyword search to just those columns
        search_columns = list(self.selected_columns) if self.selected_columns else list(COLUMNS)

        filtered = [row for row in candidate_rows
                    if self._row_matches_search(row, field_filters, keywords, logic, search_columns)]
        self._refresh_table(filtered)

    # ------------------------------------------------------------- #
    #  Table rendering
    # ------------------------------------------------------------- #
    def _refresh_table(self, rows=None):
        if rows is None:
            rows = self._fetch_rows_from_db("All", "All", "All")

        self.tree.delete(*self.tree.get_children())
        for i, row in enumerate(rows):
            values = [row.get(c, "") for c in COLUMNS]
            tag = "evenrow" if i % 2 == 0 else "oddrow"
            self.tree.insert("", "end", iid=str(i), values=values, tags=(tag,))

        # this replaces (not appends to) the previous result -- it's the only
        # place log rows live in Python memory, and only for what's on screen
        self._current_view_rows = rows

        total = self.store.count_entries()
        self.status_var.set(f"Showing {len(rows)} of {total} total log entries.")

    # ------------------------------------------------------------- #
    #  Column selection (header click toggles)
    # ------------------------------------------------------------- #
    def _toggle_column_selection(self, col):
        if col in self.selected_columns:
            self.selected_columns.remove(col)
            self.tree.heading(col, text=COLUMN_LABELS[col])
        else:
            self.selected_columns.add(col)
            self.tree.heading(col, text="\u2713 " + COLUMN_LABELS[col])

        if self.selected_columns:
            names = ", ".join(COLUMN_LABELS[c] for c in self.selected_columns)
            self.column_select_var.set(
                f"Selected columns for copy/export AND for plain-word search: {names}")
        else:
            self.column_select_var.set(
                "Tip: click a column header to select/deselect that column for copy/export "
                "(plain-word search will also be scoped to the selected column(s)).")

        # re-apply the current search so plain-word search immediately respects
        # the newly selected/deselected column(s)
        self._apply_filters()

    def _clear_column_selection(self):
        for col in list(self.selected_columns):
            self.tree.heading(col, text=COLUMN_LABELS[col])
        self.selected_columns.clear()
        self.column_select_var.set(
            "Tip: click a column header to select/deselect that column for copy/export "
            "(plain-word search will also be scoped to the selected column(s)).")
        self._apply_filters()

    def _active_columns(self):
        return list(self.selected_columns) if self.selected_columns else list(COLUMNS)

    def _dedupe_rows(self, rows, columns):
        """Remove duplicate entries, judged only by the given columns (e.g. if
        the user has selected just 'IP Address' + 'Path', two rows that only
        differ in Time/Status/Description still count as duplicates and only
        the first occurrence is kept)."""
        seen = set()
        unique_rows = []
        for row in rows:
            key = tuple(str(row.get(c, "")).strip().lower() for c in columns)
            if key in seen:
                continue
            seen.add(key)
            unique_rows.append(row)
        return unique_rows

    def _prepare_rows(self, rows, columns):
        """Apply duplicate-removal (if enabled) before copy/export."""
        if self.dedupe_var.get():
            return self._dedupe_rows(rows, columns)
        return rows

    # ------------------------------------------------------------- #
    #  Row helpers
    # ------------------------------------------------------------- #
    def _get_selected_row_dicts(self):
        rows = []
        for iid in self.tree.selection():
            idx = int(iid)
            if 0 <= idx < len(self._current_view_rows):
                rows.append(self._current_view_rows[idx])
        return rows

    def _get_all_view_row_dicts(self):
        return list(self._current_view_rows)

    # ------------------------------------------------------------- #
    #  Filtered table row -> matching Raw Log line
    # ------------------------------------------------------------- #
    def _jump_to_raw_log_from_context(self):
        """Right-click menu action: jump to (and highlight) the matching
        line in the Combined Raw Log tab for whichever row was clicked."""
        if not self._last_click_row_col:
            messagebox.showinfo("Move to Raw Log", "Right-click a row first, then use this option.")
            return
        row_id, _col_id = self._last_click_row_col
        try:
            idx = int(row_id)
        except ValueError:
            return
        if idx >= len(self._current_view_rows):
            return
        self._jump_to_raw_line(self._current_view_rows[idx])

    def _jump_to_raw_line(self, row):
        description = (row.get("description") or "").strip()
        if not description:
            return

        self.raw_text.configure(state="normal")
        self.raw_text.tag_remove("selected_line", "1.0", "end")
        # search for the raw line's own text within the combined raw view
        pos = self.raw_text.search(description, "1.0", stopindex="end")
        if pos:
            line_no = pos.split(".")[0]
            self.raw_text.tag_add("selected_line", f"{line_no}.0", f"{line_no}.end")
            self.raw_text.tag_configure("selected_line", background=PALETTE["accent"], foreground="white")
            self.raw_text.see(f"{line_no}.0")
            if self.raw_tab_index is not None:
                self.notebook.select(self.raw_tab_index)
        self.raw_text.configure(state="disabled")

    # ------------------------------------------------------------- #
    #  Mouse interactions: click tracking, cell popup, select-all
    # ------------------------------------------------------------- #
    def _on_tree_left_click(self, event):
        """Track which row/column was under the cursor on a plain left click,
        so a following double-click knows exactly which cell to open."""
        region = self.tree.identify("region", event.x, event.y)
        if region != "cell":
            self._last_click_row_col = None
            return
        row_id = self.tree.identify_row(event.y)
        col_id = self.tree.identify_column(event.x)  # e.g. '#3'
        self._last_click_row_col = (row_id, col_id)

    def _on_cell_double_click(self, event):
        """Double-click any cell in a row to open that row's Path value in
        the browser, using the domain configured in the Upload panel. Cell
        copying is still available via the right-click menu ('Copy Cell')."""
        region = self.tree.identify("region", event.x, event.y)
        if region != "cell":
            return
        row_id = self.tree.identify_row(event.y)
        if not row_id:
            return

        path_value = self.tree.set(row_id, "path")
        if path_value.strip():
            self._open_path_in_browser(path_value)
        else:
            messagebox.showinfo("Open in Browser", "This row has no Path value to open.")

    def _open_path_in_browser(self, path_value):
        """Open https://<domain>/<path> in the default web browser, where
        <domain> comes from the 'Browser domain' field in the Upload bar."""
        domain = self.base_domain_var.get().strip()
        if not domain:
            messagebox.showinfo(
                "Open in Browser",
                "Set a domain first in the 'Browser domain' field at the top of the "
                "Upload Log Files panel (e.g. example.com), then double-click a Path cell again.")
            return

        if not domain.startswith("http://") and not domain.startswith("https://"):
            domain = "https://" + domain
        domain = domain.rstrip("/")
        path_part = path_value.strip()
        if not path_part.startswith("/"):
            path_part = "/" + path_part

        url = domain + path_part
        try:
            webbrowser.open(url)
            self.status_var.set(f"Opened in browser: {url}")
        except Exception as exc:
            messagebox.showerror("Open in Browser", f"Could not open browser for:\n{url}\n\n{exc}")

    def _open_last_clicked_path_in_browser(self):
        """Right-click menu equivalent of double-clicking a Path cell."""
        if not self._last_click_row_col:
            messagebox.showinfo("Open Path in Browser", "Click a Path cell first, then use this option.")
            return
        row_id, col_id = self._last_click_row_col
        try:
            col_index = int(col_id.replace("#", "")) - 1
        except ValueError:
            return
        if col_index < 0 or col_index >= len(COLUMNS):
            return
        column_key = COLUMNS[col_index]
        if column_key != "path":
            messagebox.showinfo("Open Path in Browser", "The last-clicked cell isn't in the Path column.")
            return
        value = self.tree.set(row_id, column_key)
        if value.strip():
            self._open_path_in_browser(value)

    def _copy_cell_popup(self):
        """Right-click menu equivalent of double-clicking a cell."""
        if not self._last_click_row_col:
            messagebox.showinfo("Copy Cell", "Click a cell first, then use this option.")
            return
        row_id, col_id = self._last_click_row_col
        try:
            col_index = int(col_id.replace("#", "")) - 1
        except ValueError:
            return
        if col_index < 0 or col_index >= len(COLUMNS):
            return
        column_key = COLUMNS[col_index]
        value = self.tree.set(row_id, column_key)
        self._show_cell_popup(COLUMN_LABELS[column_key], value)

    # ------------------------------------------------------------- #
    #  A small read-only-but-selectable text popup so the user can drag-select
    # ------------------------------------------------------------- #

    def _show_cell_popup(self, title, value):
 
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("460x200")
        win.configure(bg=PALETTE["surface"])
        win.transient(self.root)

        ttk.Label(
            win, text=f"{title} — Select text with the mouse, then Ctrl+C to copy ",
            wraplength=530, justify="left",
        ).pack(anchor="w", padx=10, pady=(10, 4))

        text_frame = ttk.Frame(win)
        text_frame.pack(fill="both", expand=True, padx=10)
        yscroll = ttk.Scrollbar(text_frame, orient="vertical")
        text_widget = tk.Text(text_frame, height=4, wrap="word", font=FONT_MONO,
                               yscrollcommand=yscroll.set)
        yscroll.config(command=text_widget.yview)
        text_widget.insert("1.0", value)
        
        text_widget.configure(state="disabled") # disabled = can't be edited
        text_widget.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")
        text_widget.focus_set()

        btn_row = ttk.Frame(win)
        btn_row.pack(fill="x", padx=10, pady=8)
        ttk.Button(btn_row, text="Copy Whole Value", style="Accent.TButton",
                   command=lambda: self._copy_to_clipboard(value)).pack(side="left")
        ttk.Button(btn_row, text="Close", command=win.destroy).pack(side="right")

    def _select_all_rows(self):
        self.tree.selection_set(self.tree.get_children())
        self.status_var.set(f"Selected all {len(self.tree.get_children())} visible row(s).")
        return "break"

    # ------------------------------------------------------------- #
    #  Context menu
    # ------------------------------------------------------------- #
    def _show_context_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if iid and iid not in self.tree.selection():
            self.tree.selection_set(iid)
        col_id = self.tree.identify_column(event.x)
        if iid and col_id:
            self._last_click_row_col = (iid, col_id)
        self.context_menu.tk_popup(event.x_root, event.y_root)

    # ------------------------------------------------------------- #
    #  Copy to clipboard (row + column aware)
    # ------------------------------------------------------------- #
    def _rows_to_tsv(self, rows, columns):
        lines = ["\t".join(COLUMN_LABELS[c] for c in columns)]
        for row in rows:
            lines.append("\t".join(str(row.get(c, "")) for c in columns))
        return "\n".join(lines)

    def _copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()

    def _copy_selected_rows(self):
        rows = self._get_selected_row_dicts()
        if not rows:
            messagebox.showinfo("Copy Rows", "No rows selected. Select one or more rows first.")
            return
        columns = self._active_columns()
        original_count = len(rows)
        rows = self._prepare_rows(rows, columns)
        self._copy_to_clipboard(self._rows_to_tsv(rows, columns))
        dedupe_note = f" ({original_count - len(rows)} duplicate(s) removed)" if self.dedupe_var.get() else ""
        self.status_var.set(f"Copied {len(rows)} selected row(s), {len(columns)} column(s) to clipboard.{dedupe_note}")

    def _copy_all_rows(self):
        rows = self._get_all_view_row_dicts()
        if not rows:
            messagebox.showinfo("Copy All", "No data to copy.")
            return
        columns = self._active_columns()
        original_count = len(rows)
        rows = self._prepare_rows(rows, columns)
        self._copy_to_clipboard(self._rows_to_tsv(rows, columns))
        dedupe_note = f" ({original_count - len(rows)} duplicate(s) removed)" if self.dedupe_var.get() else ""
        self.status_var.set(f"Copied ALL {len(rows)} visible row(s), {len(columns)} column(s) to clipboard.{dedupe_note}")

    # ------------------------------------------------------------- #
    #  JSON copy / export
    # ------------------------------------------------------------- #
    def _rows_to_json_str(self, rows, columns):
        data = [{c: row.get(c, "") for c in columns} for row in rows]
        return json.dumps(data, indent=2, ensure_ascii=False)

    def _copy_as_json(self, all_rows=False):
        rows = self._get_all_view_row_dicts() if all_rows else self._get_selected_row_dicts()
        if not rows:
            messagebox.showinfo("Copy as JSON", "No rows available to copy (select rows first if needed).")
            return
        columns = self._active_columns()
        original_count = len(rows)
        rows = self._prepare_rows(rows, columns)
        self._copy_to_clipboard(self._rows_to_json_str(rows, columns))
        scope = "ALL" if all_rows else "selected"
        dedupe_note = f" ({original_count - len(rows)} duplicate(s) removed)" if self.dedupe_var.get() else ""
        self.status_var.set(f"Copied {len(rows)} {scope} row(s) as JSON to clipboard.{dedupe_note}")

    def _export_json(self, all_rows=False):
        rows = self._get_all_view_row_dicts() if all_rows else self._get_selected_row_dicts()
        if not rows:
            messagebox.showinfo("Export JSON", "No rows available to export (select rows first if needed).")
            return
        columns = self._active_columns()
        original_count = len(rows)
        rows = self._prepare_rows(rows, columns)

        default_name = f"logs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = filedialog.asksaveasfilename(
            title="Save JSON export",
            defaultextension=".json",
            initialfile=default_name,
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not filepath:
            return

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(self._rows_to_json_str(rows, columns))
        except Exception as exc:
            messagebox.showerror("Export Error", f"Could not save file:\n{exc}")
            return

        scope = "ALL" if all_rows else "selected"
        dedupe_note = f" ({original_count - len(rows)} duplicate(s) removed)" if self.dedupe_var.get() else ""
        self.status_var.set(f"Exported {len(rows)} {scope} row(s) to {filepath}{dedupe_note}")
        messagebox.showinfo("Export Complete", f"Exported {len(rows)} row(s) to:\n{filepath}{dedupe_note}")

    def _export_split_by_value(self):
        """Writes one JSON file PER searched value for a multi-value field
        search (e.g. 'ip:192.168.34.5,10.5.36.4') into a chosen folder --
        each file contains only that single value's matching rows. Values
        with zero matches are silently skipped (reported in the summary,
        not treated as an error), matching how the combined search itself
        behaves: found values are shown, not-found values are simply ignored."""
        field_filters, _keywords = parse_search_query(self.search_var.get())
        multi_value_fields = [(col, vals) for col, vals in field_filters if len(vals) > 1]
        if not multi_value_fields:
            messagebox.showinfo(
                "Export Split by Value",
                "Type a multi-value field search first, e.g. 'ip:192.168.34.5,10.5.36.4', "
                "then use this option to get one file per value.")
            return

        directory = filedialog.askdirectory(title="Choose a folder for the split export files")
        if not directory:
            return

        columns = self._active_columns()
        source_rows = self._get_all_view_row_dicts()
        written, skipped = [], []

        for column, values in multi_value_fields:
            for value in values:
                matches = [row for row in source_rows if value in str(row.get(column, "")).lower()]
                if not matches:
                    skipped.append(f"{column}={value}")
                    continue
                if self.dedupe_var.get():
                    matches = self._dedupe_rows(matches, columns)
                safe_value = re.sub(r'[^A-Za-z0-9._-]', '_', value)
                filename = f"search_split_{column}_{safe_value}.json"
                filepath = os.path.join(directory, filename)
                try:
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(self._rows_to_json_str(matches, columns))
                    written.append(f"{filename} ({len(matches)} row(s))")
                except Exception as exc:
                    messagebox.showerror("Export Error", f"Could not write {filename}:\n{exc}")

        summary = f"Wrote {len(written)} file(s) to:\n{directory}\n\n" + "\n".join(written)
        if skipped:
            summary += f"\n\nNo matches found for (skipped): {', '.join(skipped)}"
        messagebox.showinfo("Export Split by Value Complete", summary)
        self.status_var.set(f"Exported {len(written)} split file(s) to {directory}.")


def main():
    root = tk.Tk()
    app = LogAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
