#!/usr/bin/env python3
"""
Log Analyzer & Viewer
----------------------
ACreated  by: ANISH R
Date: 2024-07-20
Version: 1.0.0
Release: Initial Release
Language: Python 3
GUI Framework: Tkinter
For any queries or suggestions, contact: anishry88@gmail.com ph: +91-9895 086 743
Developer: Anish R
Email:anishry88@gmail.com
Developer's Phone: +91-9895 086 743
Tool For CERT-K
-----------
Disclaimer:
-----------
This tool is intended for educational and ethical use only. The author is not responsible for any misuse
or damage caused by this software. Always obtain proper authorization before testing any website.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re
import os
import json
from datetime import datetime

APP_TITLE = "Log Analyzer & Viewer"

CATEGORIES = [
    "System Logs",
    "Application Logs",
    "Security Logs",
    "Access Logs",
    "Audit Logs",
]

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
    "path": 220,
    "status": 60,
    "time": 160,
    "description": 380,
}

# --------------------------------------------------------------------- #
#                       Log line parsing helpers                        #
# --------------------------------------------------------------------- #
IP_RE = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')
METHOD_RE = re.compile(r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\b')
COMBINED_RE = re.compile(r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"')
PATH_RE = re.compile(r'(?<!\S)(/[^\s"\'()<>,;]+)')


STATUS_PATTERNS = [
    re.compile(r'"\s+([1-5]\d{2})\b'),
    re.compile(r'\bstatus(?:[:=]\s*|\s+is\s+)(\d{3})\b', re.IGNORECASE),
    re.compile(r'(?<!\S)([1-5]\d{2})(?!\S)'),
]


TIME_PATTERNS = [
    re.compile(r'\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b'),
    re.compile(r'\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\s+\d{4})?)\b'),
    re.compile(r'\b(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})\b'),
    re.compile(r'\[([^\]]+)\]'),
]


# --------------------------------------------------------------------- #
#            Field-aware search query parsing ("Field: value")          #
# --------------------------------------------------------------------- #

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

    Returns (field_filters, keywords) where field_filters is a list of
    (column_key, value_lowercase) tuples and keywords is a list of lowercase
    free-text words to search across (selected) columns.
    """
    field_filters = []
    remaining = text

    for match in FIELD_TOKEN_RE.finditer(text):
        label = match.group(1).strip().lower()
        value = match.group(2).strip().strip(",;")
        column = FIELD_ALIASES.get(label)
        if column and value:
            field_filters.append((column, value.lower()))
            remaining = remaining.replace(match.group(0), " ", 1)

   
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
#                              Main GUI App                             #
# --------------------------------------------------------------------- #
class LogAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1400x800")
        self.root.minsize(1000, 600)

        self.entries = []          
        self.raw_chunks = []       
        self.selected_columns = set()   
        self.dedupe_var = tk.BooleanVar(value=False)  

        self._build_style()
        self._build_widgets()
        self._refresh_table()

    # ------------------------------------------------------------- #
    #  Styling
    # ------------------------------------------------------------- #
    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=24, font=("Consolas", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        style.configure("Accent.TButton", font=("Segoe UI", 9, "bold"))

    # ------------------------------------------------------------- #
    #  Widget construction
    # ------------------------------------------------------------- #
    def _build_widgets(self):
        self._build_upload_bar()
        self._build_search_bar()
        self._build_notebook()
        self._build_action_bar()
        self._build_status_bar()

    # ---------- Upload bar ---------- #
    def _build_upload_bar(self):
        frame = ttk.LabelFrame(self.root, text="Upload Log Files")
        frame.pack(fill="x", padx=8, pady=(8, 4))

        for cat in CATEGORIES:
            btn = ttk.Button(frame, text=f"Upload {cat}",
                              command=lambda c=cat: self._upload_files(c))
            btn.pack(side="left", padx=4, pady=6)

        ttk.Separator(frame, orient="vertical").pack(side="left", fill="y", padx=8, pady=4)

        ttk.Button(frame, text="Clear All Data", command=self._clear_all).pack(
            side="left", padx=4, pady=6)

        self.upload_summary_var = tk.StringVar(value="No files uploaded yet.")
        ttk.Label(frame, textvariable=self.upload_summary_var, foreground="#444").pack(
            side="left", padx=12)

    # ---------- Search bar ---------- #
    def _build_search_bar(self):
        frame = ttk.LabelFrame(self.root, text="Search / Filter")
        frame.pack(fill="x", padx=8, pady=4)

        ttk.Label(frame, text="Search text:").grid(row=0, column=0, padx=4, pady=(6, 0), sticky="w")
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(frame, textvariable=self.search_var, width=45)
        search_entry.grid(row=0, column=1, padx=4, pady=(6, 0), sticky="w")
        search_entry.bind("<Return>", lambda e: self._apply_filters())

        self.logic_var = tk.StringVar(value="AND")
        ttk.Radiobutton(frame, text="Match ALL words (AND)", variable=self.logic_var,
                         value="AND").grid(row=0, column=2, padx=4, pady=(6, 0), sticky="w")
        ttk.Radiobutton(frame, text="Match ANY word (OR)", variable=self.logic_var,
                         value="OR").grid(row=0, column=3, padx=4, pady=(6, 0), sticky="w")

        hint_text = "Field search examples: Source: access.log   IP: 192.168.1.10   Status: 200  (combine with commas). Plain words with no field name search across all columns, or only the columns selected in the table header below."
        ttk.Label(frame, text=hint_text, foreground="#555", justify="left", wraplength=1150).grid(
            row=1, column=0, columnspan=6, padx=4, pady=(0, 6), sticky="w")

        # Field specific quick filters
        ttk.Label(frame, text="Category:").grid(row=2, column=0, padx=4, pady=6, sticky="w")
        self.filter_category_var = tk.StringVar(value="All")
        self.category_combo = ttk.Combobox(frame, textvariable=self.filter_category_var,
                                            values=["All"] + CATEGORIES, state="readonly", width=18)
        self.category_combo.grid(row=2, column=1, padx=4, sticky="w")

        ttk.Label(frame, text="Method:").grid(row=2, column=2, padx=4, sticky="w")
        self.filter_method_var = tk.StringVar(value="All")
        self.method_combo = ttk.Combobox(frame, textvariable=self.filter_method_var,
                                          values=["All"], state="readonly", width=12)
        self.method_combo.grid(row=2, column=3, padx=4, sticky="w")

        ttk.Label(frame, text="Status:").grid(row=2, column=4, padx=4, sticky="w")
        self.filter_status_var = tk.StringVar(value="All")
        self.status_combo = ttk.Combobox(frame, textvariable=self.filter_status_var,
                                          values=["All"], state="readonly", width=12)
        self.status_combo.grid(row=2, column=5, padx=4, sticky="w")

        ttk.Button(frame, text="Search", command=self._apply_filters).grid(
            row=2, column=6, padx=8)
        ttk.Button(frame, text="Clear Filters", command=self._clear_filters).grid(
            row=2, column=7, padx=4)

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

        self.tree.tag_configure("oddrow", background="#f5f5f5")
        self.tree.tag_configure("evenrow", background="#ffffff")
        self.tree.tag_configure("col_selected_marker", background="#dbe9ff")

        self.tree.grid(row=0, column=0, sticky="nsew")
        vscroll.grid(row=0, column=1, sticky="ns")
        hscroll.grid(row=1, column=0, sticky="ew")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

        # right click context menu
        self.context_menu = tk.Menu(self.tree, tearoff=0)
        self.context_menu.add_command(label="Copy Selected Row(s)", command=self._copy_selected_rows)
        self.context_menu.add_command(label="Copy ALL Rows", command=self._copy_all_rows)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Selected Row(s) as JSON", command=lambda: self._copy_as_json(all_rows=False))
        self.context_menu.add_command(label="Copy ALL Rows as JSON", command=lambda: self._copy_as_json(all_rows=True))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Export Selected Row(s) to JSON file...", command=lambda: self._export_json(all_rows=False))
        self.context_menu.add_command(label="Export ALL Rows to JSON file...", command=lambda: self._export_json(all_rows=True))
        self.context_menu.add_separator()
        self.context_menu.add_checkbutton(
            label="Remove Duplicate Entries (on copy/export)", variable=self.dedupe_var)
        self.context_menu.add_command(label="Clear Column Selection", command=self._clear_column_selection)

        self.tree.bind("<Button-3>", self._show_context_menu)   
        self.tree.bind("<Button-2>", self._show_context_menu)   

       
        self.column_select_var = tk.StringVar(
            value="Tip: click a column header to select/deselect that column for copy/export "
                  "(plain-word search will also be scoped to the selected column(s)).")
        ttk.Label(parent, textvariable=self.column_select_var, foreground="#555").pack(
            anchor="w", padx=4, pady=(2, 4))

    def _build_raw_view(self, parent):
        container = ttk.Frame(parent)
        container.pack(fill="both", expand=True)

        vscroll = ttk.Scrollbar(container, orient="vertical")
        hscroll = ttk.Scrollbar(container, orient="horizontal")

        self.raw_text = tk.Text(container, wrap="none", font=("Consolas", 9),
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
        frame = ttk.LabelFrame(self.root, text="Copy / Export")
        frame.pack(fill="x", padx=8, pady=4)

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

        row2 = ttk.Frame(frame)
        row2.pack(fill="x")

        ttk.Checkbutton(
            row2, text="Remove duplicate entries when copying/exporting",
            variable=self.dedupe_var,
        ).pack(side="left", padx=4, pady=(0, 6))

        ttk.Label(
            row2,
            text="Duplicates are judged by the currently selected column(s) in the table "
                 "header (e.g. select IP Address + Path only, then copy, to get a unique "
                 "IP/Path list). If no column is selected, whole rows are compared.",
            foreground="#555",
        ).pack(side="left", padx=4, pady=(0, 6))

    # ---------- Status bar ---------- #
    def _build_status_bar(self):
        self.status_var = tk.StringVar(value="Ready.")
        bar = ttk.Label(self.root, textvariable=self.status_var, relief="sunken", anchor="w")
        bar.pack(fill="x", side="bottom")

    # ------------------------------------------------------------- #
    #  Upload handling
    # ------------------------------------------------------------- #
    def _upload_files(self, category):
        filepaths = filedialog.askopenfilenames(
            title=f"Select one or more {category} files",
            filetypes=[("Log / Text files", "*.log *.txt *.csv *.json *.*"), ("All files", "*.*")],
        )
        if not filepaths:
            return

        added = 0
        for path in filepaths:
            source = os.path.basename(path)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    raw_text = f.read()
            except Exception as exc:
                messagebox.showerror("Read Error", f"Could not read {path}:\n{exc}")
                continue

            self.raw_chunks.append((category, source, raw_text))

            for line in raw_text.splitlines():
                row = parse_log_line(line, category, source)
                if row:
                    self.entries.append(row)
                    added += 1

        self._refresh_upload_summary()
        self._refresh_raw_view()
        self._refresh_filter_choices()
        self._apply_filters()
        self.status_var.set(f"Added {added} log line(s) from {len(filepaths)} file(s) under '{category}'.")

    def _clear_all(self):
        if not self.entries and not self.raw_chunks:
            return
        if not messagebox.askyesno("Clear All", "Remove all uploaded log data?"):
            return
        self.entries.clear()
        self.raw_chunks.clear()
        self.selected_columns.clear()
        self._refresh_upload_summary()
        self._refresh_raw_view()
        self._refresh_filter_choices()
        self._apply_filters()
        self.status_var.set("Cleared all data.")

    def _refresh_upload_summary(self):
        if not self.raw_chunks:
            self.upload_summary_var.set("No files uploaded yet.")
            return
        counts = {}
        for cat, _src, _txt in self.raw_chunks:
            counts[cat] = counts.get(cat, 0) + 1
        summary = " | ".join(f"{c}: {n} file(s)" for c, n in counts.items())
        self.upload_summary_var.set(summary)

    def _refresh_raw_view(self):
        self.raw_text.configure(state="normal")
        self.raw_text.delete("1.0", "end")
        for cat, source, text in self.raw_chunks:
            header = f"\n===== [{cat}] {source} =====\n"
            self.raw_text.insert("end", header)
            self.raw_text.insert("end", text)
            if not text.endswith("\n"):
                self.raw_text.insert("end", "\n")
        self.raw_text.configure(state="disabled")

    def _refresh_filter_choices(self):
        methods = sorted({e["method"] for e in self.entries if e["method"]})
        statuses = sorted({e["status"] for e in self.entries if e["status"]})
        self.method_combo["values"] = ["All"] + methods
        self.status_combo["values"] = ["All"] + statuses
        if self.filter_method_var.get() not in (["All"] + methods):
            self.filter_method_var.set("All")
        if self.filter_status_var.get() not in (["All"] + statuses):
            self.filter_status_var.set("All")

    # ------------------------------------------------------------- #
    #  Filtering / search
    # ------------------------------------------------------------- #
    def _clear_filters(self):
        self.search_var.set("")
        self.filter_category_var.set("All")
        self.filter_method_var.set("All")
        self.filter_status_var.set("All")
        self.logic_var.set("AND")
        self._apply_filters()

    def _row_matches(self, row, field_filters, keywords, logic, cat_f, method_f, status_f, search_columns):
        if cat_f != "All" and row["category"] != cat_f:
            return False
        if method_f != "All" and row["method"] != method_f:
            return False
        if status_f != "All" and row["status"] != status_f:
            return False

     
        for column, value in field_filters:
            if value not in str(row.get(column, "")).lower():
                return False

        if not keywords:
            return True

      
        haystack = " ".join(str(row.get(c, "")) for c in search_columns).lower()
        checks = [kw in haystack for kw in keywords]
        return all(checks) if logic == "AND" else any(checks)

    def _apply_filters(self):
        field_filters, keywords = parse_search_query(self.search_var.get())
        logic = self.logic_var.get()
        cat_f = self.filter_category_var.get()
        method_f = self.filter_method_var.get()
        status_f = self.filter_status_var.get()

      
        search_columns = list(self.selected_columns) if self.selected_columns else list(COLUMNS)

        filtered = [row for row in self.entries
                    if self._row_matches(row, field_filters, keywords, logic,
                                          cat_f, method_f, status_f, search_columns)]
        self._refresh_table(filtered)

    # ------------------------------------------------------------- #
    #  Table rendering
    # ------------------------------------------------------------- #
    def _refresh_table(self, rows=None):
        if rows is None:
            rows = self.entries

        self.tree.delete(*self.tree.get_children())
        for i, row in enumerate(rows):
            values = [row.get(c, "") for c in COLUMNS]
            tag = "evenrow" if i % 2 == 0 else "oddrow"
            self.tree.insert("", "end", iid=str(i), values=values, tags=(tag,))

        self._current_view_rows = rows
        self.status_var.set(f"Showing {len(rows)} of {len(self.entries)} total log entries.")

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
    #  Context menu
    # ------------------------------------------------------------- #
    def _show_context_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if iid and iid not in self.tree.selection():
            self.tree.selection_set(iid)
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


def main():
    root = tk.Tk()
    app = LogAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
