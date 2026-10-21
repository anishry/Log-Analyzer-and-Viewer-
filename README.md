# Log Analyzer & Viewer

**Version:** 1.0.0  
**Release:** Initial Release  
**Language:** Python 3  
**GUI Framework:** Tkinter  

A desktop-based log analysis tool developed using Python and Tkinter. It helps cybersecurity professionals, SOC analysts, system administrators, and security trainees upload, view, search, filter, and export log data through a graphical user interface.

The application extracts useful information from log files and displays it in a structured table, making log investigation and preliminary security analysis easier.

## 1. Features

### Log File Management
- Upload multiple files under five log categories:
  - System Logs
  - Application Logs
  - Security Logs
  - Access Logs
  - Audit Logs
- Supports log, text, CSV, JSON, and other readable text files.
- Displays the combined raw content of uploaded log files.
- Clear all uploaded data when starting a new analysis.

### Automatic Log Parsing
The application uses regular expressions to extract information from individual log lines.

The structured table includes:

| Field | Description |
|---|---|
| Category | Selected log category |
| Source File | Name of the uploaded file |
| IP Address | IPv4 address detected in the log line |
| Method | HTTP method, such as GET or POST |
| Path | URL path or request path |
| Status | Detected HTTP or other three-digit status code |
| Time | Timestamp or bracketed time-like value |
| Description | Original log line |

The parser is designed to handle common Apache/Nginx access log formats, syslog-style entries, and generic security or audit messages. Parsing results depend on the format and content of the input logs.

### Search and Filtering
- Search using free-text keywords.
- Match **ALL words (AND)** or **ANY word (OR)**.
- Filter by log category, HTTP method, and status code.
- Use field-specific search expressions, such as:

```text
IP: 192.168.1.10
Source: access.log
Status: 404
Method: POST
Path: /login
```

Combine field filters and free-text keywords:

```text
failed login IP: 192.168.1.10
Source: access.log, Status: 404
```

- Select table columns to limit free-text searching to particular fields.
- Clear filters to restore the full view.

### Copy and Export
- Copy selected rows or all currently visible rows as tab-separated text.
- Copy selected or visible rows as JSON.
- Export selected or visible rows to a JSON file.
- Select individual columns by clicking their table headers.
- Remove duplicate entries during copy or export, based on the selected columns.
- Use the right-click context menu for quick access to copy and export actions.

### Graphical User Interface
- Desktop interface built with Tkinter and ttk.
- Structured log table with vertical and horizontal scrolling.
- Separate tab for combined raw log content.
- Alternating table row colours for readability.
- Status bar displaying processing and export information.

## 2. Requirements

- Python 3.8 or later recommended.
- Windows, Linux, or macOS with a working graphical desktop environment.
- Tkinter support must be available in the Python installation.

**Dependencies:** No third-party Python packages are required. The application uses Python's standard library.

## 3. Installation

### Step 1: Clone the Repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd <YOUR_REPOSITORY_FOLDER>
```

Replace the placeholders with your actual GitHub repository URL and folder name.

### Step 2: Check Python

```bash
python --version
```

On some Linux systems, use:

```bash
python3 --version
```

### Step 3: Verify Tkinter

On Windows, Tkinter is normally included with standard Python installations.

On Ubuntu or Debian-based Linux systems, install Tkinter if it is missing:

```bash
sudo apt update
sudo apt install python3-tk
```

## 4. Run the Application

Place the source file in your project directory with the filename `log_analyzer.py`.

Run:

```bash
python log_analyzer.py
```

On Linux or macOS, you may need:

```bash
python3 log_analyzer.py
```

The Log Analyzer & Viewer window should open.

## 5. How to Use

### Step 1: Upload Log Files

Select the appropriate upload button for the log category you want to investigate. Choose one or more files from your system.

### Step 2: Review Parsed Logs

Open the **Structured Log Table** tab to view the extracted fields. The **Combined Raw Log** tab displays the original uploaded log content grouped by category and source filename.

### Step 3: Search and Filter

Enter a keyword or field-specific expression in the search box. Choose AND or OR matching for free-text terms, and use the category, method, and status dropdowns to narrow the results.

### Step 4: Select Rows or Columns

Select rows in the table for targeted copying or export. Click column headers to select or deselect columns. Selected columns also determine the fields used for duplicate detection when duplicate removal is enabled.

### Step 5: Copy or Export

Use the action buttons or right-click menu to copy data to the clipboard or export it as JSON.

The export contains the rows in the current filtered view, or the selected rows when a selected-row operation is used. Only the active columns are included.

### Step 6: Clear Data

Use **Clear All Data** to remove the loaded log entries and raw log content from the application. Confirm the prompt to proceed.

## 6. Example Log Input

Example Apache/Nginx-style access log:

```text
192.168.1.10 - - [21/Oct/2026:10:15:32 +0530] "GET /login HTTP/1.1" 200 1024
```

Possible extracted fields:

| Field | Example |
|---|---|
| Category | Access Logs |
| Source File | access.log |
| IP Address | 192.168.1.10 |
| Method | GET |
| Path | /login |
| Status | 200 |
| Time | 21/Oct/2026:10:15:32 +0530 |
| Description | Original log line |

*Note: This is an illustrative example. The exact extracted values depend on the regular-expression matching rules in the current release.*

## 7. Project Structure

```text
Log-Analyzer-Viewer/
├── log_analyzer.py
├── README.md
├── LICENSE
└── .gitignore
```

`LICENSE` is optional until you choose a license. Add it before distributing the project under an open-source license.

## 8. Limitations

- Log fields are extracted using regular expressions rather than format-specific parsers.
- IPv4 detection is pattern-based and does not validate whether each octet is within the valid IP address range.
- HTTP method, path, status, and timestamp extraction may be incomplete or inaccurate for unusual log formats.
- The parser does not perform advanced threat detection, event correlation, or automated incident response.
- The application loads complete files into memory, so very large log files may affect performance.
- Uploaded data is displayed and processed locally by the application; the current implementation does not include remote log collection or cloud-based analysis.
- JSON export is intended for the parsed records, not as a forensic-preservation mechanism for original evidence.

## 9. Security and Privacy

Log files may contain IP addresses, usernames, session identifiers, URLs, and other sensitive information.

- Use authorised log files only.
- Avoid committing real production logs or sensitive incident data to a public repository.
- Review exported JSON files before sharing them.
- Store investigation data securely and follow your organisation's data-handling policies.

This tool assists with preliminary log review. It should not be treated as a replacement for a SIEM platform, a dedicated forensic tool, or a comprehensive security monitoring solution.

## 10. Initial Release — v1.0.0

The first release includes:

- Multi-category log file uploads.
- Combined raw log viewing.
- Regular-expression-based log parsing.
- Structured table display with scrolling.
- Free-text search with AND/OR matching.
- Field-specific search expressions.
- Category, method, and status filters.
- Column selection for searching, copying, and exporting.
- Clipboard copy in tab-separated and JSON formats.
- JSON export with optional duplicate removal.

## 11. Future Enhancements

Potential improvements for future versions include:

- Support for additional log formats and IPv6 addresses.
- Improved timestamp normalisation and validation.
- Advanced detection rules for suspicious activity.
- Timeline-based event investigation.
- Severity classification and alert highlighting.
- CSV export and additional report formats.
- Improved performance for large log files.
- Unit tests and automated parser validation.

These are planned enhancements and are not features claimed for version 1.0.0.

## 12. Contributing

Contributions, bug reports, and feature suggestions are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Make and test your changes.
4. Submit a pull request describing the changes.

## 13. Disclaimer

This application is provided for educational, administrative, and authorised cybersecurity analysis purposes. Users are responsible for ensuring they have permission to access and analyse the log files they process.

## 14. Author

**Project:** Log Analyzer & Viewer  
**Release:** v1.0.0 — Initial Release  
**Technology:** Python, Tkinter, Regular Expressions, JSON


