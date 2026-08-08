# SentinelAudit

A **defensive, read-only** Windows security auditing tool. It inspects local system configuration (firewall, Defender, services, users, registry, event logs, startup entries, scheduled tasks, etc.), scores the overall security posture, and generates professional PDF/HTML/JSON reports plus a styled CLI dashboard.

> SentinelAudit **never modifies system settings**. It only reads configuration state and reports on it.

---

## Requirements & Prerequisites

- **Operating System**: Windows 10 or Windows 11 (relies on `winreg`, `psutil`, WMI, and PowerShell — will **not** run on Linux or macOS).
- **Python**: Version 3.12 or higher (added to System PATH).
- **Privileges**: Administrator rights are recommended for full audit coverage (firewall status, security event log analysis, password policy, registry checks, USB history). Non-admin runs degrade gracefully with warnings.

---

## Step-by-Step Guide to Run SentinelAudit

Follow these step-by-step instructions to set up and execute SentinelAudit on your Windows system:

### Step 1: Launch Terminal as Administrator
For complete security auditing capabilities, open **PowerShell** or **Command Prompt** with administrative privileges:
1. Press `Win + S` and search for **PowerShell** (or **Command Prompt**).
2. Right-click and select **Run as administrator**.

---

### Step 2: Navigate to Project Directory
Change directory to where `SentinelAudit` is located:
```powershell
cd path\to\SentinelAudit
```

---

### Step 3: Set Up Python Virtual Environment (Optional, Recommended)
Creating an isolated virtual environment ensures clean dependency management, but **you can skip this step** if you prefer installing dependencies directly into your global Python setup:

```powershell
# 1. Create a virtual environment named 'venv'
python -m venv venv

# 2. Activate the virtual environment

# For PowerShell:
.\venv\Scripts\Activate.ps1

# Note: If PowerShell displays a script execution policy error, run:
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process

# For Command Prompt (CMD):
.\venv\Scripts\activate.bat
```

---

### Step 4: Install Required Dependencies
Upgrade `pip` and install all project dependencies from `requirements.txt`:

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

### Step 5: Run the Audit Tool

Choose the execution mode according to your needs:

#### Option A: Full Audit (Default)
Runs all 13 security audit modules and renders an interactive CLI dashboard in your terminal:
```powershell
python main.py
```

#### Option B: Quick Audit
Skips slower modules (event logs, installed software, scheduled tasks, Windows updates) for fast results:
```powershell
python main.py --quick
```

#### Option C: Full Audit with Report Exports (PDF, HTML, JSON)
Runs a full audit and exports formal reports to the `reports/` folder:
```powershell
python main.py --export pdf,html,json
```

#### Option D: Compare with Previous Run
Compares findings and score against the most recent run stored in the history database:
```powershell
python main.py --compare-last
```

#### Option E: List Run History
Displays all past audit runs saved in the SQLite history database:
```powershell
python main.py --list-history
```

#### Additional Flags
- `--no-admin-check`: Bypasses administrative privilege check prompt (useful for non-interactive/scripted execution).
- `--no-save`: Runs the audit without saving results into `database/history.db`.

---

### Step 6: Inspect Output & Generated Reports

Upon completion, output files and logs can be reviewed:
- **CLI Dashboard**: Renders directly in the terminal window.
- **PDF Report**: `reports/audit.pdf` (Multi-page executive summary & findings breakdown).
- **HTML Report**: `reports/audit.html` (Self-contained, interactive HTML document).
- **JSON Report**: `reports/audit.json` (Structured JSON output for programmatic ingestion).
- **History Database**: `database/history.db` (SQLite storage for tracking security posture changes over time).
- **Application Logs**: `logs/sentinelaudit.log` (Detailed execution trace).

---

## Exit Codes

SentinelAudit returns standard status codes suitable for CI/CD and scripting:
- `0`: Score ≥ 75 (**Excellent** / **Good**)
- `1`: Score 50–74 (**Fair**)
- `2`: Score < 50 (**Poor**)

---

## How to Test the Tool

You can test SentinelAudit using the following test verification scenarios:

### 1. Fast Functional Test (Quick Mode)
Verify that imports, CLI styling, scoring engine, and light modules run cleanly without errors:
```powershell
python main.py --quick
```
*Expected Result*: Completes in 2–5 seconds with a rendered CLI dashboard showing module status and security score.

### 2. Full Audit & Report Generation Test
Test all 13 audit modules and export reports:
```powershell
python main.py --export pdf,html,json
```
*Expected Result*:
- `reports/audit.pdf` is created.
- `reports/audit.html` is created.
- `reports/audit.json` is created with valid JSON structure.

### 3. Graceful Non-Admin Test
Test how the tool handles running without elevated administrator rights:
```powershell
python main.py --no-admin-check
```
*Expected Result*: System outputs warning regarding non-admin privileges, and modules degrade gracefully without crashing.

### 4. History Tracking & Diff Test
Run two audits back-to-back and compare findings:
```powershell
# View saved history
python main.py --list-history

# Compare latest run against previous run
python main.py --compare-last
```
*Expected Result*: Displays run IDs, timestamps, and a comparison table showing score delta and new/resolved security findings.

### 5. Scripting Exit Code Test
Test the exit status return code in PowerShell:
```powershell
python main.py --quick
echo $LASTEXITCODE
```
*Expected Result*: Prints `0`, `1`, or `2` depending on the system security score band.

---

## Audit Modules Breakdown

| Module | Source / Mechanism | Description & Triggers |
|---|---|---|
| `firewall` | `netsh advfirewall` | Detects disabled profiles (Domain, Private, Public) |
| `defender` | `Get-MpComputerStatus` | Real-time protection/AV off, tamper protection off, outdated signatures |
| `services` | `psutil.win_service_iter()` | Checks for unencrypted or insecure services (Telnet, FTP, WinRM...) |
| `ports` | `psutil.net_connections()` | Inspects listening ports for vulnerable services (Telnet, FTP, RDP, SMB...) |
| `users` | `Get-LocalUser`, `Get-LocalGroupMember` | Identifies active Guest accounts, extra admin accounts, non-expiring passwords |
| `password_policy` | `net accounts` | Checks minimum password length < 8, lockout policy, never-expiring passwords |
| `startup` | Run/RunOnce keys, Startup folders | Identifies auto-start items outside trusted system folders |
| `software` | Uninstall registry keys | Detects missing publisher metadata or legacy installed software |
| `usb` | `USBSTOR` registry | Audits historical USB storage device usage |
| `registry` | Security registry keys | Flags SMBv1 enabled, RDP without NLA, AutoRun active, Remote Registry |
| `updates` | `Get-HotFix` | Flags system updates older than 30 days |
| `eventlogs` | `Get-WinEvent` | Detects failed logon spikes (brute force), account lockouts, Defender alerts |
| `tasks` | `schtasks /query /v` | Reviews scheduled tasks executing outside trusted directories |

> **Customization**: Thresholds, scoring weights, port severities, and risky services can be configured in **`config.yaml`**.

---

## Scoring System

- **Base Score**: 100
- Each finding reduces the score based on its severity and module weight configured in `config.yaml`.
- Final score is clamped to `0–100`.
- **Score Bands**:
  - **90+**: Excellent
  - **75–89**: Good
  - **50–74**: Fair
  - **< 50**: Poor

---

## Project Structure

```
SentinelAudit/
├── main.py               # CLI entry point & orchestrator
├── config.yaml           # Security thresholds, weights, and paths
├── prompt.md             # Development specification prompt
├── requirements.txt      # Python dependencies
├── audit/                # 13 security audit modules
├── utils/                # Helper utilities (config, CLI display, history, scoring)
├── report/               # Report generators (PDF, HTML, JSON)
├── database/             # SQLite run history storage (history.db)
├── reports/              # Generated audit reports (pdf, html, json)
└── logs/                 # Execution log output
```

