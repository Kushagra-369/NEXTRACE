# NEXTRACE

**Automated Network Reconnaissance & Security Analysis Tool**

NEXTRACE is a Python-based network reconnaissance tool powered by Nmap. It automates host discovery, port scanning, service enumeration, security finding classification, scan history tracking, and report generation.

## Features

- **Target Validation:** Validates IP addresses and hostnames before scanning.
- **Host Discovery:** Detects host availability using Nmap.
- **Port Scanning:** Scans selected ports and port ranges.
- **Service Enumeration:** Identifies services, products, versions, and available metadata.
- **Security Findings:** Applies rule-based classification to observed services.
- **Multiple Exports:** Generates JSON and CSV scan results.
- **Markdown Reports:** Creates readable reconnaissance reports.
- **Scan History:** Saves scan snapshots for future reference.
- **Change Detection:** Compares scans to identify newly opened ports, closed ports, service changes, and ports no longer observed.
- **System Diagnostics:** Checks Python, Nmap, project directories, and package availability.

## Technology Stack

- Python 3.10+
- Nmap 7.99 (or compatible installed version)
- XML parsing with Python standard library
- JSON and CSV
- Markdown
- unittest
- setuptools

## Project Structure

```text
NEXTRACE/
├── src/
│   └── nextrace/
│       ├── __init__.py
│       ├── main.py
│       ├── entry.py
│       ├── cli.py
│       ├── discovery.py
│       ├── scanner.py
│       ├── exporter.py
│       ├── reporter.py
│       ├── findings.py
│       ├── history.py
│       └── doctor.py
├── tests/
├── output/
├── reports/
├── history/
├── README.md
├── LICENSE
├── Makefile
├── pyproject.toml
└── requirements.txt
```

## Requirements

- Linux or another supported Python environment
- Python 3.10 or newer
- Nmap installed and available in PATH
- Permission to assess the target system

On Kali Linux:

```bash
sudo apt update
sudo apt install nmap python3-venv
```

## Installation

Clone the repository:

```bash
git clone https://github.com/Kushagra-369/NEXTRACE.git
cd NEXTRACE
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install NEXTRACE:

```bash
python -m pip install -e .
```

## Usage

Display help:

```bash
nextrace --help
```

Check version:

```bash
nextrace --version
```

Run system diagnostics:

```bash
nextrace doctor
```

View saved scan history:

```bash
nextrace history
```

Scan an authorized target:

```bash
nextrace scan --target 127.0.0.1 --ports 5432,8000 --authorized
```

Scan a port range:

```bash
nextrace scan --target 127.0.0.1 --ports 1-1000 --authorized
```

The `--authorized` flag is an operator confirmation. It does not independently verify ownership or permission.

## Generated Output

NEXTRACE generates:

| Directory | Contents |
|---|---|
| `output/` | JSON and CSV scan data |
| `reports/` | Markdown scan and comparison reports |
| `history/` | JSON scan snapshots |

Generated files are local and are not automatically uploaded.

## Testing

Run the complete unit test suite:

```bash
python -m unittest discover -s tests -v
```

Run project diagnostics and tests:

```bash
make check
```

Run a local test scan:

```bash
make scan-local
```

## Security Findings

NEXTRACE uses rule-based checks to classify observed services. Findings are informational indicators for further investigation, not proof of exploitability or confirmed vulnerabilities.

A service being open does not automatically mean that the host is vulnerable.

## Limitations

- Service and version detection depends on the information Nmap can identify.
- Filtered ports and network restrictions can limit scan visibility.
- A port missing from a later scan is classified as **no longer observed**, not automatically closed.
- Security classifications are rule-based and require manual validation.
- Scan results represent observations at the time of scanning.

## Responsible Use

Use NEXTRACE only on systems you own or have explicit permission to assess.

Unauthorized scanning may violate laws, policies, or terms of service.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
