# NessusParser Pro

NessusParser Pro is an advanced `.nessus` report parser that generates a multi-layer Excel report designed for vulnerability assessment, triage, and remediation workflows.

The project produces two reporting layers:

- **Executive layer**: KPI overview, narrative summary, risk matrix, and charts.
- **Operational layer**: priority queue, remediation plan, and quick wins.

It also supports optional **EPSS** and **CISA KEV** enrichment to help prioritize vulnerabilities more intelligently.

## Features

- Parse one or more `.nessus` or `.xml` files
- Supports:
  - single files
  - directories
  - glob patterns
- Generate `.xlsx` Excel reports
- Executive dashboard with key indicators
- Host-based risk matrix
- Priority scoring based on:
  - CVSS
  - exploit availability
  - exploited by malware
  - vulnerability age
  - EPSS
  - CISA KEV
- Remediation grouping by solution
- Quick wins identification
- Minimum severity filtering
- Exclusion of specific plugin IDs
- Verbose mode for debugging

## Report Output

The generated Excel file includes sheets such as:

- `Executive Summary`
- `Charts`
- `Risk Matrix`
- `Threat Intelligence` (only with `--enrich`, when available)
- `Priority Queue`
- `Remediation Plan`
- `Quick Wins`
- `Full Report`
- severity-based sheets
- CVSS overview sheets
- device type and Microsoft process details
- plugin counters

## Requirements

- Python **3.8+** recommended
- Python dependencies:
  - `lxml`
  - `XlsxWriter`

## Installation

Clone the repository:

```bash
git clone https://github.com/your-username/nessusparser-pro.git
cd nessusparser-pro
```

Create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

### Quick examples

```bash
python nessusparser_pro.py -i scan1.nessus scan2.nessus -o report
python nessusparser_pro.py -i ./scans/ -o report
python nessusparser_pro.py -i "./scans/*.nessus" -o report
python nessusparser_pro.py -i ./scans/ -o report --enrich
python nessusparser_pro.py -i ./scans/ -o report --enrich --exclude-ids 12345,67890
```

### Available options

```bash
python nessusparser_pro.py -h
```

Main parameters:

- `-i, --input` → `.nessus` file, directory, or glob pattern
- `-o, --output` → output filename without the `.xlsx` extension
- `--enrich` → enrich CVEs with EPSS and CISA KEV data (requires internet access)
- `--exclude-ids` → comma-separated list of Plugin IDs to exclude
- `--exclude-ids-file` → file containing one Plugin ID per line to exclude
- `--min-severity` → minimum severity to include (`0-4`)
- `-v, --verbose` → enable detailed logging

## Practical examples

### Analyze a scan folder

```bash
python nessusparser_pro.py -i ./scans/ -o vulnerability_report
```

### Generate a report for Medium and above only

```bash
python nessusparser_pro.py -i ./scans/ -o vulnerability_report --min-severity 2
```

### Enrich results with external intelligence

```bash
python nessusparser_pro.py -i ./scans/ -o vulnerability_report --enrich
```

### Exclude noisy or irrelevant plugins

```bash
python nessusparser_pro.py -i ./scans/ -o vulnerability_report --exclude-ids 19506,11219
```

## Prioritization Logic

The priority score is calculated by combining:

- CVSS base score
- exploit availability
- malware exploitation
- vulnerability age
- EPSS score
- presence in the CISA KEV catalog

This helps prioritize vulnerabilities based not only on theoretical severity, but also on real-world likelihood of exploitation.

## Project Structure

```text
.
├── nessusparser_pro.py
├── requirements.txt
├── README.md
└── LICENSE
```

## Notes

- Enrichment with `--enrich` uses external sources and requires internet connectivity.
- If the output file already exists, the tool automatically saves a new timestamped version.
- If no `.nessus` or `.xml` files are found, the program exits with an error.

## Possible Future Improvements

- CSV/JSON export
- packaging as a `pip`-installable tool
- automated tests
- Docker support
- GitHub Actions CI/CD

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
