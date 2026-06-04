# Elastic SIEM Detection Engineering and Vulnerability Risk Automation

This repository contains a cybersecurity portfolio project focused on detection engineering, SIEM validation, analyst playbooks, and vulnerability risk prioritization.

The project has two main parts:

1. Elastic Security detection engineering for Windows-based activity.
2. Python-based CVE prioritization using EPSS, CISA KEV, and NVD CVSS data.

The goal is to show a repeatable security operations workflow:

```text
security signal
-> detection rule
-> validation evidence
-> analyst playbook
-> prioritization output
-> documented security interpretation
```

## Project Scope

This project demonstrates:

- Elastic SIEM detection rule creation and validation.
- Detection logic mapped to MITRE ATT&CK.
- Analyst-facing playbooks for alert triage.
- Evidence capture from Elastic Security and related telemetry views.
- Python automation for vulnerability prioritization.
- Risk scoring using exploit probability, known exploitation, and CVSS severity.
- Visual reporting for vulnerability prioritization.

## Repository Structure

```text
repo-root/
├─ README.md
├─ artifacts/
│  ├─ playbooks/
│  │  ├─ powershell_flags_eql.md
│  │  └─ failed_logon_burst_4625.md
│  ├─ screenshots/
│  ├─ docs/
│  └─ figures/
├─ artifacts/scripts/
│  ├─ cve_prioritizer.py
│  └─ README.md
├─ artifacts/elastic/rules/
│  ├─ powershell_eql_rule_export.ndjson
│  ├─ failed_logon_4625_rule_export.ndjson
│  └─ README.md
└─ LICENSE
```

## Environment and Tools

| Area | Tools / Data |
|---|---|
| SIEM | Elastic Security |
| Endpoint / log data | Windows and System integrations |
| Detection content | Elastic rules exported as NDJSON |
| Detection validation | Elastic Discover, Security alerts, and screenshots |
| Automation | Python 3.11+ |
| Python libraries | `requests`, `pandas`, `matplotlib`, `python-dotenv` |
| Vulnerability intelligence | EPSS, CISA KEV, NVD CVSS |

## Detection Engineering Work

### Detection 1: Suspicious PowerShell Flags

| Field | Detail |
|---|---|
| Detection | Suspicious PowerShell Flags |
| MITRE ATT&CK | T1059.001 - PowerShell |
| Signal | PowerShell processes using suspicious flags such as `-enc`, `-nop`, `-NoProfile`, or `-w hidden` |
| Risk | These flags are commonly associated with encoded commands, reduced logging visibility, script obfuscation, and living-off-the-land execution patterns |
| Rule export | `artifacts/elastic/rules/powershell_eql_rule_export.ndjson` |
| Playbook | `artifacts/playbooks/powershell_flags_eql.md` |
| Evidence | `artifacts/screenshots/` |

Security interpretation:

Suspicious PowerShell flag usage does not automatically prove compromise. It is a detection signal that should trigger triage. The analyst should review process ancestry, command line arguments, user context, host context, and surrounding endpoint activity before escalating.

### Detection 2: Failed Logon Burst

| Field | Detail |
|---|---|
| Detection | Failed Logon Burst |
| Event ID | Windows Security Event ID 4625 |
| MITRE ATT&CK | T1110 - Brute Force |
| Signal | Multiple failed logon attempts within a short time window |
| Risk | May indicate password spraying, brute-force attempts, misconfigured services, stale credentials, or unauthorized access attempts |
| Rule export | `artifacts/elastic/rules/failed_logon_4625_rule_export.ndjson` |
| Playbook | `artifacts/playbooks/failed_logon_burst_4625.md` |
| Evidence | `artifacts/screenshots/` |

Security interpretation:

A burst of failed logons requires context. The analyst should review source host, target account, logon type, time window, failure reason, account criticality, and whether successful authentication followed the failures.

## Analyst Playbooks

The playbooks are written for alert triage and explain:

- Detection purpose.
- Relevant data sources.
- Triage questions.
- Fields to review.
- False-positive considerations.
- Escalation indicators.
- Analyst response guidance.

Playbooks:

```text
artifacts/playbooks/powershell_flags_eql.md
artifacts/playbooks/failed_logon_burst_4625.md
```

These playbooks are intended to connect detection logic with analyst decision-making.

## Elastic Rule Exports

Detection rules are exported as NDJSON for reproducibility.

Rule exports:

```text
artifacts/elastic/rules/powershell_eql_rule_export.ndjson
artifacts/elastic/rules/failed_logon_4625_rule_export.ndjson
```

These files can be imported into Elastic Security through:

```text
Kibana -> Security -> Rules -> Manage rules -> Import
```

After import, rule behavior should be validated against the expected data streams and alert evidence.

## Reproducing the Elastic Detection Workflow

### 1. Import the detection rules

Import the `.ndjson` rule files from:

```text
artifacts/elastic/rules/
```

### 2. Confirm required integrations and data streams

Validate that the expected Windows and System integrations are active.

Relevant data streams may include:

```text
windows.powershell
windows.powershell_operational
system.security
```

### 3. Generate or locate matching telemetry

For Suspicious PowerShell Flags:

```text
Run PowerShell with suspicious command-line flags in a controlled lab environment.
```

For Failed Logon Burst:

```text
Generate repeated failed authentication attempts in a controlled lab environment.
```

### 4. Confirm detection behavior

Review:

```text
Elastic Discover
Security -> Alerts
Rule details
Event fields
Related process or authentication context
```

### 5. Capture evidence

Screenshots and validation artifacts are stored in:

```text
artifacts/screenshots/
```

## Vulnerability Risk Prioritization Engine

The repository includes a Python script for ranking CVEs using public vulnerability intelligence.

Script:

```text
artifacts/scripts/cve_prioritizer.py
```

Purpose:

```text
Merge EPSS, CISA KEV, and NVD CVSS into a practical prioritization model for vulnerability management.
```

Outputs:

```text
artifacts/figures/priority.csv
artifacts/figures/priority_chart.png
```

## Prioritization Model

The prioritization model uses three inputs:

| Input | Meaning |
|---|---|
| CISA KEV | Whether the vulnerability is known to be exploited in the wild |
| EPSS | Probability of exploitation |
| CVSS | Severity score from NVD data |

Scoring model:

```python
df["Priority"] = (df["KEV"] * 40) + (df["EPSS"] * 50) + (df["CVSS"] * 10)
```

Design rationale:

- KEV increases priority because known exploitation changes remediation urgency.
- EPSS adds probability-based exploit likelihood.
- CVSS preserves severity context.
- The combined score supports ranked remediation decisions rather than relying on severity alone.

The model is intentionally simple and explainable. It is not a replacement for business context, asset criticality, exposure, compensating controls, or service ownership.

## Running the CVE Prioritization Script

From the repository:

```powershell
cd artifacts\scripts
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install requests pandas matplotlib python-dotenv
python .\cve_prioritizer.py
```

Outputs are written to:

```text
artifacts\figures\
```

## Environment Variables

Create a `.env` file at the repository root for local use:

```bash
NVD_API_KEY=your-api-key-here
```

`.env` should not be committed.

A safe `.env.example` file may be included with placeholder values only.

## Evidence and Reporting Artifacts

This repository includes several types of evidence:

| Artifact Type | Purpose |
|---|---|
| Detection rule exports | Allow reproducible Elastic rule import |
| Playbooks | Explain analyst triage workflow |
| Screenshots | Provide validation evidence |
| CVE prioritization script | Automates vulnerability ranking |
| Ranked CSV output | Shows prioritized vulnerability results |
| Priority chart | Visualizes prioritization output |
| Documentation | Explains methodology, assumptions, and limitations |

## What This Project Demonstrates

This project demonstrates practical ability to:

- Build and validate SIEM detections.
- Map detection logic to MITRE ATT&CK techniques.
- Export and document Elastic Security rules.
- Write analyst-facing playbooks.
- Capture evidence that supports detection validation.
- Automate vulnerability prioritization with Python.
- Combine exploit likelihood, known exploitation, and severity into a ranked output.
- Communicate security findings in a way that supports analyst workflows.

## Limitations

This project is a controlled portfolio lab.

It does not claim to represent a production SOC environment.

Limitations include:

- Detection examples are limited to the available lab telemetry.
- Rule performance was validated in a controlled environment.
- CVE prioritization does not include asset criticality, internet exposure, compensating controls, business ownership, or exploit-chain context.
- The prioritization model is explainable but intentionally simple.
- Screenshots and outputs are evidence artifacts, not proof of full enterprise coverage.

## Security Operations Value

The project connects three practical security operations skills:

```text
Detection engineering
+ analyst triage
+ vulnerability prioritization
```

This matters because security teams need more than alerts. They need validated detections, clear triage steps, and ranked remediation priorities.

## License

This project is released under the MIT License.

## Author

Gabriel Marquez

GitHub:

```text
https://github.com/gabrielmarquezcyber
```

LinkedIn:

```text
https://linkedin.com/in/gabrielmarquezcyber
```


