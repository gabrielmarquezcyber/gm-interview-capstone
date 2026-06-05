# Playbook: Suspicious PowerShell Flags (EQL)
**Date:** 2025-11-11  
**Owner:** Gabriel Marquez  
**MITRE ATT&CK:** T1059.001 (PowerShell) - Tactic: Execution

## Purpose
Detect potentially obfuscated or headless PowerShell executions commonly used by attackers, including patterns such as EncodedCommand, NoProfile, and -nop. This rule is validated in Elastic and produces alerts with evidence suitable for analyst review.

## Data Sources
- Elastic Defend (endpoint) process telemetry  
- Indices: `logs-*`, `endpoint.events.*`

## Detection (EQL)
```eql
process
  where process.name : ("powershell.exe", "pwsh.exe")
    and (
      process.command_line : "*-enc*" or
      process.command_line : "*-EncodedCommand*" or
      process.command_line : "*-NoProfile*" or
      process.command_line : "*-nop*"
    )
```

## Rule Configuration (Elastic)
- **Type:** EQL - Event category: `process`
- **Index patterns:** `logs-*`, `endpoint.events.*`
- **Schedule:** Every 5 minutes
- **Additional look-back:** 1 minute
- **Severity:** High
- **Risk score:** 75
- **Tags (optional):** `["MITRE:T1059.001","PowerShell","Execution"]`

## Validation Steps (What was done)
1. Verified incoming telemetry in *Discover* (`process.name:"powershell.exe"` and `process.command_line:*EncodedCommand*`).
2. Manually triggered test events:
   - `powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAB0AGUAcwB0AA==`
   - `powershell.exe -NoProfile -nop -Command "Write-Output test"`
3. Confirmed alerts in *Security > Alerts* filtering on `kibana.alert.rule.name: "Suspicious PowerShell Flags (EQL)"`.

## Evidence (Artifacts)
- `12_rule_manual_run.png` - Manual run succeeded for the rule
- `13_agent_reenrolled_healthy.png` - Agent healthy after re-enroll
- `14_discover_verified_powershell.png` - Telemetry shows PowerShell process events
- `15_discover_cmdline_flags.png` - Command-line flags present
- `16_rule_manual_run_success.png` - Preview shows matches (or successful execution)
- `17_alerts_list_powershell_eql.png` - Alert list with hits
- `18_alert_details_powershell_eql.png` - Alert details include command line

## Response
- Triage the command, parent/child chain, and user/session context.
- Contain host if malicious intent is confirmed (disable network, isolate in EDR).
- Hunt for similar executions over the last 24-72 hours; pivot on user, host, and `process.parent.*` fields.

## Reporting
- Record the incident summary (time, user, host, command line, outcome).
- Map to **MITRE T1059.001** in the incident write-up and detection documentation and MITRE ATT&CK framework alignment.

## Notes
- Use `kibana.alert.rule.name` (not `rule.name`) for filtering in Alerts in Elastic 8/9.x.
