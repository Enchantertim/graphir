"""Sigma rule generator — typed, validated, not LLM-generated YAML.

Generates vendor-neutral Sigma detection rules from confirmed graph findings.
The MCP tool takes structured parameters (title, logsource, detection fields)
and constructs valid YAML programmatically. The LLM never writes raw YAML.

Output: valid Sigma rules per the SigmaHQ specification, ready to deploy
via pySigma/sigmac to any SIEM (Splunk, Elastic, Sentinel, QRadar, etc.).

Each rule includes:
  - ATT&CK technique mapping (from the finding)
  - Detection logic derived from the graph evidence
  - False positive notes
  - Confidence level from verification
  - Origin trace back to source artifact
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml


# Sigma logsource categories mapped to common Windows event sources
LOGSOURCE_MAP = {
    "process_creation": {
        "category": "process_creation",
        "product": "windows",
    },
    "logon": {
        "service": "security",
        "product": "windows",
    },
    "service_install": {
        "service": "system",
        "product": "windows",
    },
    "registry": {
        "category": "registry_event",
        "product": "windows",
    },
    "network": {
        "category": "network_connection",
        "product": "windows",
    },
    "process_access": {
        "category": "process_access",
        "product": "windows",
    },
    "powershell": {
        "service": "powershell",
        "product": "windows",
    },
    "file": {
        "category": "file_event",
        "product": "windows",
    },
}

# Sigma status levels
SIGMA_LEVELS = {"informational", "low", "medium", "high", "critical"}
SIGMA_STATUSES = {"experimental", "test", "stable"}


def generate_sigma_rule(
    title: str,
    description: str,
    logsource_type: str,
    detection: dict,
    level: str = "medium",
    technique_id: str = "",
    tactic: str = "",
    confidence: str = "",
    false_positives: list[str] | None = None,
    references: list[str] | None = None,
    origin_artifact: str = "",
    finding_id: str = "",
) -> dict:
    """Generate a single Sigma rule as a validated Python dict.

    Args:
        title: Rule title (short, descriptive)
        description: What this rule detects and why
        logsource_type: Key into LOGSOURCE_MAP (process_creation, logon, etc.)
        detection: Dict with 'selection' and optional 'filter' keys.
            selection: dict of field→value(s) to match
            filter: optional dict of field→value(s) to exclude
            condition: optional string (defaults to 'selection' or 'selection and not filter')
        level: Sigma severity (informational/low/medium/high/critical)
        technique_id: MITRE ATT&CK technique (e.g., 'T1059.001')
        tactic: MITRE ATT&CK tactic (e.g., 'execution')
        confidence: graphir confidence level (CONFIRMED/PARTIAL/INFERENCE)
        false_positives: List of known false positive scenarios
        references: List of reference URLs
        origin_artifact: Source artifact this rule was derived from
        finding_id: graphir finding ID for traceability

    Returns:
        Dict with 'rule' (the Sigma rule as dict) and 'yaml' (formatted YAML string)
    """
    # Validate inputs
    level = level.lower() if level.lower() in SIGMA_LEVELS else "medium"
    logsource = LOGSOURCE_MAP.get(logsource_type, {"product": "windows"})

    # Build detection block
    sigma_detection = {}
    if "selection" in detection:
        sigma_detection["selection"] = detection["selection"]
    if "filter" in detection:
        sigma_detection["filter"] = detection["filter"]

    # Build condition
    if "condition" in detection:
        sigma_detection["condition"] = detection["condition"]
    elif "filter" in detection:
        sigma_detection["condition"] = "selection and not filter"
    else:
        sigma_detection["condition"] = "selection"

    # Build tags
    tags = []
    if tactic:
        tags.append(f"attack.{tactic.lower().replace(' ', '_')}")
    if technique_id:
        tags.append(f"attack.{technique_id.lower()}")

    # Build the rule
    rule_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).strftime("%Y/%m/%d")

    rule = {
        "title": title,
        "id": rule_id,
        "status": "experimental",
        "description": description,
        "author": "graphir (autonomous IR agent)",
        "date": now,
        "logsource": logsource,
        "detection": sigma_detection,
        "level": level,
        "tags": tags,
        "falsepositives": false_positives or ["Legitimate administrative activity"],
    }

    if references:
        rule["references"] = references

    # Add graphir-specific metadata as custom fields
    if confidence or finding_id or origin_artifact:
        rule["custom"] = {}
        if confidence:
            rule["custom"]["graphir_confidence"] = confidence
        if finding_id:
            rule["custom"]["graphir_finding_id"] = finding_id
        if origin_artifact:
            rule["custom"]["graphir_origin_artifact"] = origin_artifact

    # Generate YAML
    yaml_str = yaml.dump(rule, default_flow_style=False, sort_keys=False,
                         allow_unicode=True, width=120)

    return {"rule": rule, "yaml": yaml_str, "rule_id": rule_id}


# Known Windows service paths that are NOT suspicious — filter these out
# to avoid generating 800+ rules for standard OS driver installations
_KNOWN_SAFE_SERVICE_PATHS = {
    "\\systemroot\\system32\\drivers\\",
    "\\systemroot\\system32\\svchost.exe",
    "\\systemroot\\system32\\lsass.exe",
    "\\systemroot\\system32\\services.exe",
    "system32\\drivers\\",
    "c:\\windows\\system32\\drivers\\",
    "c:\\windows\\system32\\svchost.exe",
}

# Service names/paths that ARE suspicious even if they look like system paths
# Path indicators that strongly suggest attacker tooling — NOT legitimate software.
# Deliberately excludes \programdata\ (Windows Defender runs from there).
_SUSPICIOUS_SERVICE_INDICATORS = {
    "psexe", "psexec", "cobalt", "beacon", "meterpreter", "payload",
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp",
    "\\public\\", "\\users\\public\\",
    "cmd.exe", "powershell", "rundll32", "regsvr32", "mshta",
    "certutil", "bitsadmin", "wscript", "cscript", "msbuild",
}


def _is_suspicious_service(name: str, path: str) -> bool:
    """Check if a service is worth generating a Sigma rule for.

    Filters out the hundreds of standard Windows services/drivers to produce
    a meaningful, curated rule set. Only flags services that are genuinely
    unusual for a Windows installation.
    """
    name_lower = name.lower()
    path_lower = path.lower().strip('"').strip("'")

    # Always flag if name/path contains suspicious indicators
    for indicator in _SUSPICIOUS_SERVICE_INDICATORS:
        if indicator in name_lower or indicator in path_lower:
            return True

    # Filter out known safe paths (drivers, system services, program files)
    safe_path_prefixes = [
        "\\systemroot\\", "system32\\", "c:\\windows\\",
        "c:\\program files\\", "c:\\program files (x86)\\",
        "c:\\programdata\\microsoft\\",
        "%systemroot%\\", "\"c:\\program files",
        "\"c:\\windows\\", "\"__programfilespath__",
        "__programfilespath__",
    ]
    for prefix in safe_path_prefixes:
        if path_lower.startswith(prefix) or path_lower.startswith('"' + prefix):
            return False

    # svchost-hosted services have DLL paths or -k switches — these are Windows built-in
    if "svchost.exe" in path_lower or "\\system32\\" in path_lower:
        return False

    # Per-user service instances (e.g., CDPUserSvc_184e4649) are standard Windows
    import re
    if re.search(r'_[0-9a-f]{6,}$', name_lower):
        return False

    # Known Windows Defender / security services
    known_safe_names = {
        "windefend", "wdnissvc", "sense", "securityhealthservice",
        "mpssvc", "wscsvc", "wmpnetworksvc", "mdcoresvc",
        "ibm notes diagnostics",  # common enterprise software
    }
    if name_lower in known_safe_names:
        return False

    # If path is empty or name is empty, skip
    if not path or not name:
        return False

    # Flag services with unusual paths (outside Windows/ProgramFiles)
    return True


def generate_rules_from_findings(run_cypher, findings: list[dict]) -> list[dict]:
    """Generate Sigma rules from a list of graphir findings.

    Deduplicates, filters known-good services, and produces a meaningful
    curated set — not one rule per raw finding row.
    """
    rules = []

    for finding in findings:
        hunt = finding.get("hunt", "")
        technique = finding.get("technique", "")
        tactic = finding.get("tactic", "")
        results = finding.get("results", [])

        if not results:
            continue

        if hunt == "suspicious_process_chain":
            # One rule per unique parent→child pair
            seen = set()
            for r in results:
                parent = r.get("ancestor") or r.get("parent", "")
                child = r.get("child", "")
                key = f"{parent}→{child}"
                if key in seen:
                    continue
                seen.add(key)

                rules.append(generate_sigma_rule(
                    title=f"Suspicious Process Chain: {parent} spawned {child}",
                    description=f"Detects {parent} spawning {child}, which may indicate "
                                f"malicious command execution or living-off-the-land techniques.",
                    logsource_type="process_creation",
                    detection={
                        "selection": {
                            "ParentImage|endswith": f"\\{parent}",
                            "Image|endswith": f"\\{child}",
                        },
                    },
                    level="medium",
                    technique_id=technique,
                    tactic=tactic,
                    false_positives=[
                        "Legitimate administrative scripts",
                        f"Scheduled tasks using {child}",
                    ],
                ))

        elif hunt == "lateral_movement_logons":
            # One rule per user (not per session), skip machine accounts
            seen_users = set()
            for r in results:
                user = r.get("user", "")
                if not user or user == "SYSTEM" or user.endswith("$"):
                    continue
                if user in seen_users:
                    continue
                seen_users.add(user)

                host = r.get("host", "")
                sessions = r.get("sessions", 0)

                rules.append(generate_sigma_rule(
                    title=f"Network Logon by {user}",
                    description=f"Detects network logon (Type 3/9/10) by {user}. "
                                f"{sessions} sessions observed to {host}.",
                    logsource_type="logon",
                    detection={
                        "selection": {
                            "EventID": 4624,
                            "LogonType": [3, 9, 10],
                            "TargetUserName": user,
                        },
                    },
                    level="medium",
                    technique_id=technique,
                    tactic=tactic,
                    false_positives=[
                        "Legitimate remote administration",
                        "Service accounts with network logons",
                    ],
                ))

        elif hunt == "service_installation":
            # Filter: only generate rules for SUSPICIOUS services
            # Skip known Windows drivers/services to avoid 800+ noise rules
            suspicious_services = []
            for r in results:
                svc = r.get("service", "")
                path = r.get("path", "")
                if svc and _is_suspicious_service(svc, path):
                    suspicious_services.append(r)

            # Individual rules for suspicious services
            seen = set()
            for r in suspicious_services:
                svc = r.get("service", "")
                if svc in seen:
                    continue
                seen.add(svc)
                path = r.get("path", "")

                rules.append(generate_sigma_rule(
                    title=f"Suspicious Service: {svc}",
                    description=f"Detects installation of service '{svc}' "
                                f"with path '{path}'. Flagged because the service path "
                                f"is not a standard Windows system location.",
                    logsource_type="service_install",
                    detection={
                        "selection": {
                            "EventID": 7045,
                            "ServiceName": svc,
                        },
                    },
                    level="high",
                    technique_id=technique,
                    tactic=tactic,
                    false_positives=[
                        "Legitimate third-party software installation",
                    ],
                ))

            # Also generate a generic "non-standard service path" rule
            if not suspicious_services:
                # No suspicious services found — generate a baseline rule
                rules.append(generate_sigma_rule(
                    title="Service Installation from Non-Standard Path",
                    description="Detects installation of services with executables "
                                "outside standard Windows directories. Common for "
                                "attacker tools (PsExec, Cobalt Strike, etc.).",
                    logsource_type="service_install",
                    detection={
                        "selection": {"EventID": 7045},
                        "filter": {
                            "ImagePath|startswith": [
                                "\\SystemRoot\\System32\\",
                                "C:\\Windows\\System32\\",
                                "C:\\Windows\\SysWOW64\\",
                                "C:\\Program Files\\",
                                "C:\\Program Files (x86)\\",
                            ],
                        },
                        "condition": "selection and not filter",
                    },
                    level="high",
                    technique_id=technique,
                    tactic=tactic,
                    false_positives=[
                        "Legitimate third-party services installed outside Program Files",
                    ],
                ))

        elif hunt == "encoded_commands":
            rules.append(generate_sigma_rule(
                title="Encoded PowerShell Command Execution",
                description="Detects execution of PowerShell with encoded or obfuscated "
                            "command line arguments, commonly used by malware and attack frameworks.",
                logsource_type="process_creation",
                detection={
                    "selection_enc": {
                        "CommandLine|contains": ["-enc ", "-encodedcommand"],
                    },
                    "selection_obf": {
                        "CommandLine|contains": ["-w hidden", "-nop", "frombase64"],
                    },
                    "condition": "selection_enc or selection_obf",
                },
                level="high",
                technique_id="T1027",
                tactic="defense_evasion",
                false_positives=[
                    "Legitimate encoded PowerShell scripts (SCCM, Intune)",
                    "Administrative automation tools",
                ],
            ))

        elif hunt == "discovery_commands":
            tools = [r.get("tool", "") for r in results if r.get("tool")]
            if tools:
                rules.append(generate_sigma_rule(
                    title="Reconnaissance Command Execution",
                    description=f"Detects execution of discovery/reconnaissance tools: "
                                f"{', '.join(sorted(set(tools))[:10])}.",
                    logsource_type="process_creation",
                    detection={
                        "selection": {
                            "Image|endswith": [f"\\{t}" for t in sorted(set(tools))],
                        },
                    },
                    level="low",
                    technique_id=technique,
                    tactic=tactic,
                    false_positives=[
                        "System administrators running network diagnostics",
                        "Monitoring and inventory scripts",
                    ],
                ))

        elif hunt == "lsass_access":
            # One rule per unique accessor
            seen = set()
            for r in results:
                accessor = r.get("accessor", "")
                if not accessor or accessor in seen:
                    continue
                seen.add(accessor)
                rules.append(generate_sigma_rule(
                    title=f"LSASS Memory Access by {accessor}",
                    description=f"Detects {accessor} accessing LSASS process memory "
                                f"(Sysmon Event 10), indicating potential credential dumping.",
                    logsource_type="process_access",
                    detection={
                        "selection": {
                            "TargetImage|endswith": "\\lsass.exe",
                            "SourceImage|endswith": f"\\{accessor}",
                        },
                    },
                    level="critical",
                    technique_id="T1003.001",
                    tactic="credential_access",
                    false_positives=[
                        "Antivirus scanning LSASS",
                        "Windows Defender real-time protection",
                    ],
                ))

    return rules


def write_sigma_rules(rules: list[dict], output_dir: str = "investigation-output/sigma-rules") -> dict:
    """Write Sigma rules to YAML files in the output directory.

    Returns summary of written rules.
    """
    out_path = Path(output_dir)
    # Clean previous rules to prevent stale accumulation
    if out_path.exists():
        for old in out_path.glob("*.yml"):
            old.unlink()
    out_path.mkdir(parents=True, exist_ok=True)

    written = []
    for i, rule_data in enumerate(rules):
        rule = rule_data["rule"]
        yaml_str = rule_data["yaml"]

        # Create filename from title
        safe_title = rule["title"].lower()
        for ch in " :/\\()[]{}":
            safe_title = safe_title.replace(ch, "-")
        safe_title = safe_title[:60].rstrip("-")
        filename = f"{safe_title}.yml"

        filepath = out_path / filename
        with open(filepath, "w") as f:
            f.write(yaml_str)

        written.append({
            "file": str(filepath),
            "title": rule["title"],
            "level": rule["level"],
            "tags": rule.get("tags", []),
        })

    return {
        "rules_written": len(written),
        "output_dir": str(out_path),
        "rules": written,
    }
