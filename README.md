# Detection-as-Code

A version-controlled library of [Sigma](https://github.com/SigmaHQ/sigma) detection rules, mapped to MITRE ATT&CK, with automated validation and multi-backend compilation. Detections are authored once in a vendor-neutral format and compiled to multiple SIEM query languages on every change. Nothing reaches 'main' without passing CI.

## Why it exists

Detections are treated like software: they live in version control, are reviewed via pull request, validated automatically, and compiled to the target platform as a build step. Authoring a rule once and compiling it to multiple backends decoouples logic from any single vendor, so the library survives a SIEM migration or a multi-SIEM environment.

## What's inside

- **Source format:** Sigma (YAML), the vendor-neutral detection standard
- **Targets:** Microsoft Sentinel / Defender XDR (KQL) and Splunk (SPL)
- **CI:** GitHub Actions on every push and pull request
- **Validation:** `sigma check` (structure + best practices) plus a pytest suite (metadata governance + conversion regression)

## ATT&CK coverage

| Rule | Technique | Tactic | Severity |
|------|-----------|--------|----------|
| Shadow Copy and Backup Deletion | [T1490](https://attack.mitre.org/techniques/T1490/) — Inhibit System Recovery | Impact | High |
| LSASS Memory Dumping via Common Tooling | [T1003.001](https://attack.mitre.org/techniques/T1003/001) - OS Credential Dumping: LSASS Memory | Credential Access | High |

## Repository structure

```
rules/                  # Sigma rules, organized by platform + log source
  windows/
    process_creation/
tests/                  # pytest validation suite
  test_rules_valid.py   # enforces required metadata + ATT&CK tagging
  test_conversions.py   # asserts each rule compiles to all backends
.github/workflows/      # CI pipeline
requirements.txt
```

## Usage

Install the toolchain:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Compile a rule to a backend:

```bash
# Microsoft Sentinel / Defender XDR (KQL)
sigma convert -t kusto -p microsoft_xdr rules/windows/process_creation/proc_creation_win_vss_shadow_copy_deletion.yml

# Splunk (SPL)
sigma convert -t splunk -p sysmon rules/windows/process_creation/proc_creation_win_vss_shadow_copy_deletion.yml
```

Validate locally before committing:

```bash
sigma check rules/
pytest -q
```

## Quality gates

Every change runs through two independent CI gates:

1. **Governance** — every rule must carry a title, UUID, severity, log source, and a valid ATT&CK technique tag.
2. **Compilation** — every rule must compile cleanly to all supported backends, with regression checks on key detection logic.