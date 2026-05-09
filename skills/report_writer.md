# MORDOR Skill: Report Writer (GANDALF WHITE)

Phase 6 completion — synthesize all findings into a final intelligence report, extract IOCs in standard formats, and package evidence for downstream consumption. This is the output that analysts, SOC teams, and threat intel platforms consume.

## Report Structure

### Header

```
MORDOR Final Report
Sample: {sha256}
File: {filename}
Size: {size} bytes
Type: {filetype}
Compiler: {compiler_timestamp}
Source: {submission_source}
Analysis Date: {YYYY-MM-DD}
Pipeline Version: MORDOR 1.0
```

### Executive Summary (1 paragraph)

One paragraph answering: what is this sample, what does it do, and how urgent is it?

```
The sample is a packed x86 Windows PE that functions as an 
information stealer with C2 capability. It achieves persistence 
via registry run key, collects browser credentials and crypto 
wallet files, and exfiltrates via HTTPS POST to hardcoded 
domains. Confidence: CRITICAL (92%).
```

### Triage Overview

| Dimension | Value |
|-----------|-------|
| Overall Confidence | CRITICAL (92%) |
| Malware Family | `RedLine Stealer` (ARAGORN: 4/62 AV detections) |
| Packer | UPX 3.96 (entropy 7.1 → unpacked entropy 5.8) |
| Architecture | x86, PE32 |
| Key MITRE IDs | T1055.012, T1071.001, T1056.001, T1113, T1547.001 |

### Key Findings

For each CRITICAL hypothesis, a structured finding:

```markdown
### C2-001: HTTPS Beaconing (CRITICAL — 92%)

**Offsets**: 0x401200 (beacon_main), 0x401400 (encrypt_payload)
**APIs**: WinHttpOpen, WinHttpConnect, WinHttpOpenRequest, WinHttpSendRequest
**MITRE**: T1071.001 (Web Protocols)

**Behavior**:
- Collects system fingerprint (hostname, username, volume serial)
- Encrypts fingerprint with XOR key 0xAB
- Sends encrypted blob via HTTPS POST to /api/collect
- C2 domains: uodate-check[.]com, cdn-service[.]net
- Receives next-stage command in HTTP response body

**Evidence**:
- Decrypted C2 strings in `crypto_indicators.txt`
- Call graph confirms data flow: collect → encrypt → send
- Frida hook confirmed WinHttpSendRequest called with encrypted payload
```

### Findings Summary Table

| ID | Category | Confidence | MITRE | Status |
|----|----------|------------|-------|--------|
| C2-001 | C2 | 92% CRITICAL | T1071.001 | Confirmed |
| PERS-001 | Persistence | 88% CRITICAL | T1547.001 | Confirmed |
| INJ-001 | Injection | 67% SUSPICIOUS | T1055.012 | Human review |
| COL-001 | Collection | 91% CRITICAL | T1056.001 | Confirmed |
| EXF-001 | Exfiltration | 75% SUSPICIOUS | T1041 | Human review |

### Anti-False-Positive Summary

| Flag | GOLLUM Verdict | Adjustment | Final |
|------|----------------|------------|-------|
| INJ-001 | Signed vendor, but unsigned child process | −15 | SUSPICIOUS |
| C2-001 | No benign alternative for DGA-like domains | +10 | CRITICAL |

### IOCs

Organize by type:

```
=== Domains ===
uodate-check[.]com
cdn-service[.]net

=== IPs (resolved) ===
198.51.100.23:443
203.0.113.45:443

=== Registry ===
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdateSvc

=== Files ===
%APPDATA%\updater.exe
%TEMP%\mscorsvc.dll

=== YARA ===
redline_stealer_loader (match at 0x401200)
```

## IOC Export Formats

### STIX2

```json
{
  "type": "bundle",
  "id": "bundle--{uuid}",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--{uuid}",
      "pattern": "[domain-name:value = 'uodate-check[.]com']",
      "pattern_type": "stix",
      "valid_from": "2026-05-09T00:00:00Z",
      "score": 92
    }
  ]
}
```

Export to `output/ioc_feeds/stix2_bundle.json`.

### YARA Rule

Minimum 3 conditions per rule:

```yara
rule redline_stealer_loader {
  meta:
    description = "RedLine Stealer loader detected by MORDOR"
    author = "GANDALF WHITE"
    date = "2026-05-09"
    hash = "{sha256}"
    confidence = "critical"
  strings:
    $s1 = "uodate-check" wide ascii
    $s2 = "cdn-service" wide ascii
    $s3 = "WinHttpOpen" wide ascii
    $crypto1 = {AB AB AB AB AB AB AB AB} // XOR key pattern
  condition:
    all of ($s*) and #crypto1 > 3
}
```

Export to `output/ioc_feeds/redline_stealer.yar`.

### Sigma Rule

```yaml
title: RedLine Stealer Registry Persistence
id: {uuid}
status: experimental
description: Detects RedLine Stealer registry run key persistence
references:
  - https://github.com/daemon-blockint-tech/MORDOR
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    TargetObject|contains: '\Microsoft\Windows\CurrentVersion\Run\UpdateSvc'
  condition: selection
falsepositives:
  - Legitimate software updaters
level: high
```

Export to `output/ioc_feeds/sigma_persistence.yml`.

## Evidence Packaging

For each CRITICAL finding, provide:

1. **Decompiled function** — the relevant Ghidra/radare2 output
2. **Call graph subgraph** — DOT snippet or SVG rendering
3. **Data flow trace** — input → transformation → output chain
4. **Frida/runtime confirmation** — hook output showing runtime behavior
5. **PCAP extract** — relevant network capture (if PIPPIN captured)

Package structure:

```
output/reports/{sha256}/
├── final_report.md
├── evidence/
│   ├── C2-001_decompiled.txt
│   ├── C2-001_callgraph.svg
│   ├── C2-001_dataflow.md
│   └── C2-001_hook.log
├── ioc_feeds/
│   ├── stix2_bundle.json
│   ├── redline_stealer.yar
│   └── sigma_persistence.yml
└── dashboards/
    └── summary.html
```

## Final Quality Checks

- [ ] Executive summary answers "what, how, how urgent"
- [ ] Every CRITICAL finding has evidence artifacts
- [ ] Every CRITICAL finding has a GOLLUM anti-FP review
- [ ] Every CRITICAL finding has BOTH Ghidra and radare2 confirmation
- [ ] IOCs are deduplicated and validated
- [ ] STIX2 bundle is valid JSON
- [ ] YARA rules have ≥ 3 conditions
- [ ] Contact/attribution section included if relevant
- [ ] Report is written for both technical and non-technical readers
