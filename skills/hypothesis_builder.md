# MORDOR Skill: Hypothesis Builder

Phase 3 of the MORDOR pipeline. Transform raw Phase 2 filtered signals into structured, testable hypotheses organized by adversary behavior category. Each hypothesis must be falsifiable — "if this is C2, we expect to see X in the call graph."

## Categories

Map every signal to exactly one of these five categories:

### Persistence
Mechanisms that survive reboot.
- **Registry Run Keys**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- **Services**: `CreateService`, `OpenSCManager`
- **Scheduled Tasks**: `schtasks`, `ITaskScheduler`
- **Startup Folders**: `SHGetSpecialFolderPath(CSIDL_STARTUP)`
- **DLL Sideloading**: Missing DLL in app directory
- **WMI Event Subscription**: `__EventFilter`, `__FilterToConsumerBinding`

Signal pattern: `RegSetValue` + file write to `AppData` or `System32`.

### C2 (Command & Control)
Network communication for tasking and data retrieval.
- **HTTP/S**: `WinHttpOpen`, `HttpSendRequest`, `InternetOpen`
- **DNS Tunneling**: Unusual subdomain entropy, `nslookup` abuse
- **ICMP**: Raw socket ICMP echo packets
- **WebSocket**: `WSASocket` + `connect` to non-standard ports
- **Domain Generation Algorithms (DGA)**: High entropy domain strings, TLD rotation

Signal pattern: `socket` + `connect` + `send`/`recv` + encrypted payload buffers.

### Injection
Code execution in foreign processes.
- **Classic**: `CreateRemoteThread` + `VirtualAllocEx` + `WriteProcessMemory`
- **APC**: `QueueUserAPC` + `NtTestAlert`
- **Process Hollowing**: `CreateProcess` (suspended) + `NtUnmapViewOfSection` + `SetThreadContext` + `ResumeThread`
- **Reflective DLL**: No `LoadLibrary` — manual PE mapping
- **Atom Bombing**: `GlobalAddAtom` + `NtQueueApcThread`

Signal pattern: At least 3 of the 4 classic injection APIs imported together.

### Collection
Gathering data from the host.
- **Keylogging**: `SetWindowsHookEx(WH_KEYBOARD)`, `GetAsyncKeyState`
- **Screen Capture**: `CreateDC("DISPLAY")`, `BitBlt`, `OpenClipboard`
- **Credential Theft**: `SECUR32!LsaEnumerateLogonSessions`, `vaultcli!VaultEnumerateVaults`
- **File Harvesting**: `FindFirstFile` + `FindNextFile` on documents folders
- **Browser Data**: SQLite reads of `Login Data`, `Cookies`, `History`

Signal pattern: GUI/collection imports + file enumeration + `send` over established socket.

### Exfiltration
Data leaving the network boundary.
- **FTP/S**: `FtpPutFile`, `WinINet` upload
- **HTTP POST**: `HttpSendRequest` with large bodies
- **SMTP**: `WSAStartup` + `send` on port 25/587
- **Cloud API**: `HTTP` POST to `https://api.github.com`, `https://content.dropboxapi.com`
- **DNS Exfiltration**: Subdomain-encoded data in DNS queries

## Linking to MITRE ATT&CK

For each signal, record the MITRE technique ID and name.

| Category | Common MITRE IDs |
|----------|------------------|
| Persistence | T1547.001 (Run Key), T1543.003 (Service), T1053.005 (Scheduled Task) |
| C2 | T1071.001 (Web), T1573 (Encrypted), T1568 (DGA) |
| Injection | T1055.012 (Process Hollowing), T1055.001 (DLL), T1055.004 (APC) |
| Collection | T1056.001 (Keylog), T1113 (Screen Capture), T1005 (Local Data) |
| Exfiltration | T1041 (C2 Channel), T1048 (Alternative Protocol), T1567 (Web Service) |

Record format in `hypotheses.md`:

```markdown
## C2-001: HTTP Beaconing

**Signal**: WinHttpOpen + WinHttpConnect + WinHttpSendRequest
**MITRE**: T1071.001
**Confidence**: SUSPICIOUS (72%)
**Rationale**: 3 of 5 HTTP APIs present. No URL strings in sample — 
  suggests runtime construction or DGA.
**Falsifiable**: Call graph must show data flow from crypto
  constants to HTTP send buffer.
```

## Confidence Scoring (BOROMIR)

Score every hypothesis on 0–100% based on signal strength:

| Range | Label | Criteria |
|-------|-------|----------|
| >85% | CRITICAL | 3+ corroborating signals, known-bad ARAGORN hit, MITRE TID confirmed by LEGOLAS + ELROND |
| 50–85% | SUSPICIOUS | 2 corroborating signals or 1 strong signal with plausible alternative explanation |
| <50% | INFO | Single weak signal, no XREF, benign explanation likely |

Scoring rules:
- **+25%** per additional corroborating import
- **−20%** if no XREF connects the import to a code path
- **+15%** if ARAGORN reports known-bad association
- **−30%** if GOLLUM provides a convincing benign alternative

## Writing Rules

1. Every hypothesis must contain a **falsifiable statement** — something Phase 4 or 6 could disprove
2. Every hypothesis must have a **confidence score** with rationale
3. Group hypotheses by category with letter prefixes: `PERS-001`, `C2-001`, `INJ-001`, `COL-001`, `EXF-001`
4. Before writing, re-read `filtered_signals.json` and confirm no signal is double-counted
