# MORDOR Skill: Fingerprinting

Phase 1 of the MORDOR pipeline. Compute identifiers, extract artifacts, and enrich with OSINT before any analysis begins. Garbage in = garbage out — thorough fingerprinting prevents false paths later.

## Workflow

### 1. Hash Computation

Run all three; never rely on a single hash algorithm.

```bash
sha256sum sample.bin > sha256.txt
sha1sum sample.bin >> hashes.txt
md5sum sample.bin >> hashes.txt
```

Submit SHA256 to SAM as the case directory name (`cases/<sha256>/`).

### 2. String Extraction

Use `strings` with sensible minimum lengths. Always produce both ASCII and wide (UTF-16LE) output.

```bash
strings -n 8 sample.bin > raw_strings.txt
strings -n 8 -e l sample.bin >> raw_strings.txt
```

Post-processing — grep for high-signal patterns:

```bash
grep -E '(https?://|http%3A%2F|\\\\[0-9]{1,3}\\\\[0-9])' raw_strings.txt > ioc_urls.txt
grep -iE '(CreateProcess|WriteProcessMemory|VirtualAlloc|NtMapViewOfSection)' raw_strings.txt > suspicious_apis.txt
grep -iE '(AES|RSA|RC4|XOR|encrypt|decrypt|key|cipher)' raw_strings.txt > crypto_strings.txt
```

### 3. Import/Export Enumeration

Use Ghidra's `Import` listing or PE parsing tools:

| Tool | Command |
|------|---------|
| `readelf` (ELF) | `readelf -s sample.bin > imports.txt` |
| `objdump` | `objdump -T sample.bin > imports.txt` |
| GhidraMCP | `LEGOLAS.enumerate_imports()` |

Categorize imports by function:

- **Process manipulation**: `OpenProcess`, `CreateRemoteThread`, `WriteProcessMemory`, `NtUnmapViewOfSection`
- **Persistence**: `RegSetValue`, `CreateService`, `SCHRegSetPath`
- **Network**: `send`, `recv`, `WSASocket`, `WinHttpOpen`, `URLDownloadToFile`
- **Anti-analysis**: `IsDebuggerPresent`, `NtQueryInformationProcess`, `CheckRemoteDebuggerPresent`
- **Cryptography**: `CryptAcquireContext`, `CryptEncrypt`, `BCryptEncrypt`

### 4. Packer Detection via Entropy Analysis

Calculate shannon entropy per section/segment. LEGOLAS handles this via GhidraMCP.

| Entropy Range | Implication |
|---------------|-------------|
| < 5.0 | Native/unpacked code |
| 5.0 – 6.5 | Moderate — possible compression |
| 6.5 – 7.2 | High — packed or encrypted |
| > 7.2 | Extreme — almost certainly packed |

Correlate high entropy with low import count. A single section with entropy > 6.5 and < 10 imports is a strong packer signal.

Packer signatures to check:
- UPX magic bytes (`UPX0`, `UPX1`, `UPX!`)
- ASPack (`ADS` section)
- Themida/VMProtect (high entropy, tiny `.text`, large custom sections)

### 5. Crypto Constant Scanning

Search for known magic constants used by cryptographic primitives:

```
AES S-box (256-byte table starting with 0x63)
RC4 KSA (identity permutation 0x00-0xFF)
CRC32 tables (0xEDB88320)
Base64 alphabet ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef...")
XOR single-byte keys (common: 0x00 padding reveals key)
```

Write findings to `crypto_indicators.txt`. Include the offset and surrounding bytes for XREF later.

### 6. OSINT Enrichment (ARAGORN)

Query external sources — never execute the binary for these lookups.

```python
# ARAGORN — Shodan/VT lookup via aragorn.py
aragorn.lookup_hash(sha256)     # VirusTotal, Hybrid Analysis
aragorn.lookup_ip(ioc)           # Shodan
aragorn.lookup_domain(domain)    # PassiveTotal / Shodan DNS
```

Checklist:
- [ ] VT detection ratio
- [ ] Known malware family associations
- [ ] Signed? Valid certificate chain?
- [ ] First seen / last seen dates
- [ ] Related samples (similar hash clusters)

## Artifact Checklist

| File | Contents |
|------|----------|
| `metadata.json` | SHA256, SHA1, MD5, filetype, size, compile timestamp, source, signature info |
| `raw_strings.txt` | All extracted ASCII + wide strings |
| `imports.json` | Structured JSON of imports/exports by DLL |
| `crypto_indicators.txt` | Crypto constant offsets, entropy scores, packer signature hits |

## Before Moving to Phase 2

1. ALL four artifacts must exist and be non-empty
2. SAM must have hashes registered in `metadata.json`
3. If entropy > 6.5, flag for unpacking before Phase 3
4. If ARAGORN returns known-bad hits, elevate priority to CRITICAL
