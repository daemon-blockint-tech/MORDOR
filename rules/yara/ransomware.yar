/*
 * MORDOR — Malware Orchestration & Reverse engineering Detection Operations Runtime
 * Ransomware Detection Rules
 *
 * Detects ransomware indicators: file encryption APIs, ransom notes,
 * shadow copy deletion, wallet addresses, extension renaming.
 *
 * Confidence Gate: All rules require 3+ conditions — never single-string.
 */

rule Ransomware_Encryption_API {
    meta:
        description = "Detects ransomware samples using file encryption API calls"
        author = "MORDOR / FARAMIR"
        severity = "CRITICAL"
        mitre_technique = "T1486"
        confidence = "85+"
    strings:
        $s1 = "CryptEncrypt" fullword ascii
        $s2 = "BCryptEncrypt" fullword ascii
        $s3 = "CryptExportKey" fullword ascii
        $s4 = "RtlEncryptMemory" fullword ascii
        $s5 = "CryptAcquireContext" fullword ascii
        $s6 = "Microsoft Enhanced Cryptographic" wide ascii
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464c457f) and
        3 of ($s1, $s2, $s3, $s4) and
        (#s5 > 1 or $s6)
}

rule Ransomware_ShadowCopy_Deletion {
    meta:
        description = "Detects VSSAdmin shadow copy deletion patterns used by ransomware"
        author = "MORDOR / FARAMIR"
        severity = "CRITICAL"
        mitre_technique = "T1490"
        confidence = "85+"
    strings:
        $cmd1 = "vssadmin" nocase ascii
        $cmd2 = "Delete Shadows" nocase wide ascii
        $cmd3 = "/quiet" nocase ascii
        $cmd4 = "wmic" nocase ascii
        $cmd5 = "shadowcopy" nocase ascii
        $cmd6 = "bcdedit" nocase ascii
        $cmd7 = "recoveryenabled" nocase ascii
    condition:
        $cmd1 and
        2 of ($cmd2, $cmd3, $cmd5) and
        (uint16(0) == 0x5A4D or #cmd4 > 0 or #cmd6 > 0 or #cmd7 > 0)
}

rule Ransomware_Extension_Rename_Bulk {
    meta:
        description = "Detects ransomware bulk file rename and ransom note patterns"
        author = "MORDOR / FARAMIR"
        severity = "CRITICAL"
        mitre_technique = "T1486"
        confidence = "80+"
    strings:
        $note1 = "ransom" nocase wide ascii
        $note2 = "decrypt" nocase wide ascii
        $note3 = "bitcoin" nocase wide ascii
        $note4 = ".encrypted" ascii
        $note5 = ".locked" ascii
        $note6 = "1A" ascii    // common BTC wallet prefix pattern
        $note7 = "3" ascii     // common BTC wallet prefix pattern
        $note8 = "bc1" ascii   // bech32 BTC prefix
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464c457f) and
        2 of ($note1, $note2, $note3) and
        1 of ($note4, $note5) and
        (#note6 > 2 or #note7 > 2 or #note8 > 0)
}

rule Ransomware_Wallet_Address_Embedded {
    meta:
        description = "Detects embedded cryptocurrency wallet addresses in ransomware binaries"
        author = "MORDOR / FARAMIR"
        severity = "HIGH"
        mitre_technique = "T1486"
        confidence = "75+"
    strings:
        $btc1 = /1[1-9A-Za-z]{25,34}/   // legacy P2PKH
        $btc2 = /3[1-9A-Za-z]{25,34}/   // P2SH
        $btc3 = /bc1[a-zA-Z0-9]{38,58}/  // bech32
        $xmr  = /4[0-9AB][1-9A-Za-z]{93}/ // Monero
        $eth  = /0x[a-fA-F0-9]{40}/       // Ethereum
        $note = "send" nocase ascii
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464c457f) and
        (1 of ($btc1, $btc2, $btc3) or $xmr or $eth) and
        (#note > 0 and filesize < 10MB)
}
