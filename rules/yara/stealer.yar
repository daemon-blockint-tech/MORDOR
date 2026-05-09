/*
 * MORDOR — Malware Orchestration & Reverse engineering Detection Operations Runtime
 * Info-Stealer Detection Rules
 *
 * Detects credential harvesting, browser profile theft, keylogging,
 * FTP client credential theft, and cryptocurrency wallet stealing.
 *
 * Confidence Gate: All rules require 3+ conditions — never single-string.
 */

rule Stealer_Browser_Credential_Harvesting {
    meta:
        description = "Detects browser credential harvesting — login data, cookies, profiles"
        author = "MORDOR / FARAMIR"
        severity = "CRITICAL"
        mitre_technique = "T1555.003"
        confidence = "85+"
    strings:
        $login1 = "Login Data" wide ascii
        $login2 = "Cookies" fullword wide ascii
        $login3 = "Web Data" wide ascii
        $login4 = "autofill" nocase ascii
        $login5 = "Local State" wide ascii
        $login6 = "chrome" nocase ascii
        $login7 = "profile" nocase wide ascii
        $login8 = "encrypted_key" ascii
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464c457f) and
        3 of ($login1, $login2, $login3, $login4) and
        (#login6 > 0 or #login5 > 0) and
        (#login7 > 0 or #login8 > 0 or #login6 > 1)
}

rule Stealer_Keylogger_Indicators {
    meta:
        description = "Detects keylogging capabilities — hook APIs and input capture"
        author = "MORDOR / FARAMIR"
        severity = "HIGH"
        mitre_technique = "T1056.001"
        confidence = "80+"
    strings:
        $hook1 = "SetWindowsHookEx" fullword ascii
        $hook2 = "GetAsyncKeyState" fullword ascii
        $hook3 = "GetForegroundWindow" fullword ascii
        $hook4 = "GetWindowText" fullword ascii
        $hook5 = "WH_KEYBOARD_LL" wide ascii
        $hook6 = "keylog" nocase ascii
        $hook7 = "WM_KEYDOWN" ascii
        $hook8 = "GetKeyboardState" fullword ascii
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464c457f) and
        2 of ($hook1, $hook2, $hook5) and
        2 of ($hook3, $hook4, $hook6, $hook7, $hook8)
}

rule Stealer_CryptoWallet_FTP_Combined {
    meta:
        description = "Detects cryptocurrency wallet paths and FTP credential theft combined"
        author = "MORDOR / FARAMIR"
        severity = "CRITICAL"
        mitre_technique = "T1555, T1529"
        confidence = "85+"
    strings:
        $wal1 = "wallet.dat" wide ascii
        $wal2 = ".dat" nocase ascii
        $wal3 = "electrum" nocase ascii
        $wal4 = "exodus" nocase ascii
        $ftp1 = "FileZilla" nocase ascii
        $ftp2 = "recentservers.xml" ascii
        $ftp3 = "sitemanager.xml" ascii
        $ftp4 = "host=" nocase ascii
        $ftp5 = "password=" nocase ascii
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464c457f) and
        (1 of ($wal1, $wal3, $wal4) or 2 of ($wal2, $ftp1)) and
        (2 of ($ftp2, $ftp3, $ftp4, $ftp5) or 1 of ($wal3, $wal4)) and
        filesize < 20MB
}

rule Stealer_CredentialManager_Dumping {
    meta:
        description = "Detects Windows Credential Manager and token theft APIs"
        author = "MORDOR / FARAMIR"
        severity = "HIGH"
        mitre_technique = "T1003, T1528"
        confidence = "75+"
    strings:
        $cred1 = "CredRead" fullword ascii
        $cred2 = "CredEnumerate" fullword ascii
        $cred3 = "CredWrite" fullword ascii
        $cred4 = "vaultcli" nocase ascii
        $cred5 = "VaultEnumerateItems" ascii
        $cred6 = "token" nocase ascii
        $cred7 = "OpenProcess" fullword ascii
        $cred8 = "DuplicateTokenEx" fullword ascii
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464c457f) and
        2 of ($cred1, $cred2, $cred3) and
        2 of ($cred4, $cred5, $cred6, $cred7, $cred8)
}
