/*
 * MORDOR — Malware Orchestration & Reverse engineering Detection Operations Runtime
 * C2 Communication Detection Rules
 *
 * Detects embedded C2 infrastructure, HTTP beaconing patterns,
 * DNS tunneling indicators, named pipes, and encoded config sections.
 *
 * Confidence Gate: All rules require 3+ conditions — never single-string.
 */

rule C2_Embedded_Domains_URLs {
    meta:
        description = "Detects embedded C2 domains, IP addresses, and URL patterns in binaries"
        author = "MORDOR / FARAMIR"
        severity = "CRITICAL"
        mitre_technique = "T1071.001"
        confidence = "85+"
    strings:
        $url1 = "http://" nocase ascii
        $url2 = "https://" nocase ascii
        $url3 = ".php" nocase ascii
        $url4 = ".aspx" nocase ascii
        $url5 = "/gate" nocase ascii
        $url6 = "/command" nocase ascii
        $url7 = "/api/" nocase ascii
        $url8 = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464c457f) and
        (1 of ($url1, $url2) and 2 of ($url3, $url4, $url5, $url6)) and
        (#url8 > 0 or #url7 > 0)
}

rule C2_HTTP_Beaconing_UserAgent {
    meta:
        description = "Detects suspicious User-Agent strings common in C2 HTTP beaconing"
        author = "MORDOR / FARAMIR"
        severity = "HIGH"
        mitre_technique = "T1071.001"
        confidence = "80+"
    strings:
        $ua1 = "Mozilla/5.0" nocase ascii
        $ua2 = "Windows NT" nocase ascii
        $ua3 = "MSIE" nocase ascii
        $ua4 = "Accept-Encoding:" ascii
        $ua5 = "POST" ascii
        $ua6 = "Cookie:" nocase ascii
        $ua7 = "Content-Type:" nocase ascii
        $ua8 = "application/x-www-form-urlencoded" nocase ascii
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464c457f) and
        $ua1 and ($ua2 or $ua3) and
        2 of ($ua4, $ua5, $ua7) and
        (#ua8 > 0 or #ua6 > 1)
}

rule C2_NamedPipe_IPC {
    meta:
        description = "Detects named pipe creation and IPC patterns used for C2 tunneling"
        author = "MORDOR / FARAMIR"
        severity = "HIGH"
        mitre_technique = "T1105, T1572"
        confidence = "75+"
    strings:
        $pipe1 = "\\\\.\\pipe\\" wide ascii
        $pipe2 = "CreateNamedPipe" fullword ascii
        $pipe3 = "ConnectNamedPipe" fullword ascii
        $pipe4 = "CallNamedPipe" fullword ascii
        $pipe5 = "TransactNamedPipe" fullword ascii
        $pipe6 = "GetNamedPipeHandleState" fullword ascii
        $pipe7 = "SECURITY_IMPERSONATION" ascii
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464c457f) and
        ($pipe1 or $pipe2) and
        2 of ($pipe3, $pipe4, $pipe5) and
        (#pipe1 > 1 or $pipe6 or $pipe7)
}

rule C2_Base64_Encoded_Config {
    meta:
        description = "Detects base64-encoded configuration sections common in C2 frameworks"
        author = "MORDOR / FARAMIR"
        severity = "CRITICAL"
        mitre_technique = "T1027, T1071"
        confidence = "80+"
    strings:
        $b64  = /[A-Za-z0-9+\/]{100,}={0,2}/   // long base64 blob
        $cfg1 = "sleep" nocase ascii
        $cfg2 = "jitter" nocase ascii
        $cfg3 = "server" nocase ascii
        $cfg4 = "user-agent" nocase ascii
        $cfg5 = "killdate" nocase ascii
        $cfg6 = "aes_key" nocase ascii
        $cfg7 = "encrypt" nocase ascii
    condition:
        (#b64 >= 2) and
        (2 of ($cfg1, $cfg2, $cfg3, $cfg4)) and
        (1 of ($cfg5, $cfg6, $cfg7) or #b64 >= 3)
}

rule C2_DNS_Tunneling_Indicators {
    meta:
        description = "Detects DNS tunneling and DGA-style domain generation patterns"
        author = "MORDOR / FARAMIR"
        severity = "HIGH"
        mitre_technique = "T1572, T1568.002"
        confidence = "70+"
    strings:
        $dns1 = "DnsQuery" fullword ascii
        $dns2 = "DnsQuery_A" fullword ascii
        $dns3 = "DnsQuery_W" fullword ascii
        $dns4 = "getaddrinfo" fullword ascii
        $dns5 = "WSASendTo" fullword ascii
        $dga  = /[a-z]{8,}\.(com|net|org|top|xyz|info|club)/ ascii
        $sub  = /[a-z0-9]{20,}\.[a-z]{2,}/ ascii
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464c457f) and
        2 of ($dns1, $dns2, $dns4, $dns5) and
        (1 of ($dga, $sub) or (#dns3 + #dns1 >= 3))
}
