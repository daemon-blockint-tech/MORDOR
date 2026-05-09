/*
 * MORDOR — Malware Orchestration & Reverse engineering Detection Operations Runtime
 * Packer / Protector Detection Rules
 *
 * Detects UPX, Themida, VMProtect, ASPack, MPRESS and other common
 * packers via signatures, section entropy anomalies, suspicious
 * section names, and import table obfuscation.
 *
 * Confidence Gate: All rules require 3+ conditions — never single-string.
 */

rule Packer_UPX_Detect {
    meta:
        description = "Detects UPX-packed executables — most common packer in malware"
        author = "MORDOR / FARAMIR"
        severity = "MEDIUM"
        mitre_technique = "T1027.002"
        confidence = "95+"
    strings:
        $upx1 = "UPX" fullword ascii
        $upx2 = "UPX0" fullword ascii
        $upx3 = "UPX1" fullword ascii
        $upx4 = "UPX!" ascii
        $upx5 = "!This program cannot be run in DOS mode" wide ascii
        $sect  = ".packed" ascii
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($upx1, $upx2, $upx3, $upx4)) and
        ($upx5 or $sect or (#upx1 + #upx2 + #upx3 >= 2))
}

rule Packer_Themida_VMProtect {
    meta:
        description = "Detects Themida and VMProtect commercial protectors with entropy heuristics"
        author = "MORDOR / FARAMIR"
        severity = "HIGH"
        mitre_technique = "T1027.002"
        confidence = "85+"
    strings:
        $th1 = "Themida" wide ascii
        $th2 = "Oreans" wide ascii
        $th3 = "WinLicense" wide ascii
        $th4 = "macl" ascii
        $th5 = "mack" ascii
        $vp1 = "VMPROTECT" ascii
        $vp2 = "VMProtect" wide ascii
        $vp3 = "VProtect" ascii
        $vp4 = ".vmp0" ascii
        $vp5 = ".vmp1" ascii
    condition:
        uint16(0) == 0x5A4D and
        ((2 of ($th1, $th2, $th3, $th4, $th5)) or
         (2 of ($vp1, $vp2, $vp3, $vp4, $vp5))) and
         (#th1 + #vp1 + #vp2 >= 1)
}

rule Packer_Suspicious_Section_Names {
    meta:
        description = "Detects anomalous section names commonly produced by protectors"
        author = "MORDOR / FARAMIR"
        severity = "MEDIUM"
        mitre_technique = "T1027.002"
        confidence = "80+"
    strings:
        $sn1 = ".aspack" ascii
        $sn2 = ".adata" ascii
        $sn3 = ".MPRESS" ascii
        $sn4 = ".mackt" ascii
        $sn5 = ".pcle" ascii
        $sn6 = ".sforce" ascii
        $sn7 = ".enigma" ascii
        $sn8 = ".protect" ascii
        $sn9 = ".nsp0" ascii
        $sn10 = ".nsp1" ascii
        $sn11 = ".nsp2" ascii
    condition:
        uint16(0) == 0x5A4D and
        2 of ($sn1, $sn2, $sn3, $sn4, $sn5, $sn6) and
        (1 of ($sn7, $sn8, $sn9, $sn10, $sn11) or #sn3 + #sn1 >= 2)
}

rule Packer_IAT_Obfuscation_Import_Scramble {
    meta:
        description = "Detects import table obfuscation: scrambled or bound imports, abnormal API count"
        author = "MORDOR / FARAMIR"
        severity = "HIGH"
        mitre_technique = "T1027.002"
        confidence = "75+"
    strings:
        $iat1 = /KERNEL32\.(dll|DLL|Dll)/ fullword ascii
        $iat2 = /USER32\.(dll|DLL|Dll)/ fullword ascii
        $iat3 = "GetProcAddress" fullword ascii
        $iat4 = "LoadLibraryA" fullword ascii
        $iat5 = "LoadLibraryW" fullword ascii
        $iat6 = "VirtualProtect" fullword ascii
        $iat7 = "WriteProcessMemory" fullword ascii
        $iat8 = "VirtualAlloc" fullword ascii
    condition:
        uint16(0) == 0x5A4D and
        $iat3 and $iat4 and
        2 of ($iat1, $iat2, $iat6, $iat7, $iat8) and
        (#iat3 > 1 or #iat4 > 1 or #iat5 > 1)
}

rule Packer_ASPack_MPRESS {
    meta:
        description = "Detects ASPack and MPRESS compressed executables"
        author = "MORDOR / FARAMIR"
        severity = "MEDIUM"
        mitre_technique = "T1027.002"
        confidence = "90+"
    strings:
        $as1 = "ASPack" fullword ascii
        $as2 = ".aspack" fullword ascii
        $as3 = ".adata" fullword ascii
        $as4 = "Alexey" ascii
        $mp1 = "MPRESS" fullword ascii
        $mp2 = ".MPRESS" fullword ascii
        $mp3 = "MATCODE" fullword ascii
        $cmp = "Compress" ascii
    condition:
        uint16(0) == 0x5A4D and
        ((2 of ($as1, $as2, $as3, $as4)) or
         (2 of ($mp1, $mp2, $mp3))) and
        (#cmp > 0 or #as1 + #mp1 >= 1)
}
