/*
 * ransomware.yar — YARA Ransomware Detection Rules
 * Member B — Upload Pipeline & Security
 *
 * Purpose:
 *   Detect ransomware droppers, encrypted payload delivery mechanisms,
 *   and ransom note patterns in uploaded files.
 *
 * Hot-reload: signal clamd after editing:
 *   kill -USR2 $(cat /run/clamav/clamd.pid)
 *
 * A match quarantines the file immediately via scan.service.js.
 */

import "pe"
import "math"

// ─────────────────────────────────────────────────────────────────────────────
// RULE 1: Ransom note text patterns
// Targets: text/document files containing ransom demand language
// ─────────────────────────────────────────────────────────────────────────────
rule Ransomware_NotePatterns
{
    meta:
        description = "Detects ransom note text patterns in uploaded files"
        severity    = "CRITICAL"
        category    = "ransomware"
        author      = "SecureVault Security Team"

    strings:
        $note1  = "your files have been encrypted" nocase wide ascii
        $note2  = "your files are encrypted"       nocase wide ascii
        $note3  = "all your files"                 nocase wide ascii
        $note4  = "pay the ransom"                 nocase wide ascii
        $note5  = "bitcoin"                        nocase wide ascii
        $note6  = "BTC"                            wide ascii
        $note7  = "monero"                         nocase wide ascii
        $note8  = "decrypt your files"             nocase wide ascii
        $note9  = "decryption key"                 nocase wide ascii
        $note10 = "unique key"                     nocase wide ascii
        $note11 = "do not rename"                  nocase wide ascii
        $note12 = "do not try to recover"          nocase wide ascii
        $onion  = /[a-z2-7]{16,56}\.onion/        nocase ascii

    condition:
        (2 of ($note*)) or
        ($onion and 1 of ($note*))
}

// ─────────────────────────────────────────────────────────────────────────────
// RULE 2: File encryption API usage (Windows)
// Targets: PE files calling crypto APIs used by ransomware
// ─────────────────────────────────────────────────────────────────────────────
rule Ransomware_CryptoAPIUsage
{
    meta:
        description = "Detects PE files importing encryption APIs commonly used by ransomware"
        severity    = "HIGH"
        category    = "ransomware"
        author      = "SecureVault Security Team"

    strings:
        $pe_header = { 4D 5A }

        // Windows Crypto API
        $capi1 = "CryptEncrypt"         nocase ascii
        $capi2 = "CryptGenKey"          nocase ascii
        $capi3 = "CryptAcquireContext"  nocase ascii
        $capi4 = "CryptImportKey"       nocase ascii

        // CNG (Cryptography Next Gen)
        $cng1  = "BCryptGenerateSymmetricKey" nocase ascii
        $cng2  = "BCryptEncrypt"             nocase ascii
        $cng3  = "BCryptOpenAlgorithmProvider" nocase ascii

        // File enumeration (ransomware traverses filesystem)
        $fe1   = "FindFirstFile"        nocase ascii
        $fe2   = "FindNextFile"         nocase ascii
        $fe3   = "MoveFileEx"           nocase ascii
        $fe4   = "DeleteFile"           nocase ascii

    condition:
        $pe_header at 0 and
        (2 of ($capi*) or 2 of ($cng*)) and
        2 of ($fe*)
}

// ─────────────────────────────────────────────────────────────────────────────
// RULE 3: Shadow copy deletion — classic ransomware evasion
// ─────────────────────────────────────────────────────────────────────────────
rule Ransomware_ShadowCopyDeletion
{
    meta:
        description = "Detects commands to delete Windows shadow copies (backup destruction)"
        severity    = "CRITICAL"
        category    = "ransomware"
        author      = "SecureVault Security Team"

    strings:
        $vss1 = "vssadmin delete shadows"     nocase wide ascii
        $vss2 = "vssadmin.exe Delete Shadows" nocase wide ascii
        $vss3 = "Delete Shadows /All"         nocase wide ascii
        $vss4 = "wbadmin delete catalog"      nocase wide ascii
        $vss5 = "bcdedit /set"                nocase wide ascii
        $vss6 = "recoveryenabled No"          nocase wide ascii
        $vss7 = "wmic shadowcopy delete"      nocase wide ascii
        $vss8 = "Win32_ShadowCopy"            nocase wide ascii

    condition:
        any of ($vss*)
}

// ─────────────────────────────────────────────────────────────────────────────
// RULE 4: Known ransomware file extension targets
// Targets: scripts listing file extensions ransomware typically encrypts
// ─────────────────────────────────────────────────────────────────────────────
rule Ransomware_ExtensionTargetList
{
    meta:
        description = "Detects lists of file extensions commonly targeted by ransomware"
        severity    = "MEDIUM"
        category    = "ransomware"
        author      = "SecureVault Security Team"

    strings:
        $ext1  = ".docx" ascii
        $ext2  = ".xlsx" ascii
        $ext3  = ".pptx" ascii
        $ext4  = ".pdf"  ascii
        $ext5  = ".jpg"  ascii
        $ext6  = ".png"  ascii
        $ext7  = ".sql"  ascii
        $ext8  = ".mdb"  ascii
        $ext9  = ".bak"  ascii
        $ext10 = ".tar"  ascii
        $ext11 = ".zip"  ascii
        $ransom_ext = /\.[a-z0-9]{4,8}locked/ nocase ascii

    condition:
        8 of ($ext*) or $ransom_ext
}

// ─────────────────────────────────────────────────────────────────────────────
// RULE 5: Tor / C2 communication indicators
// ─────────────────────────────────────────────────────────────────────────────
rule Ransomware_TorC2Communication
{
    meta:
        description = "Detects Tor hidden service or C2 communication patterns"
        severity    = "HIGH"
        category    = "ransomware"
        author      = "SecureVault Security Team"

    strings:
        $tor1  = /[a-z2-7]{16}\.onion/  nocase ascii
        $tor2  = /[a-z2-7]{56}\.onion/  nocase ascii
        $c2_1  = "torproject.org"        nocase ascii
        $c2_2  = "check.torproject"      nocase ascii
        $pay1  = "payment"               nocase ascii
        $pay2  = "wallet"                nocase ascii

    condition:
        ($tor1 or $tor2 or $c2_1 or $c2_2) and
        ($pay1 or $pay2)
}

// ─────────────────────────────────────────────────────────────────────────────
// RULE 6: Ransomware dropper — script-based delivery
// Targets: scripts that download and execute a secondary payload
// ─────────────────────────────────────────────────────────────────────────────
rule Ransomware_ScriptDropper
{
    meta:
        description = "Detects script-based ransomware dropper patterns"
        severity    = "CRITICAL"
        category    = "ransomware"
        author      = "SecureVault Security Team"

    strings:
        // Download
        $dl1 = "DownloadFile"      nocase wide ascii
        $dl2 = "DownloadString"    nocase wide ascii
        $dl3 = "Invoke-WebRequest" nocase wide ascii
        $dl4 = "wget"              nocase ascii
        $dl5 = "curl"              nocase ascii

        // Execute
        $ex1 = "Start-Process"     nocase wide ascii
        $ex2 = "Invoke-Item"       nocase wide ascii
        $ex3 = "Shell.Run"         nocase wide ascii
        $ex4 = "WScript.Shell"     nocase wide ascii
        $ex5 = "cmd /c"            nocase wide ascii

        // Persistence
        $per1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
        $per2 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
        $per3 = "schtasks"         nocase wide ascii

    condition:
        (1 of ($dl*)) and
        (1 of ($ex*)) and
        (1 of ($per*))
}
